import sys
import os
import threading
import winreg
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

sys.path.insert(0, os.path.dirname(__file__))
from core.scanner import Scanner
from core.quarantine import quarantine_file, restore_file, delete_quarantined, list_quarantine
from tray import TrayIcon


COLORS = {
    'bg': '#1a1b26',
    'surface': '#24283b',
    'surface2': '#1f2335',
    'border': '#3b4261',
    'primary': '#7aa2f7',
    'danger': '#f7768e',
    'warning': '#e0af68',
    'success': '#9ecea6',
    'text': '#c0caf5',
    'subtext': '#565f89',
    'header': '#a9b1d6',
    'critical': '#f7768e',
    'high': '#e0af68',
    'medium': '#7dcfff',
    'low': '#565f89',
}

SEVERITY_TAGS = {
    'critical': ('critical', COLORS['critical']),
    'high': ('high', COLORS['high']),
    'medium': ('medium', COLORS['medium']),
    'low': ('low', COLORS['low']),
}


def _is_startup_enabled():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r'Software\Microsoft\Windows\CurrentVersion\Run',
                            0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, 'PyShieldAV')
            return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def _toggle_startup(enable):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r'Software\Microsoft\Windows\CurrentVersion\Run',
                             0, winreg.KEY_SET_VALUE)
        if enable:
            exe = sys.executable
            script = os.path.join(os.path.dirname(__file__), 'gui.py')
            if script.endswith('.py'):
                cmd = f'"{exe}" "{script}" --tray'
            else:
                cmd = f'"{script}" --tray'
            winreg.SetValueEx(key, 'PyShieldAV', 0, winreg.REG_SZ, cmd)
        else:
            try:
                winreg.DeleteValue(key, 'PyShieldAV')
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


class PyShieldGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('PyShield Antivirus')
        self.root.geometry('920x680')
        self.root.minsize(800, 600)
        self.root.configure(bg=COLORS['bg'])

        self.scanner = Scanner(threads=2)
        self.scan_thread = None
        self.scanning = False
        self.current_results = []
        self.target_paths = []
        self.tray = None
        self.minimized = False

        self._setup_style()
        self._build_ui()

        raw_args = sys.argv[1:]
        flags = set(a for a in raw_args if a.startswith('--'))
        args = [a for a in raw_args if not a.startswith('--')]
        start_in_tray = '--tray' in flags or '--minimized' in flags
        auto_quick = '--quick' in flags
        auto_hard = '--hard' in flags

        if args:
            arg = args[0]
            if os.path.exists(arg):
                self.target_paths = [os.path.abspath(arg)]
                self._update_drop_zone_text()
                if auto_hard:
                    self.root.after(200, lambda: self._start_scan(quick=False))
                elif auto_quick or not start_in_tray:
                    self.root.after(200, lambda: self._start_scan(quick=True))

        self.tray = TrayIcon(self)
        self.tray.start()

        self.root.protocol('WM_DELETE_WINDOW', self._on_close)

        if start_in_tray:
            self.root.withdraw()
            self.minimized = True

        self.root.mainloop()

    def _setup_style(self):
        style = ttk.Style()
        try:
            style.theme_use('clam')
        except Exception:
            pass

        style.configure('.', background=COLORS['bg'], foreground=COLORS['text'],
                        fieldbackground=COLORS['surface'], font=('Segoe UI', 10))
        style.configure('TFrame', background=COLORS['bg'])
        style.configure('Surface.TFrame', background=COLORS['surface'],
                        relief='flat', borderwidth=0)
        style.configure('Header.TLabel', background=COLORS['bg'],
                        foreground=COLORS['header'], font=('Segoe UI', 16, 'bold'))
        style.configure('Status.TLabel', background=COLORS['bg'],
                        foreground=COLORS['subtext'], font=('Segoe UI', 9))
        style.configure('Stats.TLabel', background=COLORS['surface'],
                        foreground=COLORS['text'], font=('Segoe UI', 11, 'bold'))
        style.configure('StatsVal.TLabel', background=COLORS['surface'],
                        foreground=COLORS['primary'], font=('Segoe UI', 11, 'bold'))
        style.configure('Title.TLabel', background=COLORS['bg'],
                        foreground=COLORS['primary'], font=('Segoe UI', 14, 'bold'))

        style.configure('TButton', background=COLORS['surface'],
                        foreground=COLORS['text'], borderwidth=1,
                        focusthickness=0, focuscolor='none',
                        font=('Segoe UI', 10, 'bold'), padding=(16, 8))
        style.map('TButton', background=[('active', COLORS['primary'])],
                  foreground=[('active', COLORS['bg'])])
        style.configure('Primary.TButton', background=COLORS['primary'],
                        foreground=COLORS['bg'])
        style.map('Primary.TButton', background=[('active', '#89b4fa')],
                  foreground=[('active', COLORS['bg'])])
        style.configure('Danger.TButton', background=COLORS['danger'],
                        foreground=COLORS['bg'])
        style.map('Danger.TButton', background=[('active', '#ff9eb0')],
                  foreground=[('active', COLORS['bg'])])
        style.configure('Success.TButton', background=COLORS['success'],
                        foreground=COLORS['bg'])
        style.map('Success.TButton', background=[('active', '#b8e6a0')],
                  foreground=[('active', COLORS['bg'])])

        style.configure('TProgressbar', background=COLORS['primary'],
                        troughcolor=COLORS['surface'], borderwidth=0,
                        lightcolor=COLORS['primary'], darkcolor=COLORS['primary'])

        style.configure('Treeview', background=COLORS['surface'],
                        foreground=COLORS['text'], fieldbackground=COLORS['surface'],
                        borderwidth=0, font=('Segoe UI', 9))
        style.map('Treeview', background=[('selected', COLORS['primary'])],
                  foreground=[('selected', COLORS['bg'])])
        style.configure('Treeview.Heading', background=COLORS['surface2'],
                        foreground=COLORS['header'], borderwidth=0,
                        font=('Segoe UI', 9, 'bold'))
        style.map('Treeview.Heading', background=[('active', COLORS['border'])])
        style.layout('Treeview', [('Treeview.treearea', {'sticky': 'nswe'})])

    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(2, weight=1)

        header_frame = tk.Frame(self.root, bg=COLORS['bg'], height=52)
        header_frame.grid(row=0, column=0, sticky='ew', padx=16, pady=(12, 4))
        header_frame.columnconfigure(1, weight=1)

        icon_label = tk.Label(header_frame, text='\u26a1', font=('Segoe UI', 20),
                              bg=COLORS['bg'], fg=COLORS['primary'])
        icon_label.grid(row=0, column=0, padx=(0, 8))

        title_label = tk.Label(header_frame, text='PyShield Antivirus',
                               font=('Segoe UI', 16, 'bold'),
                               bg=COLORS['bg'], fg=COLORS['primary'])
        title_label.grid(row=0, column=1, sticky='w')

        actions_frame = tk.Frame(header_frame, bg=COLORS['bg'])
        actions_frame.grid(row=0, column=2, sticky='e')
        for text, cmd in [('\u2699', self._show_settings),
                          ('\u2139', self._show_about)]:
            btn = tk.Button(actions_frame, text=text, font=('Segoe UI', 14),
                           bg=COLORS['bg'], fg=COLORS['subtext'],
                           relief='flat', cursor='hand2', bd=0,
                           activebackground=COLORS['bg'],
                           activeforeground=COLORS['text'],
                           command=cmd)
            btn.pack(side='left', padx=4)

        sep = tk.Frame(self.root, bg=COLORS['border'], height=1)
        sep.grid(row=1, column=0, sticky='ew', padx=0)

        content = tk.Frame(self.root, bg=COLORS['bg'])
        content.grid(row=2, column=0, sticky='nsew', padx=16, pady=8)
        content.columnconfigure(0, weight=1)
        content.rowconfigure(3, weight=1)

        self._build_drop_zone(content)
        self._build_stats_bar(content)
        self._build_scan_buttons(content)
        self._build_results_table(content)
        self._build_action_buttons(content)
        self._build_status_bar(content)

    def _build_drop_zone(self, parent):
        drop_frame = tk.Frame(parent, bg=COLORS['surface'],
                              highlightbackground=COLORS['border'],
                              highlightthickness=2, cursor='hand2')
        drop_frame.grid(row=0, column=0, sticky='ew', pady=(0, 8))
        drop_frame.columnconfigure(0, weight=1)
        drop_frame.bind('<Button-1>', lambda e: self._browse_file())

        self.drop_icon = tk.Label(drop_frame, text='\U0001f4c2',
                                  font=('Segoe UI', 32),
                                  bg=COLORS['surface'], fg=COLORS['subtext'])
        self.drop_icon.grid(row=0, column=0, pady=(20, 0))
        self.drop_icon.bind('<Button-1>', lambda e: self._browse_file())

        self.drop_text = tk.Label(drop_frame, text='Drop files or folders here, or click to browse',
                                  font=('Segoe UI', 11),
                                  bg=COLORS['surface'], fg=COLORS['subtext'])
        self.drop_text.grid(row=1, column=0, pady=(4, 4))
        self.drop_text.bind('<Button-1>', lambda e: self._browse_file())

        btn_frame = tk.Frame(drop_frame, bg=COLORS['surface'])
        btn_frame.grid(row=2, column=0, pady=(4, 20))

        ttk.Button(btn_frame, text='\U0001f4c4 Browse Files', style='TButton',
                   command=self._browse_file).pack(side='left', padx=6)
        ttk.Button(btn_frame, text='\U0001f4c1 Browse Folder', style='TButton',
                   command=self._browse_folder).pack(side='left', padx=6)

    def _build_stats_bar(self, parent):
        stats = tk.Frame(parent, bg=COLORS['surface'])
        stats.grid(row=1, column=0, sticky='ew', pady=(0, 8))
        for i in range(6):
            stats.columnconfigure(i, weight=1 if i % 2 == 0 else 0)

        labels = [('Scanned:', 'stats_scanned', '0'),
                  ('Threats:', 'stats_threats', '0'),
                  ('Skipped:', 'stats_skipped', '0')]
        self.stats_vars = {}
        col = 0
        for label, key, default in labels:
            lbl = tk.Label(stats, text=label, font=('Segoe UI', 10),
                           bg=COLORS['surface'], fg=COLORS['subtext'])
            lbl.grid(row=0, column=col, padx=(16, 4), pady=8, sticky='w')
            col += 1
            val = tk.Label(stats, text=default, font=('Segoe UI', 10, 'bold'),
                           bg=COLORS['surface'], fg=COLORS['primary'])
            val.grid(row=0, column=col, padx=(0, 24), pady=8, sticky='w')
            self.stats_vars[key] = val
            col += 1

        self.progress = ttk.Progressbar(stats, mode='determinate', length=180)
        self.progress.grid(row=0, column=col, padx=(16, 8), pady=8, sticky='ew')
        stats.columnconfigure(col, weight=1)
        self.progress_label = tk.Label(stats, text='', font=('Segoe UI', 9),
                                       bg=COLORS['surface'], fg=COLORS['subtext'])
        self.progress_label.grid(row=0, column=col + 1, padx=(0, 16), pady=8)

    def _build_scan_buttons(self, parent):
        btn_frame = tk.Frame(parent, bg=COLORS['bg'])
        btn_frame.grid(row=2, column=0, sticky='ew', pady=(0, 8))
        btn_frame.columnconfigure(0, weight=1)

        inner = tk.Frame(btn_frame, bg=COLORS['bg'])
        inner.grid(row=0, column=0)

        self.btn_quick = ttk.Button(inner, text='\u26a1 Quick Scan',
                                    style='Primary.TButton',
                                    command=lambda: self._start_scan(quick=True))
        self.btn_quick.pack(side='left', padx=4)
        self.btn_hard = ttk.Button(inner, text='\U0001f50d Hard Scan', style='TButton',
                                   command=lambda: self._start_scan(quick=False))
        self.btn_hard.pack(side='left', padx=4)
        self.btn_system = ttk.Button(inner, text='\U0001f6e1 System Scan', style='TButton',
                                     command=self._start_system_scan)
        self.btn_system.pack(side='left', padx=4)
        self.btn_stop = ttk.Button(inner, text='\u2716 Stop', style='Danger.TButton',
                                   command=self._stop_scan)
        self.btn_stop.pack(side='left', padx=4)
        self.btn_stop.configure(state='disabled')

        self.time_label = tk.Label(btn_frame, text='', font=('Segoe UI', 9),
                                   bg=COLORS['bg'], fg=COLORS['subtext'])
        self.time_label.grid(row=0, column=1, sticky='e', padx=(0, 4))

    def _build_results_table(self, parent):
        container = tk.Frame(parent, bg=COLORS['bg'])
        container.grid(row=3, column=0, sticky='nsew', pady=(0, 8))
        container.columnconfigure(0, weight=1)
        container.rowconfigure(0, weight=1)

        columns = ('file', 'type', 'severity', 'detail')
        self.tree = ttk.Treeview(container, columns=columns, show='headings',
                                 selectmode='extended', height=12)
        self.tree.heading('file', text='File')
        self.tree.heading('type', text='Threat Type')
        self.tree.heading('severity', text='Severity')
        self.tree.heading('detail', text='Detail')
        self.tree.column('file', width=200, minwidth=120)
        self.tree.column('type', width=130, minwidth=100)
        self.tree.column('severity', width=90, minwidth=70, anchor='center')
        self.tree.column('detail', width=300, minwidth=150)

        for sev, (tag, _) in SEVERITY_TAGS.items():
            self.tree.tag_configure(tag, foreground=COLORS[sev])

        vsb = ttk.Scrollbar(container, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')

    def _build_action_buttons(self, parent):
        frame = tk.Frame(parent, bg=COLORS['bg'])
        frame.grid(row=4, column=0, sticky='ew')

        self.btn_quarantine = ttk.Button(frame, text='\U0001f5d1 Quarantine Selected',
                                         style='Danger.TButton',
                                         command=self._quarantine_selected)
        self.btn_quarantine.pack(side='left', padx=(0, 4))
        self.btn_restore = ttk.Button(frame, text='\u21a9 Restore', style='TButton',
                                      command=self._show_restore_dialog)
        self.btn_restore.pack(side='left', padx=4)
        self.btn_purge = ttk.Button(frame, text='\u2718 Purge All', style='TButton',
                                    command=self._purge_all)
        self.btn_purge.pack(side='left', padx=4)
        tk.Button(frame, text='Clear Results', font=('Segoe UI', 9),
                  bg=COLORS['bg'], fg=COLORS['subtext'],
                  relief='flat', cursor='hand2', bd=0,
                  activebackground=COLORS['bg'], activeforeground=COLORS['text'],
                  command=self._clear_results).pack(side='right', padx=4)

    def _build_status_bar(self, parent):
        sep = tk.Frame(self.root, bg=COLORS['border'], height=1)
        sep.grid(row=3, column=0, sticky='ew', padx=0)

        bar = tk.Frame(self.root, bg=COLORS['bg'], height=28)
        bar.grid(row=4, column=0, sticky='ew', padx=16, pady=(6, 8))
        bar.columnconfigure(0, weight=1)

        self.status_text = tk.Label(bar, text='Ready', font=('Segoe UI', 9),
                                    bg=COLORS['bg'], fg=COLORS['subtext'], anchor='w')
        self.status_text.grid(row=0, column=0, sticky='w')

        self.startup_btn = tk.Button(bar, text='', font=('Segoe UI', 9),
                                     bg=COLORS['bg'], fg=COLORS['subtext'],
                                     relief='flat', cursor='hand2', bd=0,
                                     activebackground=COLORS['bg'],
                                     activeforeground=COLORS['text'],
                                     command=self._toggle_startup_gui)
        self.startup_btn.grid(row=0, column=1, sticky='e', padx=(0, 8))
        self._update_startup_button()

        self.shell_btn = tk.Button(bar, text='', font=('Segoe UI', 9),
                                   bg=COLORS['bg'], fg=COLORS['subtext'],
                                   relief='flat', cursor='hand2', bd=0,
                                   activebackground=COLORS['bg'],
                                   activeforeground=COLORS['text'],
                                   command=self._toggle_shell)
        self.shell_btn.grid(row=0, column=2, sticky='e')
        self._update_shell_button()

    def _update_startup_button(self):
        enabled = _is_startup_enabled()
        self.startup_btn.configure(
            text='\u23f1 Startup: ON' if enabled else '\u25a1 Startup: OFF',
            fg=COLORS['success'] if enabled else COLORS['subtext'])

    def _toggle_startup_gui(self):
        enabled = _is_startup_enabled()
        ok = _toggle_startup(not enabled)
        if ok:
            self._update_startup_button()
            self._set_status('Startup ' + ('enabled' if not enabled else 'disabled'))
        else:
            messagebox.showerror('Error', 'Could not modify startup settings')

    def _update_drop_zone_text(self):
        if self.target_paths:
            names = [os.path.basename(p) for p in self.target_paths]
            text = '\n'.join(names[:3])
            if len(names) > 3:
                text += f'\n... and {len(names) - 3} more'
            self.drop_text.configure(text=text, foreground=COLORS['text'])
            self.drop_icon.configure(text='\U0001f4e6')
        else:
            self.drop_text.configure(text='Drop files or folders here, or click to browse',
                                     foreground=COLORS['subtext'])
            self.drop_icon.configure(text='\U0001f4c2')

    def _browse_file(self):
        files = filedialog.askopenfilenames(
            title='Select files to scan',
            filetypes=[('All files', '*.*'),
                       ('Executables', '*.exe *.dll *.scr *.com *.pif'),
                       ('Scripts', '*.py *.ps1 *.bat *.vbs *.js *.hta'),
                       ('Documents', '*.docm *.xlsm *.pptm')])
        if files:
            self.target_paths = list(files)
            self._update_drop_zone_text()

    def _browse_folder(self):
        folder = filedialog.askdirectory(title='Select folder to scan')
        if folder:
            self.target_paths = [folder]
            self._update_drop_zone_text()

    def _select_and_scan(self, quick=False):
        self._browse_file()
        if self.target_paths:
            self._start_scan(quick=quick)

    def _set_scanning_state(self, scanning):
        self.scanning = scanning
        state = 'disabled' if scanning else 'normal'
        self.btn_quick.configure(state=state)
        self.btn_hard.configure(state=state)
        self.btn_system.configure(state=state)
        self.btn_stop.configure(state='normal' if scanning else 'disabled')

    def _start_system_scan(self):
        if self.scanning:
            return
        self._set_scanning_state(True)
        self.scan_aborted = False
        self.current_results = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.stats_vars['stats_scanned'].configure(text='0')
        self.stats_vars['stats_threats'].configure(text='0')
        self.stats_vars['stats_skipped'].configure(text='0')
        self.progress['value'] = 0
        self.progress_label.configure(text='Starting...')
        self.time_label.configure(text='')
        self._set_status('Running system-wide scan (persistence, network, memory)...')

        def scan_thread():
            findings = self.scanner.scan_system()
            self.root.after(0, lambda: self._system_scan_complete(findings))

        self.scan_thread = threading.Thread(target=scan_thread, daemon=True)
        self.scan_thread.start()

    def _system_scan_complete(self, findings):
        self._set_scanning_state(False)
        self._update_progress(100, type('R', (), {'scanned': 0, 'threats': findings, 'skipped': 0})())
        self.current_results = findings
        for t in findings:
            tag = SEVERITY_TAGS.get(t['severity'], ('low', COLORS['low']))[0]
            fname = os.path.basename(str(t.get('file', t.get('location', 'system'))))
            self.tree.insert('', 'end',
                             values=(fname, t['type'], t['severity'].upper(),
                                     t['detail'][:80]),
                             tags=(tag,))
        self.time_label.configure(text=f'System Scan: {len(findings)} findings')
        c = sum(1 for f in findings if f['severity'] == 'critical')
        h = sum(1 for f in findings if f['severity'] == 'high')
        self._set_status(f'System scan complete - {len(findings)} findings ({c}C/{h}H)')

    def _start_scan(self, quick=False):
        if self.scanning or not self.target_paths:
            return
        self._set_scanning_state(True)
        self.scan_aborted = False
        self.current_results = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.stats_vars['stats_scanned'].configure(text='0')
        self.stats_vars['stats_threats'].configure(text='0')
        self.stats_vars['stats_skipped'].configure(text='0')
        self.progress['value'] = 0
        self.progress_label.configure(text='Starting...')
        self.time_label.configure(text='')

        mode = 'Quick' if quick else 'Hard'
        self._set_status(f'{mode} scanning {len(self.target_paths)} target(s)...')

        def callback(progress, result):
            self.root.after(0, lambda: self._update_progress(progress, result))
            return not self.scan_aborted

        def scan_thread():
            total_targets = len(self.target_paths)
            agg = None
            for i, target in enumerate(self.target_paths):
                if self.scan_aborted:
                    break
                self.root.after(0, lambda t=target, idx=i: self._set_status(
                    f'Scanning [{idx+1}/{total_targets}]: {os.path.basename(t)}'))
                result = self.scanner.scan_path(
                    target, quick=quick, recursive=True, callback=callback)
                if agg is None:
                    agg = result
                else:
                    agg.threats.extend(result.threats)
                    agg.scanned += result.scanned
                    agg.errors += result.errors
                    agg.skipped += result.skipped
                    agg.time_taken += result.time_taken
            if agg is None:
                from core.scanner import ScanResult
                agg = ScanResult()
            self.root.after(0, lambda r=agg: self._scan_complete(r, quick))

        self.scan_thread = threading.Thread(target=scan_thread, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        self.scan_aborted = True
        self._set_status('Scan aborted by user')

    def _update_progress(self, progress, result):
        self.progress['value'] = progress
        self.progress_label.configure(text=f'{progress}%')
        self.stats_vars['stats_scanned'].configure(text=str(result.scanned))
        self.stats_vars['stats_threats'].configure(text=str(len(result.threats)))
        self.stats_vars['stats_skipped'].configure(text=str(result.skipped))

    def _scan_complete(self, result, quick):
        self._set_scanning_state(False)
        self._update_progress(100, result)
        self.current_results = result.threats

        for t in result.threats:
            tag = SEVERITY_TAGS.get(t['severity'], ('low', COLORS['low']))[0]
            self.tree.insert('', 'end',
                             values=(os.path.basename(t['file']), t['type'],
                                     t['severity'].upper(), t['detail'][:80]),
                             tags=(tag,))

        mode = 'Quick' if quick else 'Hard'
        elapsed = result.time_taken
        self.time_label.configure(
            text=f'{mode} Scan: {result.scanned} files, '
                 f'{len(result.threats)} threats in {elapsed:.1f}s')
        self._set_status(
            f'Scan complete - {result.scanned} files scanned, '
            f'{len(result.threats)} threats detected'
            + (f', {result.skipped} skipped' if result.skipped else ''))

        if result.threats and not self.scan_aborted:
            c, h = result.critical_count, result.high_count
            if c or h:
                msg = f'{c} critical and {h} high severity threats found.'
                if messagebox.askyesno('Threats Detected',
                                       f'{msg}\nQuarantine these threats?'):
                    self._quarantine_all(result.threats)

    def _quarantine_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo('No Selection', 'Select threats to quarantine.')
            return
        count = 0
        for item in selected:
            values = self.tree.item(item, 'values')
            fname = values[0]
            for t in self.current_results:
                if os.path.basename(t['file']) == fname:
                    ok, eid = quarantine_file(t['file'], t['type'])
                    if ok:
                        count += 1
                        self.tree.item(item, tags=('quarantined',))
                        self.tree.tag_configure('quarantined',
                                                foreground=COLORS['success'])
                    break
        self._set_status(f'Quarantined {count} threat(s)')

    def _quarantine_all(self, threats=None):
        targets = threats or self.current_results
        count = 0
        for t in targets:
            if t['severity'] in ('critical', 'high') and os.path.exists(t['file']):
                ok, eid = quarantine_file(t['file'], t['type'])
                if ok:
                    count += 1
        self._set_status(f'Quarantined {count} threat(s)')

    def _refresh_tree_tags(self):
        from utils.paths import quarantine_dir as _qd
        qpath = _qd()
        qfiles = [f for f in os.listdir(qpath) if f != 'manifest.json']
        for item in self.tree.get_children():
            values = self.tree.item(item, 'values')
            if any(f.endswith(values[0]) for f in qfiles):
                self.tree.item(item, tags=('quarantined',))
                self.tree.tag_configure('quarantined', foreground=COLORS['success'])

    def _show_restore_dialog(self):
        entries = list_quarantine()
        if not entries:
            messagebox.showinfo('Quarantine Empty', 'No quarantined files.')
            return
        win = tk.Toplevel(self.root)
        win.title('Restore from Quarantine')
        win.geometry('600x400')
        win.configure(bg=COLORS['bg'])
        win.transient(self.root)
        win.grab_set()

        frame = tk.Frame(win, bg=COLORS['bg'])
        frame.pack(fill='both', expand=True, padx=12, pady=12)

        tree = ttk.Treeview(frame, columns=('id', 'file', 'type', 'date'),
                            show='headings', height=10)
        tree.heading('id', text='ID')
        tree.heading('file', text='Original File')
        tree.heading('type', text='Threat Type')
        tree.heading('date', text='Date')
        tree.column('id', width=180)
        tree.column('file', width=200)
        tree.column('type', width=120)
        tree.column('date', width=140)
        tree.pack(fill='both', expand=True)

        for e in entries:
            tree.insert('', 'end', values=(
                e['id'], os.path.basename(e['original_path']),
                e['threat_type'], e['timestamp'][:19]))

        def do_restore():
            sel = tree.selection()
            if not sel:
                messagebox.showinfo('No Selection', 'Select an entry to restore.', parent=win)
                return
            eid = tree.item(sel[0], 'values')[0]
            ok, result = restore_file(eid)
            if ok:
                messagebox.showinfo('Restored', f'Restored to: {result}', parent=win)
                tree.delete(sel[0])
            else:
                messagebox.showerror('Error', str(result), parent=win)

        def do_delete():
            sel = tree.selection()
            if not sel:
                return
            eid = tree.item(sel[0], 'values')[0]
            delete_quarantined(eid)
            tree.delete(sel[0])

        btn_frame = tk.Frame(win, bg=COLORS['bg'])
        btn_frame.pack(pady=(0, 12))
        ttk.Button(btn_frame, text='\u21a9 Restore', style='Success.TButton',
                   command=do_restore).pack(side='left', padx=4)
        ttk.Button(btn_frame, text='\u2718 Delete', style='Danger.TButton',
                   command=do_delete).pack(side='left', padx=4)

    def _purge_all(self):
        if messagebox.askyesno('Purge All', 'Delete all quarantined files permanently?'):
            delete_quarantined()
            self._set_status('All quarantined files purged')

    def _clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.current_results = []
        self.stats_vars['stats_scanned'].configure(text='0')
        self.stats_vars['stats_threats'].configure(text='0')
        self.stats_vars['stats_skipped'].configure(text='0')
        self.progress['value'] = 0
        self.progress_label.configure(text='')
        self.time_label.configure(text='')
        self._set_status('Results cleared')

    def _show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()
        self.minimized = False

    def _hide_window(self):
        self.root.withdraw()
        self.minimized = True

    def _set_status(self, text):
        self.status_text.configure(text=text)

    def _toggle_shell(self):
        from shell_integration import register, unregister, is_registered
        if is_registered():
            ok, msg = unregister()
            messagebox.showinfo('Shell Extension', msg)
        else:
            ok, msg = register()
            messagebox.showinfo('Shell Extension', msg)
        self._update_shell_button()

    def _update_shell_button(self):
        try:
            from shell_integration import is_registered
            reg = is_registered()
            self.shell_btn.configure(
                text='\u2716 Shell Ext' if reg else '\u2714 Shell Ext',
                fg=COLORS['success'] if reg else COLORS['subtext'])
        except Exception:
            self.shell_btn.configure(text='Shell: N/A', fg=COLORS['subtext'])

    def _show_settings(self):
        win = tk.Toplevel(self.root)
        win.title('PyShield Settings')
        win.geometry('480x420')
        win.configure(bg=COLORS['bg'])
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)

        main = tk.Frame(win, bg=COLORS['bg'], padx=20, pady=20)
        main.pack(fill='both', expand=True)

        sections = [
            ('\u2699 General', [
                ('Startup with Windows', 'Run minimized to system tray on boot',
                 _is_startup_enabled(),
                 lambda v: (_toggle_startup(v), self._update_startup_button())),
                ('Right-click Integration', 'Quick Scan / Hard Scan in file context menu',
                 self._is_shell_registered(),
                 lambda v: self._toggle_shell_settings(v)),
            ]),
            ('\U0001f50d Scanning', [
                ('Quick Scan', 'Extension filter + signature hashes only (fast)',
                 None, None, True),
                ('Hard Scan', 'Full heuristics: PE analysis, RAT detection, '
                 'string scan, entropy check',
                 None, None, True),
            ]),
            ('\U0001f4a1 System', [
                ('System Scan', 'Persistence audit + network connections + '
                 'process module inspection',
                 None, None, True),
            ]),
        ]

        for sec_title, items in sections:
            sep = tk.Frame(main, bg=COLORS['border'], height=1)
            sep.pack(fill='x', pady=(12, 6))

            hdr = tk.Label(main, text=sec_title, font=('Segoe UI', 11, 'bold'),
                           bg=COLORS['bg'], fg=COLORS['primary'], anchor='w')
            hdr.pack(fill='x', pady=(0, 6))

            for item in items:
                frame = tk.Frame(main, bg=COLORS['surface'], padx=12, pady=8)
                frame.pack(fill='x', pady=3)

                row = tk.Frame(frame, bg=COLORS['surface'])
                row.pack(fill='x')

                text_frame = tk.Frame(row, bg=COLORS['surface'])
                text_frame.pack(side='left', fill='x', expand=True)

                tk.Label(text_frame, text=item[0], font=('Segoe UI', 10, 'bold'),
                        bg=COLORS['surface'], fg=COLORS['text'],
                        anchor='w').pack(fill='x')
                tk.Label(text_frame, text=item[1], font=('Segoe UI', 8),
                        bg=COLORS['surface'], fg=COLORS['subtext'],
                        anchor='w').pack(fill='x')

                if len(item) == 5 and item[4] is True:
                    lbl = tk.Label(row, text='\u2713 Active', font=('Segoe UI', 9, 'bold'),
                                   bg=COLORS['surface'], fg=COLORS['success'])
                    lbl.pack(side='right', padx=(8, 0))
                elif item[2] is not None and item[3] is not None:
                    var = tk.BooleanVar(value=item[2])
                    cb = tk.Checkbutton(row, variable=var,
                                       bg=COLORS['surface'], fg=COLORS['text'],
                                       selectcolor=COLORS['surface'],
                                       activebackground=COLORS['surface'],
                                       activeforeground=COLORS['text'],
                                       command=lambda v=var, cb_fn=item[3]: cb_fn(v.get()),
                                       highlightthickness=0, bd=0)
                    cb.pack(side='right')

        tk.Label(main, text='', bg=COLORS['bg']).pack(pady=4)
        ttk.Button(main, text='Close', style='TButton',
                   command=win.destroy).pack()

    def _is_shell_registered(self):
        from shell_integration import is_registered
        return is_registered()

    def _toggle_shell_settings(self, enable):
        from shell_integration import register, unregister
        if enable:
            register()
        else:
            unregister()
        self._update_shell_button()

    def _show_about(self):
        from core.signatures import load_signatures
        sigs = load_signatures()
        total = sum(len(v) if isinstance(v, list) else 0 for v in sigs.values())
        messagebox.showinfo('About PyShield',
                            f'PyShield Antivirus v2.0\n\n'
                            f'Creator: Eren\n\n'
                            f'Advanced local malware scanner with RAT/grabber '
                            f'detection, system-wide persistence analysis, '
                            f'network monitoring, and real-time process protection.\n\n'
                            f'Signatures: {total}\n'
                            f'Detection: Signature, Heuristic, PE, Entropy, '
                            f'RAT Family, Network, Memory, Persistence\n'
                            f'Platform: Windows\n\n'
                            f'Runs in system tray for background protection.')

    def _on_close(self):
        if self.scanning:
            if not messagebox.askokcancel('Scan in Progress',
                                           'A scan is running. Minimize to tray?'):
                return
            self.scan_aborted = True
        self._hide_window()

    def _quit_app(self):
        if self.scanning:
            self.scan_aborted = True
        if self.tray:
            self.tray.stop()
        self.root.destroy()


if __name__ == '__main__':
    PyShieldGUI()
