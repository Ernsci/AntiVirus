import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

from core.scanner import Scanner
from core.process_monitor import ProcessMonitor
from core.quarantine import quarantine_file, restore_file, delete_quarantined, list_quarantine
from core.signatures import load_signatures
from core.url_scanner import scan_url


SEVERITY_COLORS = {
    'critical': '[CRITICAL]', 'high': '[HIGH]',
    'medium': '[MEDIUM]', 'low': '[LOW]',
}


def print_banner():
    print('='*40)
    print('     PyShield Antivirus')
    print('     Local Security Scanner')
    print('='*40)


def print_threat(threat):
    color = SEVERITY_COLORS.get(threat['severity'], '[?]')
    f = threat.get('file', threat.get('url', 'unknown'))
    print(f"  {color} {threat['type']:25s} {os.path.basename(str(f))[:40]:40s} {threat['detail'][:60]}")


def cmd_scan(args):
    if not args:
        print("Usage: antivirus scan <path> [--quick]")
        return
    quick = '--quick' in args
    path = [a for a in args if a != '--quick'][0] if args else '.'
    if not os.path.exists(path):
        print(f"Path not found: {path}")
        return
    scanner = Scanner(threads=2)
    print(f"\nScanning: {path}" + (" (quick mode)" if quick else "") + "\n")
    result = scanner.scan_path(path, quick=quick)
    for t in result.threats:
        print_threat(t)
    skipped = f", {result.skipped} skipped" if result.skipped else ""
    print(f"\nScan complete: {result.scanned} files{skipped}, "
          f"{len(result.threats)} threats "
          f"({result.critical_count}C/{result.high_count}H/"
          f"{result.medium_count}M/{result.low_count}L)"
          f" in {result.time_taken:.1f}s")
    if result.threats:
        auto_q = input("\nQuarantine threats? (y/n): ").lower().strip() == 'y'
        if auto_q:
            for t in result.threats:
                if t['severity'] in ('critical', 'high') and os.path.exists(t['file']):
                    ok, eid = quarantine_file(t['file'], t['type'])
                    if ok:
                        print(f"  Quarantined: {os.path.basename(t['file'])} [{eid}]")
                    else:
                        print(f"  Failed: {eid}")


def cmd_quick(args):
    cmd_scan((args or ['.']) + ['--quick'])


def cmd_url(args):
    if not args:
        print("Usage: antivirus url <url> [...urls]")
        return
    for url in args:
        print(f"\nScanning URL: {url}")
        results = scan_url(url)
        if not results:
            print("  No threats detected")
        for r in results:
            print_threat(r)


def cmd_monitor(args):
    interval = 10
    if args and args[0].isdigit():
        interval = int(args[0])
    monitor = ProcessMonitor(interval=interval)
    print(f"\nProcess monitor started (interval: {interval}s). Press Ctrl+C to stop.\n")
    try:
        monitor.start()
        while True:
            time.sleep(interval)
            suspicious = monitor.get_suspicious()
            if suspicious:
                for s in suspicious:
                    color = SEVERITY_COLORS.get(s['severity'], '[?]')
                    print(f"  {color} {s['name']:25s} PID:{s['pid']:>6s} {s['reason']}")
            else:
                print(f"  [{time.strftime('%H:%M:%S')}] No threats detected")
    except KeyboardInterrupt:
        monitor.stop()
        print("\nMonitor stopped")


def cmd_quarantine(args):
    if not args or args[0] == 'list':
        entries = list_quarantine()
        if not entries:
            print("No quarantined files")
            return
        print(f"\nQuarantined files ({len(entries)}):\n")
        for e in entries:
            print(f"  [{e['id']}] {os.path.basename(e['original_path'])}")
            print(f"        Type: {e['threat_type']} | Date: {e['timestamp'][:19]}")
            print(f"        From: {e['original_path']}\n")
    elif args[0] == 'restore' and len(args) > 1:
        ok, result = restore_file(args[1])
        print(f"  Restored: {result}" if ok else f"  Failed: {result}")
    elif args[0] == 'delete' and len(args) > 1:
        ok = delete_quarantined(args[1])
        print(f"  Deleted entry: {args[1]}" if ok else "  Entry not found")
    elif args[0] == 'purge':
        delete_quarantined()
        print("  All quarantined files purged")


def cmd_hidden(args):
    path = args[0] if args else None
    from core.hidden_detector import HiddenMalwareDetector
    detector = HiddenMalwareDetector()
    results = detector.run_all(filepath=path)
    if not results:
        print("  No hidden malware detected")
    for r in results:
        print_threat(r)


def cmd_system(args):
    scanner = Scanner(threads=2)
    print('\nRunning system-wide scan (persistence, network, memory)...\n')
    findings = scanner.scan_system()
    if not findings:
        print('  No threats detected')
    for f in findings:
        color = SEVERITY_COLORS.get(f['severity'], '[?]')
        src = os.path.basename(str(f.get('file', f.get('location', 'system'))))
        print(f"  {color} {f['type']:30s} {src[:40]:40s} {f['detail'][:60]}")
    c = sum(1 for f in findings if f['severity'] == 'critical')
    h = sum(1 for f in findings if f['severity'] == 'high')
    print(f'\nSystem scan complete - {len(findings)} total ({c}C/{h}H)')


def cmd_processes(args):
    monitor = ProcessMonitor()
    results = monitor.scan_current_processes()
    if not results:
        print("  No suspicious processes found")
    for r in results:
        print(f"  {SEVERITY_COLORS.get(r['severity'], '[?]')} "
              f"{r['name']:25s} PID:{r['pid']:>6s} {r['reason']}")


def cmd_gui(args):
    from gui import PyShieldGUI
    PyShieldGUI()


def cmd_shell(args):
    from shell_integration import register, unregister, is_registered
    if not args:
        print('Registered' if is_registered() else 'Not registered')
        return
    if args[0] == 'register':
        ok, msg = register()
        print(msg)
        if not ok:
            sys.exit(1)
    elif args[0] == 'unregister':
        ok, msg = unregister()
        print(msg)
    else:
        print(f"Usage: antivirus shell [register|unregister]")


def cmd_info(args):
    print_banner()
    sigs = load_signatures()
    total = sum(len(v) if isinstance(v, list) else 0 for v in sigs.values())
    from utils.paths import quarantine_dir as _qd
    qdir = _qd()
    qcount = len([f for f in os.listdir(qdir) if f != 'manifest.json'])
    print(f"\n  Signatures: {total}")
    print(f"  Scanner threads: 2 (of {os.cpu_count() or 'N/A'} cores)")
    print(f"  Quarantined: {qcount} files")
    print(f"  Max file size: 50MB (quick) / 200MB (full)")
    print(f"  Memory: strings scan limited to 512KB per file")


def cmd_startup(args):
    if args and args[0] == 'off':
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r'Software\Microsoft\Windows\CurrentVersion\Run',
                                 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, 'PyShieldAV')
            winreg.CloseKey(key)
            print('Startup disabled')
        except Exception as e:
            print(f'Failed: {e}')
    else:
        import winreg
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r'Software\Microsoft\Windows\CurrentVersion\Run',
                                 0, winreg.KEY_SET_VALUE)
            exe = sys.executable
            script = os.path.join(os.path.dirname(__file__), 'gui.py')
            if script.endswith('.py'):
                cmd = f'"{exe}" "{script}" --tray'
            else:
                cmd = f'"{script}" --tray'
            winreg.SetValueEx(key, 'PyShieldAV', 0, winreg.REG_SZ, cmd)
            winreg.CloseKey(key)
            print('Startup enabled (launches minimized to tray)')
        except Exception as e:
            print(f'Failed (run as admin?): {e}')


def cmd_build(args):
    from build import build
    build()


def print_help():
    print_banner()
    print("""
Commands:
  scan <path> [--quick]     Scan file or directory
  quick <path>              Quick scan (skip heuristics)
  url <url> [...]           Scan URL(s)
  gui                       Launch graphical interface
  monitor [interval]        Monitor running processes
  processes                 Scan current processes
  system                    Full system scan (RAT, persistence, network)
  hidden [file]             Check for hidden malware
  quarantine list           List quarantined files
  quarantine restore <id>   Restore file from quarantine
  quarantine delete <id>    Delete quarantined file
  quarantine purge          Delete all quarantined files
  shell [register|unreg]    Manage right-click context menu
  startup [off]             Enable/disable Windows startup
  build                     Build standalone .exe with PyInstaller
  info                      Show scanner info
  help                      Show this help
""")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('help', '--help', '-h'):
        print_help()
        return
    cmd = sys.argv[1]
    args = sys.argv[2:]

    commands = {
        'scan': cmd_scan, 'quick': cmd_quick, 'url': cmd_url,
        'monitor': cmd_monitor, 'quarantine': cmd_quarantine,
        'hidden': cmd_hidden, 'processes': cmd_processes,
        'system': cmd_system,
        'info': cmd_info, 'gui': cmd_gui, 'shell': cmd_shell,
        'startup': cmd_startup, 'build': cmd_build,
    }
    if cmd in commands:
        commands[cmd](args)
    else:
        print(f"Unknown command: {cmd}")
        print_help()


if __name__ == '__main__':
    main()
