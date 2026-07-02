import threading
import time
import subprocess
import os
from utils.helpers import file_hash


SYSTEM_PROCS = {'system', 'system idle process', 'registry', 'memory compression',
                'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
                'lsass.exe', 'svchost.exe', 'fontdrvhost.exe', 'winlogon.exe',
                'dwm.exe', 'ctfmon.exe', 'spoolsv.exe', 'conhost.exe',
                'taskhostw.exe', 'sihost.exe', 'RuntimeBroker.exe',
                'SecurityHealthService.exe', 'Widgets.exe', 'SearchIndexer.exe',
                'dllhost.exe', 'dasHost.exe', 'audiodg.exe', 'WmiPrvSE.exe'}


class ProcessMonitor:
    def __init__(self, interval=5):
        self.interval = interval
        self.running = False
        self.thread = None
        self.watchlist = set()
        self.suspicious_processes = []

    def _get_process_list(self):
        try:
            result = subprocess.run(
                ['wmic', 'process', 'get', 'ProcessId,Name,ExecutablePath',
                 '/format:csv'],
                capture_output=True, text=True, timeout=5
            )
            processes = []
            for line in result.stdout.strip().split('\n'):
                if not line.strip() or ',' not in line:
                    continue
                parts = line.split(',')
                if len(parts) >= 3:
                    name = parts[1].strip()
                    pid = parts[2].strip()
                    path = parts[0].strip() if len(parts) > 1 else ''
                    if path.startswith('"') and path.endswith('"'):
                        path = path[1:-1]
                    if pid and pid.isdigit():
                        processes.append((name, pid, path))
            return processes
        except Exception:
            return []

    def _check_new_processes(self, current):
        current_set = set((n, p) for n, p, _ in current)
        old_set = set((n, p) for n, p, _ in self.watchlist) if self.watchlist else set()
        new = current_set - old_set
        proc_map = {(n, p): path for n, p, path in current}
        for name, pid in new:
            path = proc_map.get((name, pid), '')
            if not path or name.lower() in SYSTEM_PROCS:
                continue
            if not os.path.exists(path):
                self.suspicious_processes.append({
                    'name': name, 'pid': pid, 'path': path,
                    'reason': 'Process executable not found on disk',
                    'severity': 'critical'
                })
            elif name.lower() == 'svchost.exe' and \
                 path.lower() != r'c:\windows\system32\svchost.exe':
                self.suspicious_processes.append({
                    'name': name, 'pid': pid, 'path': path,
                    'reason': f'Svchost running from unusual location: {path}',
                    'severity': 'critical'
                })
        return current

    def _monitor_loop(self):
        while self.running:
            try:
                current = self._get_process_list()
                if self.watchlist:
                    self._check_new_processes(current)
                self.watchlist = current
            except Exception:
                pass
            time.sleep(self.interval)

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()
            return True
        return False

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)
        return True

    def get_suspicious(self):
        result = list(self.suspicious_processes)
        self.suspicious_processes.clear()
        return result

    def scan_current_processes(self):
        results = []
        processes = self._get_process_list()
        for name, pid, path in processes:
            if not path or name.lower() in SYSTEM_PROCS:
                continue
            if not os.path.exists(path):
                results.append({
                    'name': name, 'pid': pid, 'path': path,
                    'reason': 'Process file missing from disk',
                    'severity': 'high'
                })
                continue
            h = file_hash(path)
            if h:
                from core.signatures import known_malicious_hash
                if known_malicious_hash(h):
                    results.append({
                        'name': name, 'pid': pid, 'path': path,
                        'reason': 'Known malicious hash',
                        'severity': 'critical'
                    })
            if name.lower() == 'svchost.exe' and \
               path.lower() != r'c:\windows\system32\svchost.exe':
                results.append({
                    'name': name, 'pid': pid, 'path': path,
                    'reason': 'Svchost from unusual location, possible hollowing',
                    'severity': 'critical'
                })
        return results
