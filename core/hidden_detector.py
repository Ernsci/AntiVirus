import os
import subprocess
import ctypes
from ctypes import wintypes
from utils.helpers import read_strings


class HiddenMalwareDetector:
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32

    def check_ads(self, filepath):
        results = []
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 f"Get-Item -LiteralPath '{filepath}' -Stream * | Select-Object -ExpandProperty Stream"],
                capture_output=True, text=True, timeout=10
            )
            streams = [s.strip() for s in result.stdout.split('\n') if s.strip()]
            for s in streams:
                if s != ':$DATA':
                    results.append({
                        'type': 'ads',
                        'detail': f"ADS stream found: {s}",
                        'severity': 'high',
                        'file': filepath
                    })
        except Exception:
            pass
        return results

    def check_process_hollowing(self, pid):
        results = []
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 f"Get-Process -Id {pid} | Select-Object Name, Path, StartTime"],
                capture_output=True, text=True, timeout=5
            )
            output = result.stdout.strip()
            if not output or 'Path' not in output:
                return results
            lines = [l.strip() for l in output.split('\n') if l.strip()]
            if len(lines) < 2:
                return results
            parts = [p for p in lines[1].split() if p]
            if len(parts) < 1:
                return results
            proc_name = parts[0]
            proc_path = parts[1] if len(parts) > 1 else None
            if proc_name and proc_name.lower() in ('svchost.exe', 'lsass.exe', 'csrss.exe',
                                                    'winlogon.exe', 'services.exe'):
                expected = f"c:\\windows\\system32\\{proc_name}"
                if proc_path and proc_path.lower() != expected:
                    results.append({
                        'type': 'process_hollowing',
                        'detail': f"{proc_name} running from {proc_path}, expected {expected}",
                        'severity': 'critical',
                        'file': proc_path
                    })
        except Exception:
            pass
        return results

    def check_persistence(self):
        results = []
        locations = [
            (r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
             'HKLM Run key'),
            (r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
             'HKCU Run key'),
            (r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM RunOnce key'),
            (r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit',
             'Winlogon Userinit'),
            (r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs',
             'AppInit DLLs'),
        ]
        for location, desc in locations:
            try:
                result = subprocess.run(
                    ['reg', 'query', location],
                    capture_output=True, text=True, timeout=5
                )
                if result.stdout.strip():
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if line and '\\' in line:
                            results.append({
                                'type': 'persistence',
                                'detail': f"{desc}: {line[:100]}",
                                'severity': 'medium',
                                'file': location
                            })
            except Exception:
                pass
        return results

    def check_dll_hijacking(self):
        results = []
        try:
            safe_dlls = {'kernel32.dll', 'ntdll.dll', 'user32.dll', 'gdi32.dll',
                         'advapi32.dll', 'ole32.dll', 'shell32.dll', 'ws2_32.dll'}
            suspicious_paths = []
            result = subprocess.run(
                ['tasklist', '/m'],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                if '.dll' in line.lower():
                    parts = line.strip().split()
                    for p in parts:
                        if p.lower().endswith('.dll') and p.lower() not in safe_dlls:
                            suspicious_paths.append(p)
            if suspicious_paths:
                results.append({
                    'type': 'dll_hijacking',
                    'detail': f"Suspicious DLLs loaded: {', '.join(suspicious_paths[:5])}",
                    'severity': 'medium',
                    'file': None
                })
        except Exception:
            pass
        return results

    def run_all(self, filepath=None, pid=None):
        results = []
        if filepath and os.path.exists(filepath):
            results.extend(self.check_ads(filepath))
        if pid:
            results.extend(self.check_process_hollowing(pid))
        results.extend(self.check_persistence())
        results.extend(self.check_dll_hijacking())
        return results
