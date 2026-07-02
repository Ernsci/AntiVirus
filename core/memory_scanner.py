import subprocess
import os


SUSPICIOUS_PATTERNS = [
    b'CreateRemoteThread', b'VirtualAllocEx', b'WriteProcessMemory',
    b'NtUnmapViewOfSection', b'SetWindowsHookEx',
    b'GetAsyncKeyState', b'MiniDumpWriteDump',
    b'bitcoin', b'wallet', b'electrum',
    b'Login Data', b'Cookies', b'Web Data',
    b'Discord', b'discordapp', b'discord.com',
    b'sqlite3_open', b'CryptUnprotectData',
    b'Send', b'recv', b'connect',
]

SUSPICIOUS_DLLS = [
    'psapi.dll', 'wtsapi32.dll', 'dbghelp.dll',
    'vcruntime140.dll', 'msvcp140.dll',
    'winmm.dll', 'winmmbase.dll',
    'avicap32.dll', 'msvfw32.dll',
]


class MemoryScanner:
    def check_process_modules(self, pid):
        findings = []
        try:
            result = subprocess.run(
                ['tasklist', '/fi', f'PID eq {pid}', '/m'],
                capture_output=True, text=True, timeout=5
            )
            modules = result.stdout.lower()
            for dll in SUSPICIOUS_DLLS:
                if dll in modules:
                    findings.append({
                        'type': 'suspicious_module',
                        'detail': f'PID {pid} loaded: {dll}',
                        'severity': 'medium'
                    })
        except Exception:
            pass
        return findings

    def check_all_processes(self):
        findings = []
        try:
            result = subprocess.run(
                ['tasklist', '/fo', 'csv', '/nh'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.strip().split('","')
                if len(parts) >= 2:
                    name = parts[0].strip('"').lower()
                    pid = parts[1].strip('"')
                    if pid and pid.isdigit() and name.endswith('.exe'):
                        findings.extend(self.check_process_modules(pid))
        except Exception:
            pass
        return findings

    def scan_process_memory_pattern(self, pid, patterns=None):
        if patterns is None:
            patterns = SUSPICIOUS_PATTERNS
        findings = []
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 f'$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; '
                 f'if ($p) {{ $p.Modules | Select-Object ModuleName }}'],
                capture_output=True, text=True, timeout=5
            )
            modules_text = result.stdout.lower()
            for pat in patterns:
                if isinstance(pat, bytes):
                    try:
                        decoded = pat.decode('latin-1').lower()
                        if decoded in modules_text:
                            findings.append(pat)
                    except Exception:
                        pass
        except Exception:
            pass
        return findings

    def scan(self):
        return self.check_all_processes()
