import subprocess
import os
import re


AUTORUN_LOCATIONS = [
    (r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
     'HKLM Run', 'medium'),
    (r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
     'HKCU Run', 'medium'),
    (r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
     'HKLM RunOnce', 'high'),
    (r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
     'HKCU RunOnce', 'high'),
    (r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
     'HKLM RunServices', 'high'),
    (r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit',
     'Winlogon Userinit', 'critical'),
    (r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell',
     'Winlogon Shell', 'critical'),
    (r'HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Load',
     'Windows Load', 'critical'),
    (r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs',
     'AppInit DLLs', 'critical'),
    (r'HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute',
     'BootExecute', 'critical'),
    (r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad',
     'ShellServiceObjectDelayLoad', 'high'),
    (r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler',
     'SharedTaskScheduler', 'high'),
]

SUSPICIOUS_STARTUP_PATHS = [
    'C:\\Users\\',
    'C:\\ProgramData\\',
    'C:\\Temp',
    'C:\\Windows\\Temp',
    '%TEMP%',
    '%APPDATA%',
    '%LOCALAPPDATA%',
    '\\AppData\\Roaming\\',
    '\\AppData\\Local\\',
]

SUSPICIOUS_NAMES = ['svchost', 'rundll32', 'explorer', 'lsass',
                    'winlogon', 'csrss', 'services', 'smss',
                    'spoolsv', 'conhost', 'taskhost', 'RuntimeBroker']

SUSPICIOUS_SERVICES_PATTERNS = [
    r'c:\\users\\', r'c:\\programdata\\', r'c:\\temp',
    r'%appdata%', r'%temp%', r'powershell.*-enc',
    r'-WindowStyle Hidden', r'-ExecutionPolicy Bypass',
    r'rundll32.*javascript', r'regsvr32.*/s.*http',
    r'mshta.*http', r'cmd.*/c.*powershell',
    r'wmic.*process.*create',
]


class PersistenceAnalyzer:
    def scan_registry_run_keys(self):
        findings = []
        for location, desc, severity in AUTORUN_LOCATIONS:
            try:
                result = subprocess.run(
                    ['reg', 'query', location, '/s'],
                    capture_output=True, text=True, timeout=8
                )
                output = result.stdout.strip()
                if not output:
                    continue
                for line in output.split('\n'):
                    line = line.strip()
                    if not line or line.startswith(location) or line.startswith('HKEY'):
                        continue
                    if 'REG_' in line:
                        parts = line.split('REG_', 1)
                        if len(parts) > 1:
                            name = parts[0].strip()
                            value = parts[1].strip()
                            if len(value) > 3 and name and value.lower() not in ('(value not set)', ''):
                                suspicious = False
                                for sp in SUSPICIOUS_STARTUP_PATHS:
                                    if sp.lower().replace('%temp%', '').replace('%appdata%', '') in value.lower():
                                        suspicious = True
                                        break
                                findings.append({
                                    'type': 'persistence',
                                    'detail': f'{desc}: {name} = {value[:120]}',
                                    'severity': severity,
                                    'location': location,
                                    'value': value
                                })
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        return findings

    def scan_scheduled_tasks(self):
        findings = []
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'LIST', '/v'],
                capture_output=True, text=True, timeout=15
            )
            tasks = result.stdout
            current_task_name = None
            current_task_cmd = None
            for line in tasks.split('\n'):
                line = line.strip()
                if line.startswith('TaskName:'):
                    current_task_name = line.split(':', 1)[1].strip() if ':' in line else ''
                elif line.startswith('Task To Run:'):
                    current_task_cmd = line.split(':', 1)[1].strip() if ':' in line else ''
                    if current_task_cmd and current_task_name:
                        for pat in SUSPICIOUS_SERVICES_PATTERNS:
                            if re.search(pat, current_task_cmd.lower()):
                                findings.append({
                                    'type': 'scheduled_task',
                                    'detail': f'{current_task_name}: {current_task_cmd[:120]}',
                                    'severity': 'high'
                                })
                                break
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        return findings

    def scan_services(self):
        findings = []
        try:
            result = subprocess.run(
                ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                capture_output=True, text=True, timeout=15
            )
            services = result.stdout
            current_name = None
            current_path = None
            current_state = None
            for line in services.split('\n'):
                line = line.strip()
                if line.startswith('SERVICE_NAME:'):
                    current_name = line.split(':', 1)[1].strip()
                elif 'BINARY_PATH_NAME' in line:
                    current_path = line.split(':', 1)[1].strip() if ':' in line else ''
                elif 'STATE' in line:
                    current_state = line
                    if current_name and current_path and current_state:
                        path_lower = current_path.lower()
                        for pat in SUSPICIOUS_SERVICES_PATTERNS:
                            if re.search(pat, path_lower):
                                findings.append({
                                    'type': 'suspicious_service',
                                    'detail': f'{current_name}: {current_path[:120]}',
                                    'severity': 'high'
                                })
                                break
                        current_name = None
                        current_path = None
                        current_state = None
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        return findings

    def scan_startup_folder(self):
        findings = []
        startup_paths = [
            os.path.join(os.environ.get('APPDATA', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
            os.path.join(os.environ.get('ProgramData', ''), r'Microsoft\Windows\Start Menu\Programs\Startup'),
        ]
        for sp in startup_paths:
            if os.path.exists(sp):
                try:
                    for fname in os.listdir(sp):
                        fpath = os.path.join(sp, fname)
                        if os.path.isfile(fpath):
                            ext = os.path.splitext(fname)[1].lower()
                            if ext in ('.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.lnk'):
                                findings.append({
                                    'type': 'startup_folder',
                                    'detail': f'{fname} in Startup folder',
                                    'severity': 'medium'
                                })
                except PermissionError:
                    pass
        return findings

    def scan_all(self):
        findings = []
        findings.extend(self.scan_registry_run_keys())
        findings.extend(self.scan_scheduled_tasks())
        findings.extend(self.scan_services())
        findings.extend(self.scan_startup_folder())
        return findings
