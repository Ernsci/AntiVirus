import os
import json
import re
from utils.helpers import read_strings, is_pe_file
from core.pe_parser import PEParser
from core.byte_pattern import BytePatternMatcher


RAT_SIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            'data', 'rat_signatures.json')


def _load_sigs():
    if os.path.exists(RAT_SIG_PATH):
        with open(RAT_SIG_PATH, 'r') as f:
            return json.load(f)
    return {'family_signatures': [], 'generic_rat_imports': [],
            'credential_targets': [], 'suspicious_directory_paths': []}


class RATDetector:
    def __init__(self):
        self.sigs = _load_sigs()
        self.matcher = BytePatternMatcher()
        self._family_cache = {}

    def detect_family(self, filepath):
        if not os.path.exists(filepath) or not is_pe_file(filepath):
            return None
        if filepath in self._family_cache:
            return self._family_cache[filepath]

        pe = PEParser(filepath)
        if not pe.valid:
            self._family_cache[filepath] = None
            return None

        strings = read_strings(filepath, min_length=3)
        all_text = '\n'.join(strings)

        section_names = [s['name'].lower() for s in pe.sections]
        imports_lower = [i.lower() for i in pe.imports]

        for sig in self.sigs['family_signatures']:
            score = 0
            thresholds = {'critical': 3, 'high': 2}
            need = thresholds.get(sig['severity'], 2)

            for pat in sig.get('patterns', []):
                if pat.lower() in all_text.lower():
                    score += 2

            for imp in sig.get('imports', []):
                if imp.lower() in imports_lower:
                    score += 1.5

            for sec in sig.get('sections', []):
                if sec.lower() in section_names:
                    score += 2

            for mtx in sig.get('mutexes', []):
                if mtx.lower() in all_text.lower():
                    score += 2

            if score >= need:
                result = {
                    'family': sig['family'],
                    'confidence': min(int((score / max(need, 1)) * 50 + 50), 100),
                    'score': score,
                    'description': sig['description'],
                    'severity': sig['severity']
                }
                self._family_cache[filepath] = result
                return result

        rat_imports = self.sigs.get('generic_rat_imports', [])
        found_rat_imports = [i for i in rat_imports if i.lower() in imports_lower]
        if len(found_rat_imports) >= 4:
            result = {
                'family': 'GenericRAT',
                'confidence': min(len(found_rat_imports) * 15, 80),
                'score': len(found_rat_imports),
                'description': f'Generic RAT indicators ({len(found_rat_imports)} suspicious imports)',
                'severity': 'high',
                'matched_imports': found_rat_imports[:8]
            }
            self._family_cache[filepath] = result
            return result

        self._family_cache[filepath] = None
        return None

    def check_rat_c2(self, filepath):
        strings = read_strings(filepath, min_length=6)
        findings = []
        ip_port = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}')
        domain_port = re.compile(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:\d{2,5}')
        base64 = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')

        for s in strings:
            if ip_port.match(s):
                findings.append({'type': 'rat_c2_ip', 'detail': f'C2 pattern: {s[:40]}',
                                 'severity': 'critical'})
            if domain_port.match(s):
                findings.append({'type': 'rat_c2_domain', 'detail': f'C2 pattern: {s[:50]}',
                                 'severity': 'critical'})
            if base64.match(s) and len(s) > 60:
                findings.append({'type': 'base64_payload', 'detail': 'Large base64 string',
                                 'severity': 'high'})
            if 'http://' in s and ('/gate' in s or '/connect' in s or '/command' in s):
                findings.append({'type': 'rat_panel_url', 'detail': f'Panel URL: {s[:60]}',
                                 'severity': 'critical'})

        return findings

    def check_anti_debug(self, filepath):
        strings = read_strings(filepath, min_length=3)
        all_text = '\n'.join(strings).lower()
        findings = []
        anti_debug = ['IsDebuggerPresent', 'NtGlobalFlag', 'CheckRemoteDebuggerPresent',
                      'OutputDebugString', 'NtQueryInformationProcess',
                      'NtSetInformationThread', 'HideThread',
                      'ZwQueryInformationProcess', 'ProcessDebugPort',
                      'ProcessDebugObjectHandle', 'ProcessDebugFlags',
                      'RDSEED', 'rdtsc', 'CPUID', 'VMDetect',
                      'TitanHide', 'vmtoolsd', 'VBoxGuest',
                      'virtualbox', 'vmware', 'qemu', 'xen']

        found = [s for s in anti_debug if s.lower() in all_text]
        if len(found) >= 3:
            findings.append({
                'type': 'anti_debug',
                'detail': f'Anti-debug/VM techniques: {", ".join(found[:5])}',
                'severity': 'high'
            })
        return findings

    def check_grabber_targets(self, filepath):
        strings = read_strings(filepath, min_length=5)
        all_text = '\n'.join(strings).lower()
        findings = []

        targets = self.sigs.get('credential_targets', [])
        found_targets = [t for t in targets if t.lower() in all_text]
        if len(found_targets) >= 2:
            findings.append({
                'type': 'credential_theft',
                'detail': f'Targets: {", ".join(found_targets[:4])}',
                'severity': 'critical'
            })

        paths = self.sigs.get('suspicious_directory_paths', [])
        found_paths = [p for p in paths if p.lower() in all_text]
        if found_paths:
            findings.append({
                'type': 'credential_directory_enum',
                'detail': f'Enumerating: {", ".join(found_paths[:3])}',
                'severity': 'critical'
            })

        crypto_wallets = ['wallet.dat', 'electrum', 'exodus', 'atomic',
                          'blockchain', 'metamask', 'coinbase', 'binance']
        found_wallets = [w for w in crypto_wallets if w in all_text]
        if found_wallets:
            findings.append({
                'type': 'crypto_theft',
                'detail': f'Crypto wallet targets: {", ".join(found_wallets[:4])}',
                'severity': 'critical'
            })

        return findings

    def check_persistence_install(self, filepath):
        strings = read_strings(filepath, min_length=5)
        all_text = '\n'.join(strings).lower()
        findings = []

        persistence_apis = [
            'RegCreateKeyEx', 'RegSetValueEx', 'SHCreateShortcut',
            'CreateService', 'OpenSCManager', 'StartService',
            'SchTasksRegister', 'ITaskScheduler',
            'CopyFile', 'MoveFileEx',
            'GetModuleFileName', 'GetTempPath',
            'SHGetFolderPath', 'SHGetSpecialFolderPath',
            'AppData', 'Startup', 'Start Menu\\Programs\\Startup',
            'Run\\', 'RunOnce', 'CurrentVersion\\Run'
        ]
        found = [a for a in persistence_apis if a.lower() in all_text]
        if len(found) >= 3:
            findings.append({
                'type': 'persistence_install',
                'detail': f'Persistence APIs: {", ".join(found[:5])}',
                'severity': 'high'
            })
        return findings

    def scan(self, filepath):
        findings = []
        family = self.detect_family(filepath)
        if family:
            findings.append({
                'file': filepath,
                'type': f'malware_family:{family["family"]}',
                'severity': family['severity'],
                'detail': f'{family["description"]} (confidence: {family["confidence"]}%)'
            })
        findings.extend([{**f, 'file': filepath} for f in self.check_rat_c2(filepath)])
        findings.extend([{**f, 'file': filepath} for f in self.check_anti_debug(filepath)])
        findings.extend([{**f, 'file': filepath} for f in self.check_grabber_targets(filepath)])
        findings.extend([{**f, 'file': filepath} for f in self.check_persistence_install(filepath)])
        return findings
