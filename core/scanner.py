import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.helpers import file_hash, file_entropy, is_pe_file, read_strings
from core.signatures import load_heuristic_rules, match_signature
from core.pe_parser import PEParser
from core.hidden_detector import HiddenMalwareDetector
from core.url_scanner import scan_url, scan_text_for_urls
from core.rat_detector import RATDetector
from core.network_scanner import NetworkScanner
from core.persistence_analyzer import PersistenceAnalyzer
from core.memory_scanner import MemoryScanner


SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1',
                         '.vbs', '.js', '.jse', '.vbe', '.wsf', '.wsh',
                         '.hta', '.msi', '.msp', '.com', '.pif', '.cpl',
                         '.docm', '.xlsm', '.pptm', '.jar',
                         '.py', '.pyw', '.rb', '.pl', '.php'}
SUSPICIOUS_STRINGS = ['CreateRemoteThread', 'VirtualAllocEx',
                      'WriteProcessMemory', 'WinExec', 'ShellExecute',
                      'Process32First', 'Toolhelp32', 'NtUnmapViewOfSection',
                      'URLDownloadToFile', 'WinHttpOpen',
                      'MiniDumpWriteDump', 'IsDebuggerPresent',
                      'OutputDebugString', 'CheckRemoteDebuggerPresent',
                      'ctypes.windll', 'kernel32', 'ntdll',
                      'subprocess.Popen', 'os.system', 'os.popen',
                      'base64.b64decode', 'base64.b64encode']

MAX_FILE_SIZE_QUICK = 50 * 1024 * 1024
MAX_FILE_SIZE_FULL = 200 * 1024 * 1024
MAX_STRINGS_SIZE = 512 * 1024
BATCH_SIZE = 500


class ScanResult:
    def __init__(self):
        self.threats = []
        self.scanned = 0
        self.time_taken = 0.0
        self.errors = 0
        self.skipped = 0

    def add_threat(self, filepath, threat_type, severity, detail):
        self.threats.append({
            'file': filepath, 'type': threat_type,
            'severity': severity, 'detail': detail
        })

    @property
    def critical_count(self):
        return sum(1 for t in self.threats if t['severity'] == 'critical')

    @property
    def high_count(self):
        return sum(1 for t in self.threats if t['severity'] == 'high')

    @property
    def medium_count(self):
        return sum(1 for t in self.threats if t['severity'] == 'medium')

    @property
    def low_count(self):
        return sum(1 for t in self.threats if t['severity'] == 'low')


class Scanner:
    def __init__(self, threads=2):
        self.threads = max(1, min(threads, os.cpu_count() or 2))
        self.hidden_detector = HiddenMalwareDetector()
        self.rules = load_heuristic_rules()
        self.rat_detector = RATDetector()
        self.network_scanner = NetworkScanner()
        self.persistence_analyzer = PersistenceAnalyzer()
        self.memory_scanner = MemoryScanner()

    def scan_file(self, filepath, quick=False):
        findings = []
        if not os.path.exists(filepath):
            return findings
        try:
            size = os.path.getsize(filepath)
            if size == 0:
                return findings
            max_size = MAX_FILE_SIZE_QUICK if quick else MAX_FILE_SIZE_FULL
            if size > max_size:
                return findings

            sig_match = match_signature(filepath)
            if sig_match:
                findings.append({
                    'file': filepath, 'type': 'signature',
                    'severity': 'critical',
                    'detail': f"Signature match: {sig_match}"
                })
                return findings

            ext = os.path.splitext(filepath)[1].lower()
            if ext not in SUSPICIOUS_EXTENSIONS:
                return findings

            if is_pe_file(filepath) and size < 50 * 1024 * 1024:
                pe = PEParser(filepath)
                if pe.valid:
                    sus_sec = pe.suspicious_sections()
                    if sus_sec:
                        findings.append({
                            'file': filepath, 'type': 'packed_section',
                            'severity': 'high',
                            'detail': f"Suspicious: {sus_sec[0]['name']}"})
                    sus_imp = pe.suspicious_imports()
                    if sus_imp:
                        findings.append({
                            'file': filepath, 'type': 'suspicious_imports',
                            'severity': 'high',
                            'detail': f"Imports: {', '.join(sus_imp[:3])}"})
                    if pe.has_anomalous_entry():
                        findings.append({
                            'file': filepath, 'type': 'anomalous_entry',
                            'severity': 'critical',
                            'detail': "Entry point outside code section"})

            if not quick:
                findings.extend(self.rat_detector.scan(filepath))

            if not quick and size > 0 and size < 10 * 1024 * 1024:
                ent = file_entropy(filepath)
                if ent > 7.5:
                    findings.append({
                        'file': filepath, 'type': 'high_entropy',
                        'severity': 'high',
                        'detail': f"High entropy ({ent:.2f}) - possible packed"})

            if not quick and size < MAX_STRINGS_SIZE:
                strings = read_strings(filepath)
                found = [s for s in strings if s in SUSPICIOUS_STRINGS]
                if found:
                    findings.append({
                        'file': filepath, 'type': 'suspicious_strings',
                        'severity': 'medium',
                        'detail': f"API strings: {', '.join(found[:5])}"})
                url_results = scan_text_for_urls('\n'.join(strings[:200]))
                for u in url_results:
                    if u['severity'] in ('critical', 'high'):
                        findings.append({
                            'file': filepath, 'type': 'malicious_url_embedded',
                            'severity': u['severity'], 'detail': u['detail']})
        except (PermissionError, FileNotFoundError):
            pass
        except Exception:
            pass
        return findings

    def scan_path(self, path, quick=False, recursive=True, callback=None):
        result = ScanResult()
        start = time.time()
        files = []
        try:
            if os.path.isfile(path):
                files = [path]
            elif recursive:
                for root, _, filenames in os.walk(path):
                    for fn in filenames:
                        ext = os.path.splitext(fn)[1].lower()
                        if ext in SUSPICIOUS_EXTENSIONS:
                            fp = os.path.join(root, fn)
                            try:
                                sz = os.path.getsize(fp)
                                limit = MAX_FILE_SIZE_QUICK if quick else MAX_FILE_SIZE_FULL
                                if sz <= limit:
                                    files.append(fp)
                                else:
                                    result.skipped += 1
                            except OSError:
                                result.errors += 1
            else:
                with os.scandir(path) as it:
                    for entry in it:
                        if entry.is_file():
                            ext = os.path.splitext(entry.name)[1].lower()
                            if ext in SUSPICIOUS_EXTENSIONS:
                                limit = MAX_FILE_SIZE_QUICK if quick else MAX_FILE_SIZE_FULL
                                if entry.stat().st_size <= limit:
                                    files.append(entry.path)
                                else:
                                    result.skipped += 1
        except PermissionError:
            result.errors += 1

        total = len(files)
        scanned = 0
        for i in range(0, total, BATCH_SIZE):
            batch = files[i:i + BATCH_SIZE]
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                fut_map = {executor.submit(self.scan_file, fp, quick): fp for fp in batch}
                for fut in as_completed(fut_map):
                    scanned += 1
                    result.scanned += 1
                    try:
                        for f in fut.result():
                            result.add_threat(f['file'], f['type'], f['severity'], f['detail'])
                    except Exception:
                        result.errors += 1
                    if callback:
                        progress = int(scanned / total * 100) if total else 100
                        if not callback(progress, result):
                            result.time_taken = time.time() - start
                            return result

        result.time_taken = time.time() - start
        return result

    def scan_system(self):
        findings = []
        findings.extend(self.persistence_analyzer.scan_all())
        findings.extend(self.network_scanner.scan_connections())
        findings.extend(self.memory_scanner.scan())
        return findings

    def scan_url(self, url):
        return scan_url(url)

    def scan_text(self, text):
        return scan_text_for_urls(text)

    def scan_hidden_malware(self, filepath=None, pid=None):
        return self.hidden_detector.run_all(filepath, pid)
