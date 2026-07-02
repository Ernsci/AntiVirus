import os
import sys


def _is_frozen():
    return getattr(sys, 'frozen', False)


def _meipass():
    return getattr(sys, '_MEIPASS', None)


def app_data_dir():
    base = os.environ.get('APPDATA', os.path.expanduser('~'))
    d = os.path.join(base, 'PyShieldAV')
    os.makedirs(d, exist_ok=True)
    return d


def bundled_data_dir():
    if _is_frozen():
        meip = _meipass()
        if meip:
            return os.path.join(meip, 'data')
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')


def quarantine_dir():
    d = os.path.join(app_data_dir(), 'quarantine')
    os.makedirs(d, exist_ok=True)
    return d


def signatures_path():
    return os.path.join(bundled_data_dir(), 'signatures.json')


def heuristic_path():
    return os.path.join(bundled_data_dir(), 'heuristic_rules.json')


def patterns_path():
    return os.path.join(bundled_data_dir(), 'malicious_patterns.json')


def phishing_path():
    return os.path.join(bundled_data_dir(), 'phishing_domains.txt')
