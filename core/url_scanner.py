import re
import json
import os
from urllib.parse import urlparse
from utils.paths import phishing_path, patterns_path


SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                   '.club', '.work', '.bid', '.download', '.review',
                   '.date', '.men', '.loan', '.click'}
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'account', 'banking',
                       'update', 'confirm', 'password', 'credential',
                       'signin', 'webmail', '2fa', 'mfa', 'authenticator',
                       'wallet', 'coinbase', 'blockchain', 'metamask']
IP_PATTERN = re.compile(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
HEX_IP = re.compile(r'^https?://0x[0-9a-fA-F]+')


def load_phishing_domains():
    p = phishing_path()
    if not os.path.exists(p):
        return set()
    with open(p, 'r') as f:
        return {line.strip().lower() for line in f if line.strip() and not line.startswith('#')}


def load_malicious_patterns():
    p = patterns_path()
    if not os.path.exists(p):
        return []
    with open(p, 'r') as f:
        return json.load(f)


def scan_url(url):
    results = []
    if not url.startswith(('http://', 'https://', 'ftp://')):
        return [{'type': 'invalid_url', 'detail': f"Not a valid URL: {url[:50]}",
                 'severity': 'low', 'url': url}]

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full_url = url.lower()

    if IP_PATTERN.match(url):
        results.append({'type': 'ip_url', 'detail': f"URL uses raw IP: {domain}",
                        'severity': 'medium', 'url': url})
    if HEX_IP.match(url):
        results.append({'type': 'hex_ip', 'detail': f"URL uses hex-encoded IP",
                        'severity': 'high', 'url': url})
    if parsed.port and parsed.port not in (80, 443):
        results.append({'type': 'nonstandard_port',
                        'detail': f"Non-standard port: {parsed.port}",
                        'severity': 'medium', 'url': url})

    phishing_domains = load_phishing_domains()
    if domain in phishing_domains:
        results.append({'type': 'phishing_domain', 'detail': f"Known phishing domain: {domain}",
                        'severity': 'critical', 'url': url})

    tld = '.' + domain.split('.')[-1] if '.' in domain else ''
    if tld in SUSPICIOUS_TLDS:
        results.append({'type': 'suspicious_tld',
                        'detail': f"Suspicious TLD: {tld}",
                        'severity': 'medium', 'url': url})

    path_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    if path_keywords:
        results.append({'type': 'phishing_keywords',
                        'detail': f"Phishing keywords: {', '.join(path_keywords)}",
                        'severity': 'high', 'url': url})

    patterns = load_malicious_patterns()
    for p in patterns:
        try:
            if re.search(p['pattern'], url, re.I):
                results.append({'type': 'malicious_pattern',
                                'detail': p.get('description', 'Matched malicious pattern'),
                                'severity': p.get('severity', 'high'), 'url': url})
        except re.error:
            pass

    return results


def scan_text_for_urls(text):
    url_pattern = re.compile(r'https?://[^\s<>"\'{}|\\^`]+')
    urls = url_pattern.findall(text)
    all_results = []
    for url in urls[:50]:
        all_results.extend(scan_url(url))
    return all_results
