import json
import os
from utils.helpers import file_hash
from utils.paths import signatures_path, heuristic_path


def load_signatures():
    p = signatures_path()
    if not os.path.exists(p):
        return {'sha256': [], 'sha1': [], 'md5': []}
    with open(p, 'r') as f:
        return json.load(f)


def load_heuristic_rules():
    p = heuristic_path()
    if not os.path.exists(p):
        return []
    with open(p, 'r') as f:
        return json.load(f)


def match_signature(filepath):
    sigs = load_signatures()
    for algo in ('md5', 'sha1', 'sha256'):
        h = file_hash(filepath, algo)
        if h and h in sigs.get(algo, []):
            return next(
                (s['name'] for s in sigs.get(algo, []) if not isinstance(sigs[algo], list)),
                f"Matched {algo}: {h[:16]}..."
            )
    return None


def known_malicious_hash(hash_value):
    sigs = load_signatures()
    for algo in ('md5', 'sha1', 'sha256'):
        if hash_value in sigs.get(algo, []):
            return True
    return False
