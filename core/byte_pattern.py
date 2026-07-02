import os
import re


class BytePatternMatcher:
    def __init__(self):
        self._cache = {}

    def find_bytes(self, filepath, pattern):
        if isinstance(pattern, str):
            pattern = pattern.encode('latin-1')
        try:
            if filepath in self._cache:
                data = self._cache[filepath]
            else:
                with open(filepath, 'rb') as f:
                    data = f.read(min(1024 * 1024, os.path.getsize(filepath)))
                self._cache[filepath] = data
            return pattern in data if isinstance(pattern, bytes) else bool(re.search(pattern, data))
        except Exception:
            return False

    def find_string(self, filepath, s):
        try:
            with open(filepath, 'rb') as f:
                data = f.read(min(512 * 1024, os.path.getsize(filepath)))
            return s.encode('utf-8', errors='replace') in data or s.encode('latin-1') in data
        except Exception:
            return False

    def find_strings(self, filepath, strings):
        try:
            with open(filepath, 'rb') as f:
                data = f.read(min(512 * 1024, os.path.getsize(filepath)))
            found = []
            for s in strings:
                if s.encode('utf-8', errors='replace') in data or s.encode('latin-1') in data:
                    found.append(s)
            return found
        except Exception:
            return []

    def find_any_pattern(self, filepath, patterns):
        try:
            with open(filepath, 'rb') as f:
                data = f.read(min(512 * 1024, os.path.getsize(filepath)))
            for p in patterns:
                if isinstance(p, bytes):
                    if p in data:
                        return True
                elif isinstance(p, re.Pattern):
                    if p.search(data):
                        return True
                elif isinstance(p, str):
                    if p.encode('utf-8', errors='replace') in data:
                        return True
            return False
        except Exception:
            return False

    def clear_cache(self):
        self._cache.clear()
