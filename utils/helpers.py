import hashlib
import os
import struct
import re
import math


def file_hash(filepath, algo='sha256', buffer=8192):
    h = hashlib.new(algo)
    try:
        with open(filepath, 'rb') as f:
            while chunk := f.read(buffer):
                h.update(chunk)
    except (PermissionError, FileNotFoundError):
        return None
    return h.hexdigest()


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    for c in counts:
        if c:
            p = c / len(data)
            ent -= p * math.log2(p)
    return ent


def file_entropy(filepath, buffer=4096):
    try:
        with open(filepath, 'rb') as f:
            data = f.read(min(buffer, os.path.getsize(filepath)))
        return entropy(data)
    except (PermissionError, FileNotFoundError, OSError):
        return 0.0


def read_strings(filepath, min_length=4, max_size=524288):
    strings = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read(max_size)
        current = []
        for b in data:
            if 32 <= b <= 126:
                current.append(chr(b))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        if len(current) >= min_length:
            strings.append(''.join(current))
    except (PermissionError, FileNotFoundError):
        pass
    return strings


def is_pe_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            magic = f.read(2)
            if magic != b'MZ':
                return False
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]
            f.seek(pe_offset)
            return f.read(4) == b'PE\x00\x00'
    except Exception:
        return False


def human_size(size):
    for unit in ('B', 'KB', 'MB', 'GB'):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
