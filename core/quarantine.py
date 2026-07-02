import os
import json
import shutil
from datetime import datetime
from utils.paths import quarantine_dir as _quarantine_dir


QUARANTINE_DIR = _quarantine_dir()
MANIFEST_FILE = os.path.join(QUARANTINE_DIR, 'manifest.json')


def _load_manifest():
    if not os.path.exists(MANIFEST_FILE):
        return []
    with open(MANIFEST_FILE, 'r') as f:
        return json.load(f)


def _save_manifest(manifest):
    with open(MANIFEST_FILE, 'w') as f:
        json.dump(manifest, f, indent=2)


def quarantine_file(filepath, threat_type='unknown'):
    if not os.path.exists(filepath):
        return False, "File not found"
    manifest = _load_manifest()
    entry_id = f"QT{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
    dest = os.path.join(QUARANTINE_DIR, entry_id + '_' + os.path.basename(filepath))
    try:
        shutil.copy2(filepath, dest)
        entry = {
            'id': entry_id,
            'original_path': os.path.abspath(filepath),
            'quarantine_path': dest,
            'threat_type': threat_type,
            'timestamp': datetime.now().isoformat()
        }
        manifest.append(entry)
        _save_manifest(manifest)
        try:
            os.remove(filepath)
        except Exception:
            pass
        return True, entry_id
    except Exception as e:
        return False, str(e)


def restore_file(entry_id):
    manifest = _load_manifest()
    for entry in manifest:
        if entry['id'] == entry_id:
            src = entry['quarantine_path']
            dst = entry['original_path']
            if not os.path.exists(src):
                return False, "Quarantined file no longer exists"
            try:
                shutil.copy2(src, dst)
                manifest.remove(entry)
                _save_manifest(manifest)
                os.remove(src)
                return True, dst
            except Exception as e:
                return False, str(e)
    return False, "Entry not found"


def delete_quarantined(entry_id=None):
    manifest = _load_manifest()
    if entry_id:
        for entry in list(manifest):
            if entry['id'] == entry_id:
                qpath = entry['quarantine_path']
                if os.path.exists(qpath):
                    os.remove(qpath)
                manifest.remove(entry)
                _save_manifest(manifest)
                return True
        return False
    else:
        for entry in manifest:
            if os.path.exists(entry['quarantine_path']):
                try:
                    os.remove(entry['quarantine_path'])
                except Exception:
                    pass
        _save_manifest([])
        return True


def list_quarantine():
    return _load_manifest()
