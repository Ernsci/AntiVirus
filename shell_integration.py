import os
import sys
import winreg
import ctypes


BASE_KEY = r'*\shell\PyShieldAV'
ROOT = winreg.HKEY_CURRENT_USER
ROOT_PATH = r'Software\Classes'


def _refresh_shell():
    try:
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
    except Exception:
        pass


def _full_path(*parts):
    return '\\'.join(str(p) for p in parts)


def _get_command(flags=''):
    script = os.path.join(os.path.dirname(__file__), 'gui.py')
    if script.endswith('.py'):
        cmd = f'"{sys.executable}" "{script}" {flags} "%1"'
    else:
        cmd = f'"{script}" {flags} "%1"'
    return cmd.strip()


def register():
    try:
        base = _full_path(ROOT_PATH, BASE_KEY)
        quick_key = _full_path(base, 'shell', '01_quick')
        hard_key = _full_path(base, 'shell', '02_hard')

        with winreg.CreateKey(ROOT, base) as k:
            winreg.SetValueEx(k, 'MUIVerb', 0, winreg.REG_SZ, 'PyShield Antivirus')
            winreg.SetValueEx(k, 'SubCommands', 0, winreg.REG_SZ, '')
            winreg.SetValueEx(k, 'Icon', 0, winreg.REG_SZ,
                              os.path.join(os.path.dirname(sys.executable), 'python.exe'))

        with winreg.CreateKey(ROOT, quick_key) as k:
            winreg.SetValueEx(k, 'MUIVerb', 0, winreg.REG_SZ, 'Quick Scan')
            winreg.SetValueEx(k, 'CommandFlags', 0, winreg.REG_DWORD, 0x20)

        with winreg.CreateKey(ROOT, _full_path(quick_key, 'command')) as k:
            winreg.SetValueEx(k, '', 0, winreg.REG_SZ, _get_command('--quick'))

        with winreg.CreateKey(ROOT, hard_key) as k:
            winreg.SetValueEx(k, 'MUIVerb', 0, winreg.REG_SZ, 'Hard Scan')
            winreg.SetValueEx(k, 'CommandFlags', 0, winreg.REG_DWORD, 0x20)

        with winreg.CreateKey(ROOT, _full_path(hard_key, 'command')) as k:
            winreg.SetValueEx(k, '', 0, winreg.REG_SZ, _get_command('--hard'))

        _refresh_shell()
        return True, 'Shell extension registered (HKCU, no admin needed)'
    except Exception as e:
        return False, f'Registration failed: {e}'


def unregister():
    try:
        base = _full_path(ROOT_PATH, BASE_KEY)
        keys = [
            _full_path(base, 'shell', '01_quick', 'command'),
            _full_path(base, 'shell', '01_quick'),
            _full_path(base, 'shell', '02_hard', 'command'),
            _full_path(base, 'shell', '02_hard'),
            _full_path(base, 'shell'),
            base,
        ]
        for k in reversed(keys):
            try:
                winreg.DeleteKey(ROOT, k)
            except FileNotFoundError:
                pass
            except PermissionError:
                return False, f'Could not delete {k} (permission denied)'
        _refresh_shell()
        return True, 'Shell extension removed'
    except Exception as e:
        return False, f'Unregistration failed: {e}'


def is_registered():
    try:
        with winreg.OpenKey(ROOT, _full_path(ROOT_PATH, BASE_KEY), 0, winreg.KEY_READ):
            return True
    except FileNotFoundError:
        return False
    except Exception:
        return False


def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} [register|unregister|status]')
        return
    cmd = sys.argv[1].lower()
    if cmd == 'register':
        ok, msg = register()
        print(msg)
        if not ok:
            sys.exit(1)
    elif cmd == 'unregister':
        ok, msg = unregister()
        print(msg)
    elif cmd == 'status':
        print('Registered' if is_registered() else 'Not registered')
    else:
        print(f'Unknown: {cmd}')


if __name__ == '__main__':
    main()
