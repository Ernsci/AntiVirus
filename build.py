import sys
import os
import shutil
import subprocess


APP_NAME = 'PyShieldAV'
DIST_DIR = os.path.join(os.path.dirname(__file__), 'dist')
BUILD_DIR = os.path.join(os.path.dirname(__file__), 'build')


def clean():
    for d in [DIST_DIR, BUILD_DIR]:
        if os.path.exists(d):
            shutil.rmtree(d)
    spec = os.path.join(os.path.dirname(__file__), f'{APP_NAME}.spec')
    if os.path.exists(spec):
        os.remove(spec)


def build():
    script = os.path.join(os.path.dirname(__file__), 'gui.py')
    if not os.path.exists(script):
        print(f'Error: {script} not found')
        sys.exit(1)

    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    pyinstaller_args = [
        sys.executable, '-m', 'PyInstaller',
        '--noconfirm',
        '--windowed',
        '--onefile',
        '--name', APP_NAME,
        '--icon', 'NONE',
        '--add-data', f'{data_dir}{os.pathsep}data',
        '--hidden-import', 'pystray',
        '--hidden-import', 'PIL',
        '--hidden-import', 'PIL._tkinter_finder',
        '--hidden-import', 'winreg',
        '--hidden-import', 'core.scanner',
        '--hidden-import', 'core.quarantine',
        '--hidden-import', 'core.signatures',
        '--hidden-import', 'core.pe_parser',
        '--hidden-import', 'core.hidden_detector',
        '--hidden-import', 'core.url_scanner',
        '--hidden-import', 'core.process_monitor',
        '--hidden-import', 'core.rat_detector',
        '--hidden-import', 'core.byte_pattern',
        '--hidden-import', 'core.network_scanner',
        '--hidden-import', 'core.persistence_analyzer',
        '--hidden-import', 'core.memory_scanner',
        '--hidden-import', 'utils.helpers',
        '--hidden-import', 'utils.paths',
        '--hidden-import', 'shell_integration',
        '--hidden-import', 'tray',
        '--collect-all', 'core',
        '--collect-all', 'utils',
        '--collect-all', 'data',
        script,
    ]

    print(f'Building {APP_NAME}.exe with PyInstaller...\n')
    print(f'Source: {script}')
    print(f'Output: {os.path.join(DIST_DIR, f"{APP_NAME}.exe")}\n')

    result = subprocess.run(pyinstaller_args, cwd=os.path.dirname(__file__))

    if result.returncode == 0:
        exe_path = os.path.join(DIST_DIR, f'{APP_NAME}.exe')
        data_dest = os.path.join(DIST_DIR, 'data')
        if os.path.exists(exe_path):
            print(f'\nSuccess! Built: {exe_path}')
            print(f'Size: {os.path.getsize(exe_path) / 1024 / 1024:.1f} MB')
        if os.path.exists(data_dest):
            shutil.rmtree(data_dest)
        print(f'\nTo distribute: copy {APP_NAME}.exe to any location.')
        print('Run it once to register startup (Settings > Startup).')
    else:
        print('\nBuild failed')
        sys.exit(1)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'clean':
        clean()
    else:
        build()


if __name__ == '__main__':
    main()
