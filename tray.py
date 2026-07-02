import threading
import pystray
from PIL import Image, ImageDraw


def _create_icon():
    img = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rectangle([8, 8, 55, 55], fill=(122, 162, 247, 255))
    draw.polygon([(32, 14), (44, 24), (40, 38), (32, 44), (24, 38), (20, 24)], fill=(26, 27, 38, 255))
    return img


class TrayIcon:
    def __init__(self, gui):
        self.gui = gui
        self.icon = None
        self.thread = None

    def _build_menu(self):
        return pystray.Menu(
            pystray.MenuItem('Open PyShield', self._on_open, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Quick Scan', self._on_quick_scan),
            pystray.MenuItem('Hard Scan', self._on_hard_scan),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem('Quit', self._on_quit),
        )

    def _on_open(self):
        self.gui.root.after(0, self.gui._show_window)

    def _on_quick_scan(self):
        self.gui.root.after(0, lambda: self.gui._select_and_scan(quick=True))

    def _on_hard_scan(self):
        self.gui.root.after(0, lambda: self.gui._select_and_scan(quick=False))

    def _on_quit(self):
        self.gui.root.after(0, self.gui._quit_app)

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        img = _create_icon()
        self.icon = pystray.Icon('pyshield', img, 'PyShield Antivirus', self._build_menu())
        self.icon.run()

    def stop(self):
        if self.icon:
            self.icon.stop()
