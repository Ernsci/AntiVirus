# PyShieldAV — Python Antivirus Engine

PyShieldAV is a lightweight antivirus and security scanner for Windows built entirely in Python. It provides both a graphical interface and a command-line tool for detecting malware, monitoring system threats, and managing quarantined files.

## Features

- **File Scanner** — Signature-based and heuristic detection with multi-threaded scanning
- **URL Scanner** — Check URLs against phishing domains and malicious patterns
- **Process Monitor** — Real-time monitoring of running processes for suspicious behavior
- **RAT Detector** — Identify Remote Access Trojan indicators
- **Memory Scanner** — Scan process memory for known malicious patterns
- **Network Scanner** — Detect anomalous network connections
- **Hidden Malware Detector** — Analyze files for obfuscation, packing, and stealth techniques
- **Persistence Analyzer** — Check startup entries, scheduled tasks, and service hooks
- **PE Parser** — Deep inspection of Portable Executable headers and sections
- **Quarantine Manager** — Isolate, restore, or delete threats with a managed quarantine
- **Windows Shell Integration** — Right-click context menu for quick file scanning
- **System Tray** — Background operation with quick-scan access from the tray icon
- **Startup Manager** — Enable/disable autostart with Windows
- **Standalone Build** — Build a portable `.exe` via PyInstaller

## Installation

```bash
# Clone and run directly
git clone https://github.com/Ernsci/AntiVirus.git
cd AntiVirus
pip install -r requirements.txt
python antivirus.py --help

# Or build a standalone executable
python build.py
```

## Usage

### CLI

```
scan <path> [--quick]     Scan file or directory
quick <path>              Quick scan (skip heuristics)
url <url>                 Scan URL(s)
gui                       Launch graphical interface
monitor [interval]        Monitor running processes
processes                 Scan current processes
system                    Full system scan (RAT, persistence, network)
hidden [file]             Check for hidden malware
quarantine list           List quarantined files
quarantine restore <id>   Restore file from quarantine
quarantine delete <id>    Delete quarantined file
quarantine purge          Delete all quarantined files
shell [register|unreg]    Manage right-click context menu
startup [off]             Enable/disable Windows startup
build                     Build standalone .exe with PyInstaller
info                      Show scanner info
```

### GUI

```bash
python antivirus.py gui
```

The GUI offers scan controls, a results table with severity coloring, quarantine management, and a settings panel — all in a dark-themed interface.

## Project Structure

```
├── antivirus.py           Main CLI entry point
├── gui.py                 Tkinter graphical interface
├── tray.py                System tray icon (pystray)
├── shell_integration.py   Windows context menu registration
├── build.py               PyInstaller build script
├── core/
│   ├── scanner.py         File scanning engine
│   ├── signatures.py      Signature and heuristic rule loading
│   ├── pe_parser.py       PE header parser
│   ├── process_monitor.py Process monitoring
│   ├── quarantine.py      Quarantine management
│   ├── url_scanner.py     URL threat scanning
│   ├── rat_detector.py    RAT detection
│   ├── memory_scanner.py  Memory pattern scanning
│   ├── network_scanner.py Network connection analysis
│   ├── hidden_detector.py Hidden/obfuscated malware detection
│   ├── persistence_analyzer.py Persistence mechanism analysis
│   └── byte_pattern.py    Byte-level pattern matching
├── data/
│   ├── signatures.json         Malware signature database
│   ├── heuristic_rules.json    Heuristic detection rules
│   ├── malicious_patterns.json Malicious behavior patterns
│   ├── rat_signatures.json     RAT-specific signatures
│   ├── phishing_domains.txt    Phishing domain blacklist
│   └── quarantine/             Isolated threat storage
├── utils/
│   ├── helpers.py          Hashing, entropy, string extraction
│   └── paths.py            Application path resolution
└── dist/                   Standalone builds
```

## Requirements

- Python 3.8+
- Windows 10/11
- Dependencies: `pystray`, `Pillow`, `requests`

## License

MIT
