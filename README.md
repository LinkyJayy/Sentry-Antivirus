# 🛡️ Sentry Antivirus

Sentry is a Python-based antivirus solution that provides comprehensive protection for your system with real-time monitoring, on-demand scanning, and quarantine capabilities.

## Features

- **Real-time Protection**: Monitors file system changes and scans new/modified files automatically
- **Quick Scan**: Rapidly scans common threat locations
- **Full Scan**: Comprehensive system-wide scanning
- **Custom Scan**: Scan specific files or folders
- **Quarantine System**: Safely isolate detected threats
- **Threat Database**: Signature-based and heuristic detection
- **Modern UI**: Clean, intuitive interface inspired by Windows Security

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Launch GUI Application
```bash
python main.py
```

### Command Line Interface
```bash
# Quick scan
python main.py --quick-scan

# Full scan
python main.py --full-scan

# Scan specific path
python main.py --scan "C:\path\to\scan"

# Update definitions
python main.py --update
```

## Project Structure

```
sentry/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── sentry/
│   ├── __init__.py
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── engine.py       # Core scanning engine
│   │   ├── signatures.py   # Virus signatures database
│   │   └── heuristics.py   # Heuristic analysis
│   ├── protection/
│   │   ├── __init__.py
│   │   └── realtime.py     # Real-time protection monitor
│   ├── quarantine/
│   │   ├── __init__.py
│   │   └── manager.py      # Quarantine management
│   ├── gui/
│   │   ├── __init__.py
│   │   ├── app.py          # Main GUI application
│   │   ├── dashboard.py    # Dashboard view
│   │   ├── scan_view.py    # Scan interface
│   │   └── settings_view.py # Settings interface
│   └── utils/
│       ├── __init__.py
│       ├── config.py       # Configuration management
│       └── logger.py       # Logging utilities
└── data/
    ├── signatures.yaml     # Threat signatures
    └── quarantine/         # Quarantined files storage
```

## Disclaimer

This is an educational project demonstrating antivirus concepts. For production use, consider established antivirus solutions with extensive threat databases and kernel-level protection.

## License

MIT License - See LICENSE file for details.
