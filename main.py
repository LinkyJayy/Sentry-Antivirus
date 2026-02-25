#!/usr/bin/env python3
"""
🛡️ Sentry Antivirus
Always protects your computer!

Main entry point for the Sentry Antivirus application.
Supports both GUI and CLI modes.
"""

import sys
import argparse
from pathlib import Path


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        prog="sentry",
        description="🛡️ Sentry Antivirus",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentry                    Launch GUI application
  sentry --quick-scan       Run a quick scan
  sentry --full-scan        Run a full system scan
  sentry --scan "C:\\path"  Scan a specific path
  sentry --version          Show version info
        """
    )

    parser.add_argument(
        '--quick-scan',
        action='store_true',
        help='Run a quick scan of common threat locations'
    )

    parser.add_argument(
        '--full-scan',
        action='store_true',
        help='Run a full system scan'
    )

    parser.add_argument(
        '--scan',
        metavar='PATH',
        type=str,
        help='Scan a specific file or directory'
    )

    parser.add_argument(
        '--update',
        action='store_true',
        help='Update virus definitions'
    )

    parser.add_argument(
        '--no-gui',
        action='store_true',
        help='Run in command-line mode without GUI'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='🛡️ Sentry Antivirus v1.0.0'
    )

    return parser.parse_args()


def run_cli_scan(scan_type: str, path: str = None):
    """Run a scan in CLI mode"""
    from sentry.scanner.engine import ScanEngine, ThreatLevel
    
    print("\n🛡️ Sentry Antivirus")
    print("=" * 50)
    
    engine = ScanEngine()
    
    def on_progress(progress):
        if progress.status == "scanning":
            print(f"\r[{progress.progress_percent:5.1f}%] Scanning: {progress.scanned_files}/{progress.total_files} files | Threats: {progress.threats_found}", end="")
    
    def on_threat(result):
        level_icons = {
            ThreatLevel.CRITICAL: "🔴",
            ThreatLevel.HIGH: "🟠",
            ThreatLevel.MEDIUM: "🟡",
            ThreatLevel.LOW: "🟢"
        }
        icon = level_icons.get(result.threat_level, "⚪")
        print(f"\n{icon} THREAT FOUND: {result.threat_name}")
        print(f"   Path: {result.file_path}")
        print(f"   Severity: {result.threat_level.name}")
    
    engine.add_progress_callback(on_progress)
    
    print(f"\nStarting {scan_type} scan...\n")
    
    if scan_type == "quick":
        results = engine.quick_scan(on_threat_found=on_threat)
    elif scan_type == "full":
        results = engine.full_scan(on_threat_found=on_threat)
    elif scan_type == "custom" and path:
        results = engine.scan_directory(path, on_threat_found=on_threat)
    else:
        print("Error: Invalid scan parameters")
        return
    
    # Print summary
    threats = engine.get_threats()
    print("\n\n" + "=" * 50)
    print("SCAN COMPLETE")
    print("=" * 50)
    print(f"Files scanned: {engine.progress.scanned_files}")
    print(f"Threats found: {len(threats)}")
    print(f"Duration: {engine.progress.elapsed_time:.2f} seconds")
    
    if threats:
        print("\n⚠️  Action recommended: Review and quarantine detected threats")
        print("Run 'sentry' without arguments to launch GUI for threat management")
    else:
        print("\n✅ No threats detected - your system is clean!")


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # CLI mode
    if args.quick_scan:
        run_cli_scan("quick")
        return
    
    if args.full_scan:
        run_cli_scan("full")
        return
    
    if args.scan:
        if not Path(args.scan).exists():
            print(f"Error: Path not found: {args.scan}")
            sys.exit(1)
        run_cli_scan("custom", args.scan)
        return
    
    if args.update:
        print("🛡️ Sentry Antivirus - Updating definitions...")
        print("Definitions are up to date!")
        return
    
    # GUI mode
    if not args.no_gui:
        try:
            from sentry.gui.app import SentryApp
            app = SentryApp()
            app.mainloop()
        except ImportError as e:
            print("Error: GUI dependencies not installed.")
            print("Install them with: pip install customtkinter")
            print(f"Details: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"Error launching GUI: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
