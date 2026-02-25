"""
Sentry Antivirus - Scan View
Always protects your computer!
"""

import os
import threading
import customtkinter as ctk
from tkinter import filedialog
from datetime import datetime
from typing import TYPE_CHECKING, Optional, List

if TYPE_CHECKING:
    from .app import SentryApp
    from ..scanner.engine import ScanEngine, ScanResult, ScanProgress
    from ..quarantine.manager import QuarantineManager


class ScanView(ctk.CTkFrame):
    """Scan interface for running virus scans"""

    def __init__(self, parent, app: 'SentryApp', scan_engine: 'ScanEngine',
                 quarantine_manager: 'QuarantineManager'):
        super().__init__(parent, fg_color="transparent")
        
        self.app = app
        self.scan_engine = scan_engine
        self.quarantine_manager = quarantine_manager
        self._scan_thread: Optional[threading.Thread] = None
        self._is_scanning = False
        self._threats_found: List['ScanResult'] = []

        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._create_widgets()
        
        # Add progress callback
        self.scan_engine.add_progress_callback(self._on_progress_update)

    def _create_widgets(self):
        """Create scan view widgets"""
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))

        title = ctk.CTkLabel(
            header,
            text="Virus & Threat Scan",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            header,
            text="Scan your system for malware and threats",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle.pack(anchor="w")

        # Scan options
        self._create_scan_options()

        # Progress section
        self._create_progress_section()

        # Results section
        self._create_results_section()

    def _create_scan_options(self):
        """Create scan option buttons"""
        options_frame = ctk.CTkFrame(self, fg_color="transparent")
        options_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        options_frame.grid_columnconfigure((0, 1, 2), weight=1)

        # Quick Scan
        quick_frame = ctk.CTkFrame(options_frame, corner_radius=15)
        quick_frame.grid(row=0, column=0, padx=(0, 10), sticky="nsew")

        quick_icon = ctk.CTkLabel(quick_frame, text="⚡", font=ctk.CTkFont(size=36))
        quick_icon.pack(pady=(20, 10))

        quick_title = ctk.CTkLabel(
            quick_frame,
            text="Quick Scan",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        quick_title.pack()

        quick_desc = ctk.CTkLabel(
            quick_frame,
            text="Scans common threat locations\nFast and efficient",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        quick_desc.pack(pady=5)

        self.quick_scan_btn = ctk.CTkButton(
            quick_frame,
            text="Start Quick Scan",
            font=ctk.CTkFont(size=13),
            corner_radius=8,
            command=self.start_quick_scan
        )
        self.quick_scan_btn.pack(padx=20, pady=(10, 20))

        # Full Scan
        full_frame = ctk.CTkFrame(options_frame, corner_radius=15)
        full_frame.grid(row=0, column=1, padx=10, sticky="nsew")

        full_icon = ctk.CTkLabel(full_frame, text="🔍", font=ctk.CTkFont(size=36))
        full_icon.pack(pady=(20, 10))

        full_title = ctk.CTkLabel(
            full_frame,
            text="Full Scan",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        full_title.pack()

        full_desc = ctk.CTkLabel(
            full_frame,
            text="Comprehensive system scan\nTakes longer but thorough",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        full_desc.pack(pady=5)

        self.full_scan_btn = ctk.CTkButton(
            full_frame,
            text="Start Full Scan",
            font=ctk.CTkFont(size=13),
            corner_radius=8,
            fg_color=("gray75", "gray25"),
            hover_color=("gray65", "gray35"),
            command=self.start_full_scan
        )
        self.full_scan_btn.pack(padx=20, pady=(10, 20))

        # Custom Scan
        custom_frame = ctk.CTkFrame(options_frame, corner_radius=15)
        custom_frame.grid(row=0, column=2, padx=(10, 0), sticky="nsew")

        custom_icon = ctk.CTkLabel(custom_frame, text="📁", font=ctk.CTkFont(size=36))
        custom_icon.pack(pady=(20, 10))

        custom_title = ctk.CTkLabel(
            custom_frame,
            text="Custom Scan",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        custom_title.pack()

        custom_desc = ctk.CTkLabel(
            custom_frame,
            text="Choose specific files or\nfolders to scan",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        custom_desc.pack(pady=5)

        self.custom_scan_btn = ctk.CTkButton(
            custom_frame,
            text="Select & Scan",
            font=ctk.CTkFont(size=13),
            corner_radius=8,
            fg_color=("gray75", "gray25"),
            hover_color=("gray65", "gray35"),
            command=self.start_custom_scan
        )
        self.custom_scan_btn.pack(padx=20, pady=(10, 20))

    def _create_progress_section(self):
        """Create scan progress section"""
        self.progress_frame = ctk.CTkFrame(self, corner_radius=15)
        self.progress_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        self.progress_frame.grid_columnconfigure(0, weight=1)

        # Progress header
        progress_header = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        progress_header.pack(fill="x", padx=20, pady=(20, 10))

        self.progress_status = ctk.CTkLabel(
            progress_header,
            text="Ready to scan",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        self.progress_status.pack(side="left")

        self.cancel_btn = ctk.CTkButton(
            progress_header,
            text="Cancel",
            font=ctk.CTkFont(size=12),
            width=80,
            height=30,
            fg_color="#FF4444",
            hover_color="#CC3333",
            command=self._cancel_scan
        )
        self.cancel_btn.pack(side="right")
        self.cancel_btn.pack_forget()  # Hide initially

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, height=20)
        self.progress_bar.pack(fill="x", padx=20, pady=10)
        self.progress_bar.set(0)

        # Progress details
        details_frame = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        details_frame.pack(fill="x", padx=20)

        self.scanned_label = ctk.CTkLabel(
            details_frame,
            text="Files scanned: 0",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.scanned_label.pack(side="left")

        self.threats_label = ctk.CTkLabel(
            details_frame,
            text="Threats found: 0",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.threats_label.pack(side="right")

        # Current file
        self.current_file_label = ctk.CTkLabel(
            self.progress_frame,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        self.current_file_label.pack(fill="x", padx=20, pady=(10, 20))

    def _create_results_section(self):
        """Create scan results section"""
        self.results_frame = ctk.CTkFrame(self, corner_radius=15)
        self.results_frame.grid(row=3, column=0, sticky="nsew")
        self.results_frame.grid_rowconfigure(1, weight=1)
        self.results_frame.grid_columnconfigure(0, weight=1)

        # Results header
        results_header = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        results_header.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        results_title = ctk.CTkLabel(
            results_header,
            text="Scan Results",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        results_title.pack(side="left")

        self.quarantine_all_btn = ctk.CTkButton(
            results_header,
            text="Quarantine All",
            font=ctk.CTkFont(size=12),
            width=120,
            height=30,
            fg_color="#FF4444",
            hover_color="#CC3333",
            command=self._quarantine_all_threats
        )
        self.quarantine_all_btn.pack(side="right")
        self.quarantine_all_btn.pack_forget()

        # Results list
        self.results_list = ctk.CTkScrollableFrame(
            self.results_frame,
            fg_color="transparent"
        )
        self.results_list.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

        # Initial message
        self.no_results_label = ctk.CTkLabel(
            self.results_list,
            text="No scan results yet. Start a scan to check for threats.",
            font=ctk.CTkFont(size=13),
            text_color="gray"
        )
        self.no_results_label.pack(pady=30)

    def _on_progress_update(self, progress: 'ScanProgress'):
        """Handle progress updates from scan engine"""
        # Use after() to update GUI from main thread
        self.after(0, lambda: self._update_progress_display(progress))

    def _update_progress_display(self, progress: 'ScanProgress'):
        """Update progress display"""
        if progress.status == "counting":
            self.progress_status.configure(text="Counting files...")
        elif progress.status == "scanning":
            self.progress_status.configure(text="Scanning...")
        elif progress.status == "completed":
            self.progress_status.configure(text="Scan completed")
            self._on_scan_complete()
        elif progress.status == "cancelled":
            self.progress_status.configure(text="Scan cancelled")
            self._on_scan_complete()
        elif progress.status == "paused":
            self.progress_status.configure(text="Scan paused")

        # Update progress bar
        self.progress_bar.set(progress.progress_percent / 100)

        # Update labels
        self.scanned_label.configure(
            text=f"Files scanned: {progress.scanned_files}/{progress.total_files}"
        )
        self.threats_label.configure(
            text=f"Threats found: {progress.threats_found}",
            text_color="#FF4444" if progress.threats_found > 0 else "gray"
        )

        # Update current file
        if progress.current_file:
            display_path = progress.current_file
            if len(display_path) > 70:
                display_path = "..." + display_path[-67:]
            self.current_file_label.configure(text=display_path)

    def _on_threat_found(self, result: 'ScanResult'):
        """Handle threat detection"""
        self._threats_found.append(result)
        self.after(0, lambda: self._add_threat_to_results(result))

    def _add_threat_to_results(self, result: 'ScanResult'):
        """Add a threat to the results list"""
        # Clear no results message
        if self.no_results_label.winfo_exists():
            self.no_results_label.destroy()

        # Show quarantine all button
        self.quarantine_all_btn.pack(side="right")

        # Create threat item
        frame = ctk.CTkFrame(self.results_list, corner_radius=10)
        frame.pack(fill="x", pady=3)

        # Threat icon
        level_colors = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FF4444",
            "MEDIUM": "#FFB800",
            "LOW": "#00D26A"
        }
        color = level_colors.get(result.threat_level.name, "gray")

        icon_label = ctk.CTkLabel(
            frame,
            text="⚠️",
            font=ctk.CTkFont(size=20)
        )
        icon_label.pack(side="left", padx=15, pady=15)

        # Threat info
        info_frame = ctk.CTkFrame(frame, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True, pady=10)

        name_label = ctk.CTkLabel(
            info_frame,
            text=result.threat_name or "Unknown Threat",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=color
        )
        name_label.pack(anchor="w")

        path_label = ctk.CTkLabel(
            info_frame,
            text=result.file_path,
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        path_label.pack(anchor="w")

        level_label = ctk.CTkLabel(
            info_frame,
            text=f"Severity: {result.threat_level.name}",
            font=ctk.CTkFont(size=11),
            text_color=color
        )
        level_label.pack(anchor="w")

        # Quarantine button
        quarantine_btn = ctk.CTkButton(
            frame,
            text="Quarantine",
            font=ctk.CTkFont(size=12),
            width=100,
            height=32,
            fg_color="#FF4444",
            hover_color="#CC3333",
            command=lambda r=result, f=frame: self._quarantine_single(r, f)
        )
        quarantine_btn.pack(side="right", padx=15)

    def _quarantine_single(self, result: 'ScanResult', frame: ctk.CTkFrame):
        """Quarantine a single threat"""
        if self.quarantine_manager.quarantine_file(result.file_path, result):
            frame.destroy()
            self._threats_found.remove(result)
            if not self._threats_found:
                self.quarantine_all_btn.pack_forget()
                self._show_no_threats_message()
            self.app.show_notification("Success", f"File quarantined: {result.file_path}")
        else:
            self.app.show_notification("Error", "Failed to quarantine file", "error")

    def _quarantine_all_threats(self):
        """Quarantine all detected threats"""
        success_count = 0
        for result in self._threats_found[:]:
            if self.quarantine_manager.quarantine_file(result.file_path, result):
                success_count += 1
        
        # Clear results
        for widget in self.results_list.winfo_children():
            widget.destroy()
        
        self._threats_found.clear()
        self.quarantine_all_btn.pack_forget()
        self._show_no_threats_message()
        
        self.app.show_notification(
            "Quarantine Complete",
            f"Successfully quarantined {success_count} threat(s)"
        )

    def _show_no_threats_message(self):
        """Show no threats message"""
        no_threats = ctk.CTkLabel(
            self.results_list,
            text="✓ No threats detected - your system is clean!",
            font=ctk.CTkFont(size=14),
            text_color="#00D26A"
        )
        no_threats.pack(pady=30)

    def _start_scan(self, scan_type: str, path: Optional[str] = None):
        """Start a scan"""
        if self._is_scanning:
            return

        self._is_scanning = True
        self._threats_found.clear()

        # Clear previous results
        for widget in self.results_list.winfo_children():
            widget.destroy()

        self.no_results_label = ctk.CTkLabel(
            self.results_list,
            text="Scanning...",
            font=ctk.CTkFont(size=13),
            text_color="gray"
        )
        self.no_results_label.pack(pady=30)

        # Show cancel button
        self.cancel_btn.pack(side="right")
        self.quarantine_all_btn.pack_forget()

        # Disable scan buttons
        self.quick_scan_btn.configure(state="disabled")
        self.full_scan_btn.configure(state="disabled")
        self.custom_scan_btn.configure(state="disabled")

        # Reset progress
        self.progress_bar.set(0)
        self.scanned_label.configure(text="Files scanned: 0")
        self.threats_label.configure(text="Threats found: 0", text_color="gray")

        def run_scan():
            if scan_type == "quick":
                self.scan_engine.quick_scan(on_threat_found=self._on_threat_found)
            elif scan_type == "full":
                self.scan_engine.full_scan(on_threat_found=self._on_threat_found)
            elif scan_type == "custom" and path:
                self.scan_engine.scan_directory(path, on_threat_found=self._on_threat_found)

        self._scan_thread = threading.Thread(target=run_scan, daemon=True)
        self._scan_thread.start()

    def _cancel_scan(self):
        """Cancel the current scan"""
        self.scan_engine.cancel()
        self.progress_status.configure(text="Cancelling...")

    def _on_scan_complete(self):
        """Handle scan completion"""
        self._is_scanning = False
        
        # Hide cancel button
        self.cancel_btn.pack_forget()

        # Enable scan buttons
        self.quick_scan_btn.configure(state="normal")
        self.full_scan_btn.configure(state="normal")
        self.custom_scan_btn.configure(state="normal")

        # Update results message if no threats
        if not self._threats_found:
            for widget in self.results_list.winfo_children():
                widget.destroy()
            self._show_no_threats_message()

    def start_quick_scan(self):
        """Start a quick scan"""
        self._start_scan("quick")

    def start_full_scan(self):
        """Start a full scan"""
        self._start_scan("full")

    def start_custom_scan(self):
        """Start a custom scan with file/folder selection"""
        path = filedialog.askdirectory(
            title="Select folder to scan",
            initialdir=os.path.expanduser("~")
        )
        if path:
            self._start_scan("custom", path)

    def refresh(self):
        """Refresh the view"""
        pass
