"""
Sentry Antivirus - Settings View
Always protects your computer!
"""

import customtkinter as ctk
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import SentryApp
    from ..utils.config import Config
    from ..protection.realtime import RealtimeProtection


class SettingsView(ctk.CTkFrame):
    """Settings and configuration view"""

    def __init__(self, parent, app: 'SentryApp', config: 'Config',
                 realtime_protection: 'RealtimeProtection'):
        super().__init__(parent, fg_color="transparent")
        
        self.app = app
        self.config = config
        self.realtime_protection = realtime_protection

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._create_widgets()

    def _create_widgets(self):
        """Create settings view widgets"""
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))

        title = ctk.CTkLabel(
            header,
            text="Settings",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            header,
            text="Configure Sentry protection settings",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle.pack(anchor="w")

        # Settings content
        content = ctk.CTkScrollableFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew")

        # Protection Settings
        self._create_section(content, "Protection Settings", [
            self._create_protection_settings
        ])

        # Scan Settings
        self._create_section(content, "Scan Settings", [
            self._create_scan_settings
        ])

        # Appearance Settings
        self._create_section(content, "Appearance", [
            self._create_appearance_settings
        ])

        # About Section
        self._create_section(content, "About", [
            self._create_about_section
        ])

    def _create_section(self, parent, title: str, content_builders: list):
        """Create a settings section"""
        section = ctk.CTkFrame(parent, corner_radius=15)
        section.pack(fill="x", pady=(0, 15))

        # Section title
        title_label = ctk.CTkLabel(
            section,
            text=title,
            font=ctk.CTkFont(size=16, weight="bold")
        )
        title_label.pack(anchor="w", padx=20, pady=(20, 15))

        # Section content
        for builder in content_builders:
            builder(section)

    def _create_protection_settings(self, parent):
        """Create protection settings"""
        # Real-time protection
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=5)

        label = ctk.CTkLabel(
            row,
            text="Real-time Protection",
            font=ctk.CTkFont(size=13)
        )
        label.pack(side="left")

        self.realtime_switch = ctk.CTkSwitch(
            row,
            text="",
            command=self._toggle_realtime,
            onvalue=True,
            offvalue=False
        )
        self.realtime_switch.pack(side="right")
        
        if self.config.get("realtime_protection_enabled", True):
            self.realtime_switch.select()

        desc = ctk.CTkLabel(
            parent,
            text="Monitor file system for new threats automatically",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        desc.pack(anchor="w", padx=20, pady=(0, 10))

        # Auto quarantine
        row2 = ctk.CTkFrame(parent, fg_color="transparent")
        row2.pack(fill="x", padx=20, pady=5)

        label2 = ctk.CTkLabel(
            row2,
            text="Auto Quarantine",
            font=ctk.CTkFont(size=13)
        )
        label2.pack(side="left")

        self.auto_quarantine_switch = ctk.CTkSwitch(
            row2,
            text="",
            command=self._toggle_auto_quarantine,
            onvalue=True,
            offvalue=False
        )
        self.auto_quarantine_switch.pack(side="right")
        
        if self.config.get("auto_quarantine", False):
            self.auto_quarantine_switch.select()

        desc2 = ctk.CTkLabel(
            parent,
            text="Automatically quarantine detected threats",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        desc2.pack(anchor="w", padx=20, pady=(0, 20))

    def _create_scan_settings(self, parent):
        """Create scan settings"""
        # Scan threads
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=5)

        label = ctk.CTkLabel(
            row,
            text="Scan Threads",
            font=ctk.CTkFont(size=13)
        )
        label.pack(side="left")

        self.threads_var = ctk.StringVar(value=str(self.config.get("scan_threads", 4)))
        threads_dropdown = ctk.CTkComboBox(
            row,
            values=["1", "2", "4", "8"],
            variable=self.threads_var,
            width=80,
            command=self._on_threads_change
        )
        threads_dropdown.pack(side="right")

        desc = ctk.CTkLabel(
            parent,
            text="Number of parallel threads for scanning (higher = faster but uses more resources)",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        desc.pack(anchor="w", padx=20, pady=(0, 10))

        # Heuristic sensitivity
        row2 = ctk.CTkFrame(parent, fg_color="transparent")
        row2.pack(fill="x", padx=20, pady=5)

        label2 = ctk.CTkLabel(
            row2,
            text="Heuristic Sensitivity",
            font=ctk.CTkFont(size=13)
        )
        label2.pack(side="left")

        self.sensitivity_var = ctk.StringVar(value=self.config.get("heuristic_sensitivity", "Medium"))
        sensitivity_dropdown = ctk.CTkComboBox(
            row2,
            values=["Low", "Medium", "High"],
            variable=self.sensitivity_var,
            width=100,
            command=self._on_sensitivity_change
        )
        sensitivity_dropdown.pack(side="right")

        desc2 = ctk.CTkLabel(
            parent,
            text="Higher sensitivity may detect more threats but could cause false positives",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        desc2.pack(anchor="w", padx=20, pady=(0, 20))

    def _create_appearance_settings(self, parent):
        """Create appearance settings"""
        # Theme
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=5)

        label = ctk.CTkLabel(
            row,
            text="Theme",
            font=ctk.CTkFont(size=13)
        )
        label.pack(side="left")

        self.theme_var = ctk.StringVar(value=self.config.get("appearance_mode", "dark").capitalize())
        theme_dropdown = ctk.CTkComboBox(
            row,
            values=["Light", "Dark", "System"],
            variable=self.theme_var,
            width=100,
            command=self._on_theme_change
        )
        theme_dropdown.pack(side="right")

        desc = ctk.CTkLabel(
            parent,
            text="Choose the application color theme",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        desc.pack(anchor="w", padx=20, pady=(0, 20))

    def _create_about_section(self, parent):
        """Create about section"""
        about_frame = ctk.CTkFrame(parent, fg_color="transparent")
        about_frame.pack(fill="x", padx=20, pady=(0, 20))

        # Logo
        logo = ctk.CTkLabel(
            about_frame,
            text="🛡️",
            font=ctk.CTkFont(size=48)
        )
        logo.pack(pady=(10, 5))

        name = ctk.CTkLabel(
            about_frame,
            text="Sentry Antivirus",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        name.pack()

        tagline = ctk.CTkLabel(
            about_frame,
            text="Always protects your computer!",
            font=ctk.CTkFont(size=13),
            text_color="gray"
        )
        tagline.pack()

        version = ctk.CTkLabel(
            about_frame,
            text="Version 1.0.0",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        version.pack(pady=(10, 0))

        # Signature info
        sig_count = self.app.scan_engine.signatures.get_signature_count()
        signatures = ctk.CTkLabel(
            about_frame,
            text=f"Loaded Signatures: {sig_count['total']}",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        signatures.pack(pady=(5, 10))

    def _toggle_realtime(self):
        """Toggle real-time protection"""
        enabled = self.realtime_switch.get()
        self.app.toggle_realtime_protection(enabled)
        self.config.set("realtime_protection_enabled", enabled)

    def _toggle_auto_quarantine(self):
        """Toggle auto quarantine"""
        enabled = self.auto_quarantine_switch.get()
        self.realtime_protection.set_auto_quarantine(enabled)
        self.config.set("auto_quarantine", enabled)

    def _on_threads_change(self, value):
        """Handle thread count change"""
        threads = int(value)
        self.app.scan_engine.max_workers = threads
        self.config.set("scan_threads", threads)

    def _on_sensitivity_change(self, value):
        """Handle sensitivity change"""
        thresholds = {
            "Low": 70,
            "Medium": 50,
            "High": 30
        }
        self.app.scan_engine.heuristics.set_threshold(thresholds.get(value, 50))
        self.config.set("heuristic_sensitivity", value)

    def _on_theme_change(self, value):
        """Handle theme change"""
        mode = value.lower()
        ctk.set_appearance_mode(mode)
        self.config.set("appearance_mode", mode)

    def refresh(self):
        """Refresh settings view"""
        pass
