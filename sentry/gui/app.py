"""
Sentry Antivirus - Main GUI Application
Always protects your computer!
"""

import os
import sys
import threading
from pathlib import Path
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image
from typing import Optional

from .dashboard import DashboardView
from .scan_view import ScanView
from .settings_view import SettingsView
from .quarantine_view import QuarantineView
from .history_view import HistoryView

from ..scanner.engine import ScanEngine
from ..protection.realtime import RealtimeProtection, ProtectionStatus
from ..quarantine.manager import QuarantineManager
from ..utils.config import Config


class SentryApp(ctk.CTk):
    """
    Main Sentry Antivirus Application
    
    A modern, user-friendly antivirus interface
    """

    def __init__(self):
        super().__init__()

        # Initialize components
        self.config = Config()
        self.scan_engine = ScanEngine()
        self.realtime_protection = RealtimeProtection(self.scan_engine)
        self.quarantine_manager = QuarantineManager()

        # Setup window
        self.title("🛡️ Sentry Antivirus")
        self.geometry("1100x700")
        self.minsize(900, 600)

        # Set window icon
        icon_path = Path(__file__).parent / "icon.png"
        if icon_path.exists():
            self._icon_image = ctk.CTkImage(
                light_image=Image.open(icon_path),
                dark_image=Image.open(icon_path),
                size=(32, 32)
            )
            icon_photo = Image.open(icon_path).resize((32, 32))
            from PIL import ImageTk
            self._icon_photo = ImageTk.PhotoImage(icon_photo)
            self.wm_iconphoto(True, self._icon_photo)

        # Set appearance
        ctk.set_appearance_mode(self.config.get("appearance_mode", "dark"))
        ctk.set_default_color_theme(str(Path(__file__).parent / "theme.json"))

        # Configure grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Create sidebar
        self._create_sidebar()

        # Create main content area
        self.content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Initialize views
        self.views = {}
        self._create_views()

        # Show dashboard by default
        self._show_view("dashboard")

        # Start real-time protection if enabled
        if self.config.get("realtime_protection_enabled", True):
            self._start_realtime_protection()

        # Set up closing handler
        self.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _create_sidebar(self):
        """Create the sidebar navigation"""
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(7, weight=1)

        # Logo and title
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=(20, 10))

        icon_path = Path(__file__).parent / "icon.png"
        if icon_path.exists():
            sidebar_icon = ctk.CTkImage(
                light_image=Image.open(icon_path),
                dark_image=Image.open(icon_path),
                size=(48, 48)
            )
            ctk.CTkLabel(logo_frame, image=sidebar_icon, text="").pack()

        self.logo_label = ctk.CTkLabel(
            logo_frame,
            text="Sentry",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.logo_label.pack()

        self.tagline_label = ctk.CTkLabel(
            logo_frame,
            text="Always protects your computer!",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        self.tagline_label.pack()

        # Navigation buttons
        self.nav_buttons = {}
        
        nav_items = [
            ("dashboard", "🏠 Dashboard", 1),
            ("scan", "🔍 Scan", 2),
            ("quarantine", "📦 Quarantine", 3),
            ("history", "📋 History", 4),
            ("settings", "⚙️ Settings", 5),
        ]

        for view_name, text, row in nav_items:
            btn = ctk.CTkButton(
                self.sidebar,
                text=text,
                font=ctk.CTkFont(size=14),
                height=40,
                anchor="w",
                corner_radius=8,
                fg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray30"),
                command=lambda v=view_name: self._show_view(v)
            )
            btn.grid(row=row, column=0, padx=15, pady=5, sticky="ew")
            self.nav_buttons[view_name] = btn

        # Protection status indicator
        self.status_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.status_frame.grid(row=8, column=0, padx=15, pady=15, sticky="sew")

        self.status_indicator = ctk.CTkLabel(
            self.status_frame,
            text="● Protected",
            font=ctk.CTkFont(size=12),
            text_color="#00D26A"
        )
        self.status_indicator.pack()

        # Version info
        self.version_label = ctk.CTkLabel(
            self.sidebar,
            text="v1.0.0",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        )
        self.version_label.grid(row=9, column=0, pady=(0, 10))

    def _create_views(self):
        """Create all application views"""
        self.views["dashboard"] = DashboardView(
            self.content_frame,
            app=self,
            scan_engine=self.scan_engine,
            realtime_protection=self.realtime_protection,
            quarantine_manager=self.quarantine_manager
        )
        
        self.views["scan"] = ScanView(
            self.content_frame,
            app=self,
            scan_engine=self.scan_engine,
            quarantine_manager=self.quarantine_manager
        )
        
        self.views["quarantine"] = QuarantineView(
            self.content_frame,
            app=self,
            quarantine_manager=self.quarantine_manager
        )
        
        self.views["history"] = HistoryView(
            self.content_frame,
            app=self,
            realtime_protection=self.realtime_protection
        )
        
        self.views["settings"] = SettingsView(
            self.content_frame,
            app=self,
            config=self.config,
            realtime_protection=self.realtime_protection
        )

    def _show_view(self, view_name: str):
        """Show a specific view"""
        # Hide all views
        for view in self.views.values():
            view.grid_forget()

        # Update button states
        for name, btn in self.nav_buttons.items():
            if name == view_name:
                btn.configure(fg_color=("gray75", "gray25"))
            else:
                btn.configure(fg_color="transparent")

        # Show selected view
        self.views[view_name].grid(row=0, column=0, sticky="nsew")
        
        # Refresh view if it has refresh method
        if hasattr(self.views[view_name], 'refresh'):
            self.views[view_name].refresh()

    def _start_realtime_protection(self):
        """Start real-time protection in background"""
        def start():
            self.realtime_protection.start()
            self._update_protection_status()
        
        thread = threading.Thread(target=start, daemon=True)
        thread.start()

    def _update_protection_status(self):
        """Update protection status indicator"""
        status = self.realtime_protection.get_status()
        
        if status == ProtectionStatus.ENABLED:
            self.status_indicator.configure(text="● Protected", text_color="#00D26A")
        elif status == ProtectionStatus.PAUSED:
            self.status_indicator.configure(text="● Paused", text_color="#FFB800")
        elif status == ProtectionStatus.ERROR:
            self.status_indicator.configure(text="● Error", text_color="#FF4444")
        else:
            self.status_indicator.configure(text="● Unprotected", text_color="#FF4444")

    def toggle_realtime_protection(self, enabled: bool):
        """Toggle real-time protection on/off"""
        if enabled:
            self._start_realtime_protection()
        else:
            self.realtime_protection.stop()
        
        self._update_protection_status()
        self.config.set("realtime_protection_enabled", enabled)

    def show_notification(self, title: str, message: str, type_: str = "info"):
        """Show a notification to the user"""
        if type_ == "error":
            messagebox.showerror(title, message)
        elif type_ == "warning":
            messagebox.showwarning(title, message)
        else:
            messagebox.showinfo(title, message)

    def navigate_to(self, view_name: str):
        """Navigate to a specific view"""
        self._show_view(view_name)

    def _on_closing(self):
        """Handle window closing"""
        # Stop real-time protection
        self.realtime_protection.stop()
        
        # Save config
        self.config.save()
        
        # Close window
        self.destroy()


def main():
    """Main entry point for GUI application"""
    app = SentryApp()
    app.mainloop()


if __name__ == "__main__":
    main()
