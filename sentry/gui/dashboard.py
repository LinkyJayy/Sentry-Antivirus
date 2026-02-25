"""
Sentry Antivirus - Dashboard View
Always protects your computer!
"""

from pathlib import Path
import customtkinter as ctk
from PIL import Image
from datetime import datetime
from typing import TYPE_CHECKING
from .widgets import AnimatedSwitch

if TYPE_CHECKING:
    from .app import SentryApp
    from ..scanner.engine import ScanEngine
    from ..protection.realtime import RealtimeProtection
    from ..quarantine.manager import QuarantineManager


class DashboardView(ctk.CTkFrame):
    """Main dashboard view showing protection status and quick actions"""

    def __init__(self, parent, app: 'SentryApp', scan_engine: 'ScanEngine',
                 realtime_protection: 'RealtimeProtection', 
                 quarantine_manager: 'QuarantineManager'):
        super().__init__(parent, fg_color="transparent")
        
        self.app = app
        self.scan_engine = scan_engine
        self.realtime_protection = realtime_protection
        self.quarantine_manager = quarantine_manager

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._create_widgets()
        self._update_status()

    def _create_widgets(self):
        """Create dashboard widgets"""
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))

        title = ctk.CTkLabel(
            header,
            text="Security Dashboard",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            header,
            text="Monitor your system's protection status",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle.pack(anchor="w")

        # Main content area
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew")
        content.grid_columnconfigure((0, 1), weight=1)
        content.grid_rowconfigure(1, weight=1)

        # Protection status card
        self._create_protection_card(content)

        # Quick actions card
        self._create_quick_actions_card(content)

        # Statistics card
        self._create_stats_card(content)

        # Recent activity card
        self._create_recent_activity_card(content)

    def _create_protection_card(self, parent):
        """Create the main protection status card"""
        card = ctk.CTkFrame(parent, corner_radius=15)
        card.grid(row=0, column=0, padx=(0, 10), pady=(0, 10), sticky="nsew")

        # Status icon and text
        gui_dir = Path(__file__).parent
        rtp_on_path = gui_dir / "rtp_on.png"
        rtp_off_path = gui_dir / "rtp_off.png"
        self._rtp_on_image = ctk.CTkImage(
            light_image=Image.open(rtp_on_path),
            dark_image=Image.open(rtp_on_path),
            size=(80, 80)
        ) if rtp_on_path.exists() else None
        self._rtp_off_image = ctk.CTkImage(
            light_image=Image.open(rtp_off_path),
            dark_image=Image.open(rtp_off_path),
            size=(80, 80)
        ) if rtp_off_path.exists() else None

        self.status_icon = ctk.CTkLabel(card, image=self._rtp_on_image, text="")
        self.status_icon.pack(pady=(30, 10))

        self.status_text = ctk.CTkLabel(
            card,
            text="You're Protected",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#00D26A"
        )
        self.status_text.pack()

        self.status_detail = ctk.CTkLabel(
            card,
            text="Real-time protection is active",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        self.status_detail.pack(pady=(5, 20))

        # Protection toggle
        toggle_frame = ctk.CTkFrame(card, fg_color="transparent")
        toggle_frame.pack(pady=(0, 20))

        toggle_label = ctk.CTkLabel(
            toggle_frame,
            text="Real-time Protection",
            font=ctk.CTkFont(size=13)
        )
        toggle_label.pack(side="left", padx=(0, 10))

        self.protection_toggle = AnimatedSwitch(
            toggle_frame,
            command=self._on_protection_toggle,
            onvalue=True,
            offvalue=False
        )
        self.protection_toggle.pack(side="left")

        # Last scan info
        self.last_scan_label = ctk.CTkLabel(
            card,
            text="Last scan: Never",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        self.last_scan_label.pack(pady=(0, 20))

    def _create_quick_actions_card(self, parent):
        """Create quick actions card"""
        card = ctk.CTkFrame(parent, corner_radius=15)
        card.grid(row=0, column=1, padx=(10, 0), pady=(0, 10), sticky="nsew")

        title = ctk.CTkLabel(
            card,
            text="Quick Actions",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(anchor="w", padx=20, pady=(20, 15))

        # Quick scan button
        quick_scan_btn = ctk.CTkButton(
            card,
            text="⚡ Quick Scan",
            font=ctk.CTkFont(size=14),
            height=45,
            corner_radius=10,
            command=self._start_quick_scan
        )
        quick_scan_btn.pack(fill="x", padx=20, pady=5)

        # Full scan button
        full_scan_btn = ctk.CTkButton(
            card,
            text="🔍 Full Scan",
            font=ctk.CTkFont(size=14),
            height=45,
            corner_radius=10,
            fg_color=("gray75", "gray25"),
            hover_color=("gray65", "gray35"),
            command=self._start_full_scan
        )
        full_scan_btn.pack(fill="x", padx=20, pady=5)

        # Custom scan button
        custom_scan_btn = ctk.CTkButton(
            card,
            text="📁 Custom Scan",
            font=ctk.CTkFont(size=14),
            height=45,
            corner_radius=10,
            fg_color=("gray75", "gray25"),
            hover_color=("gray65", "gray35"),
            command=self._start_custom_scan
        )
        custom_scan_btn.pack(fill="x", padx=20, pady=5)

        # View quarantine button
        quarantine_btn = ctk.CTkButton(
            card,
            text="📦 View Quarantine",
            font=ctk.CTkFont(size=14),
            height=45,
            corner_radius=10,
            fg_color=("gray75", "gray25"),
            hover_color=("gray65", "gray35"),
            command=lambda: self.app.navigate_to("quarantine")
        )
        quarantine_btn.pack(fill="x", padx=20, pady=(5, 20))

    def _create_stats_card(self, parent):
        """Create statistics card"""
        card = ctk.CTkFrame(parent, corner_radius=15)
        card.grid(row=1, column=0, padx=(0, 10), pady=(10, 0), sticky="nsew")

        title = ctk.CTkLabel(
            card,
            text="Protection Statistics",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(anchor="w", padx=20, pady=(20, 15))

        stats_frame = ctk.CTkFrame(card, fg_color="transparent")
        stats_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        stats_frame.grid_columnconfigure((0, 1), weight=1)

        # Threats blocked
        self._create_stat_item(stats_frame, "🚫", "Threats Blocked", "0", 0, 0)
        
        # Files scanned
        self._create_stat_item(stats_frame, "📄", "Files Scanned", "0", 0, 1)
        
        # Quarantined items
        quarantine_count = self.quarantine_manager.get_item_count()
        self._create_stat_item(stats_frame, "📦", "Quarantined", str(quarantine_count), 1, 0)
        
        # Database signatures
        sig_count = self.scan_engine.signatures.get_signature_count()['total']
        self._create_stat_item(stats_frame, "🔐", "Signatures", str(sig_count), 1, 1)

    def _create_stat_item(self, parent, icon: str, label: str, value: str, row: int, col: int):
        """Create a single stat item"""
        frame = ctk.CTkFrame(parent, corner_radius=10)
        frame.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")

        icon_label = ctk.CTkLabel(frame, text=icon, font=ctk.CTkFont(size=24))
        icon_label.pack(pady=(15, 5))

        value_label = ctk.CTkLabel(frame, text=value, font=ctk.CTkFont(size=20, weight="bold"))
        value_label.pack()

        name_label = ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(size=12), text_color="gray")
        name_label.pack(pady=(0, 15))

    def _create_recent_activity_card(self, parent):
        """Create recent activity card"""
        card = ctk.CTkFrame(parent, corner_radius=15)
        card.grid(row=1, column=1, padx=(10, 0), pady=(10, 0), sticky="nsew")

        title = ctk.CTkLabel(
            card,
            text="Recent Activity",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        title.pack(anchor="w", padx=20, pady=(20, 15))

        # Activity list
        self.activity_frame = ctk.CTkScrollableFrame(card, fg_color="transparent")
        self.activity_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Placeholder for no activity
        self.no_activity_label = ctk.CTkLabel(
            self.activity_frame,
            text="No recent activity",
            font=ctk.CTkFont(size=13),
            text_color="gray"
        )
        self.no_activity_label.pack(pady=30)

    def _update_status(self):
        """Update protection status display"""
        from ..protection.realtime import ProtectionStatus
        
        status = self.realtime_protection.get_status()
        
        if status == ProtectionStatus.ENABLED:
            self.status_icon.configure(image=self._rtp_on_image)
            self.status_text.configure(text="You're Protected", text_color="#00D26A")
            self.status_detail.configure(text="Real-time protection is active")
            self.protection_toggle.select()
        elif status == ProtectionStatus.PAUSED:
            self.status_icon.configure(image=self._rtp_on_image)
            self.status_text.configure(text="Protection Paused", text_color="#FFB800")
            self.status_detail.configure(text="Real-time protection is paused")
            self.protection_toggle.select()
        else:
            self.status_icon.configure(image=self._rtp_off_image)
            self.status_text.configure(text="At Risk", text_color="#FF4444")
            self.status_detail.configure(text="Real-time protection is disabled")
            self.protection_toggle.deselect()

    def _on_protection_toggle(self):
        """Handle protection toggle"""
        enabled = self.protection_toggle.get()
        self.app.toggle_realtime_protection(enabled)

    def _start_quick_scan(self):
        """Start a quick scan"""
        self.app.navigate_to("scan")
        self.app.views["scan"].start_quick_scan()

    def _start_full_scan(self):
        """Start a full scan"""
        self.app.navigate_to("scan")
        self.app.views["scan"].start_full_scan()

    def _start_custom_scan(self):
        """Start a custom scan"""
        self.app.navigate_to("scan")
        self.app.views["scan"].start_custom_scan()

    def refresh(self):
        """Refresh the dashboard"""
        self._update_status()
        
        # Update quarantine count
        quarantine_count = self.quarantine_manager.get_item_count()
        # Would need to store reference to update specific stat
        
        # Update recent activity
        events = self.realtime_protection.get_recent_events(5)
        
        # Clear existing activity items
        for widget in self.activity_frame.winfo_children():
            widget.destroy()
        
        if events:
            for event in reversed(events):
                self._add_activity_item(event)
        else:
            no_activity = ctk.CTkLabel(
                self.activity_frame,
                text="No recent activity",
                font=ctk.CTkFont(size=13),
                text_color="gray"
            )
            no_activity.pack(pady=30)

    def _add_activity_item(self, event):
        """Add an activity item to the list"""
        frame = ctk.CTkFrame(self.activity_frame, corner_radius=8)
        frame.pack(fill="x", pady=3)

        # Determine icon based on event type
        if event.threat_info:
            icon = "⚠️"
            color = "#FF4444"
        elif event.action_taken == "scanned":
            icon = "✓"
            color = "#00D26A"
        else:
            icon = "ℹ️"
            color = "gray"

        icon_label = ctk.CTkLabel(frame, text=icon, font=ctk.CTkFont(size=14))
        icon_label.pack(side="left", padx=10)

        info_frame = ctk.CTkFrame(frame, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True)

        action_text = event.action_taken.replace("_", " ").title()
        action_label = ctk.CTkLabel(
            info_frame,
            text=action_text,
            font=ctk.CTkFont(size=12),
            text_color=color
        )
        action_label.pack(anchor="w")

        path_label = ctk.CTkLabel(
            info_frame,
            text=event.file_path[-50:] if len(event.file_path) > 50 else event.file_path,
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        path_label.pack(anchor="w")

        time_label = ctk.CTkLabel(
            frame,
            text=event.timestamp.strftime("%H:%M"),
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        time_label.pack(side="right", padx=10)
