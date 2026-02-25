"""
Sentry Antivirus - History View
Always protects your computer!
"""

import customtkinter as ctk
from datetime import datetime
from typing import TYPE_CHECKING, List

if TYPE_CHECKING:
    from .app import SentryApp
    from ..protection.realtime import RealtimeProtection, ProtectionEvent


class HistoryView(ctk.CTkFrame):
    """View for protection history and activity log"""

    def __init__(self, parent, app: 'SentryApp', realtime_protection: 'RealtimeProtection'):
        super().__init__(parent, fg_color="transparent")
        
        self.app = app
        self.realtime_protection = realtime_protection

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._create_widgets()

    def _create_widgets(self):
        """Create history view widgets"""
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))

        title = ctk.CTkLabel(
            header,
            text="Protection History",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            header,
            text="View recent protection events and scan history",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle.pack(anchor="w")

        # Main content
        content = ctk.CTkFrame(self, corner_radius=15)
        content.grid(row=1, column=0, sticky="nsew")
        content.grid_rowconfigure(1, weight=1)
        content.grid_columnconfigure(0, weight=1)

        # Filter toolbar
        toolbar = ctk.CTkFrame(content, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        filter_label = ctk.CTkLabel(
            toolbar,
            text="Filter:",
            font=ctk.CTkFont(size=13)
        )
        filter_label.pack(side="left", padx=(0, 10))

        self.filter_var = ctk.StringVar(value="all")
        
        all_btn = ctk.CTkRadioButton(
            toolbar,
            text="All",
            variable=self.filter_var,
            value="all",
            font=ctk.CTkFont(size=12),
            command=self.refresh
        )
        all_btn.pack(side="left", padx=5)

        threats_btn = ctk.CTkRadioButton(
            toolbar,
            text="Threats",
            variable=self.filter_var,
            value="threats",
            font=ctk.CTkFont(size=12),
            command=self.refresh
        )
        threats_btn.pack(side="left", padx=5)

        scans_btn = ctk.CTkRadioButton(
            toolbar,
            text="Scans",
            variable=self.filter_var,
            value="scans",
            font=ctk.CTkFont(size=12),
            command=self.refresh
        )
        scans_btn.pack(side="left", padx=5)

        # Clear history button
        clear_btn = ctk.CTkButton(
            toolbar,
            text="Clear History",
            font=ctk.CTkFont(size=12),
            width=100,
            height=30,
            fg_color=("gray75", "gray25"),
            hover_color=("gray65", "gray35"),
            command=self._clear_history
        )
        clear_btn.pack(side="right")

        # Events list
        self.events_frame = ctk.CTkScrollableFrame(content, fg_color="transparent")
        self.events_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

    def refresh(self):
        """Refresh the history list"""
        # Clear existing items
        for widget in self.events_frame.winfo_children():
            widget.destroy()

        events = self.realtime_protection.get_recent_events(100)
        
        # Apply filter
        filter_type = self.filter_var.get()
        if filter_type == "threats":
            events = [e for e in events if e.threat_info is not None]
        elif filter_type == "scans":
            events = [e for e in events if e.action_taken == "scanned"]

        if not events:
            empty_label = ctk.CTkLabel(
                self.events_frame,
                text="📋 No history yet\nProtection events will appear here",
                font=ctk.CTkFont(size=14),
                text_color="gray"
            )
            empty_label.pack(pady=50)
            return

        # Group events by date
        events_by_date = {}
        for event in reversed(events):
            date_key = event.timestamp.strftime("%Y-%m-%d")
            if date_key not in events_by_date:
                events_by_date[date_key] = []
            events_by_date[date_key].append(event)

        # Display events
        for date_key, date_events in events_by_date.items():
            self._add_date_header(date_key)
            for event in date_events:
                self._add_event_row(event)

    def _add_date_header(self, date_str: str):
        """Add a date header"""
        try:
            dt = datetime.strptime(date_str, "%Y-%m-%d")
            if dt.date() == datetime.now().date():
                display = "Today"
            else:
                display = dt.strftime("%B %d, %Y")
        except:
            display = date_str

        header = ctk.CTkLabel(
            self.events_frame,
            text=display,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="gray"
        )
        header.pack(anchor="w", pady=(15, 5))

    def _add_event_row(self, event: 'ProtectionEvent'):
        """Add an event row"""
        frame = ctk.CTkFrame(self.events_frame, corner_radius=8)
        frame.pack(fill="x", pady=2)

        # Determine icon and color
        if event.threat_info:
            icon = "⚠️"
            color = "#FF4444"
            action = f"Threat detected: {event.threat_info.threat_name}"
        elif event.action_taken == "quarantined":
            icon = "📦"
            color = "#FFB800"
            action = "File quarantined"
        elif event.action_taken == "scanned":
            icon = "✓"
            color = "#00D26A"
            action = "File scanned - clean"
        elif event.event_type == "protection_started":
            icon = "🛡️"
            color = "#00D26A"
            action = "Real-time protection started"
        elif event.event_type == "protection_stopped":
            icon = "⚪"
            color = "gray"
            action = "Real-time protection stopped"
        else:
            icon = "ℹ️"
            color = "gray"
            action = event.action_taken.replace("_", " ").title()

        # Time
        time_label = ctk.CTkLabel(
            frame,
            text=event.timestamp.strftime("%H:%M:%S"),
            font=ctk.CTkFont(size=11),
            text_color="gray",
            width=70
        )
        time_label.pack(side="left", padx=10, pady=10)

        # Icon
        icon_label = ctk.CTkLabel(
            frame,
            text=icon,
            font=ctk.CTkFont(size=16)
        )
        icon_label.pack(side="left", padx=5)

        # Event info
        info_frame = ctk.CTkFrame(frame, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True, pady=8)

        action_label = ctk.CTkLabel(
            info_frame,
            text=action,
            font=ctk.CTkFont(size=12),
            text_color=color
        )
        action_label.pack(anchor="w")

        if event.file_path:
            path = event.file_path
            if len(path) > 60:
                path = "..." + path[-57:]
            
            path_label = ctk.CTkLabel(
                info_frame,
                text=path,
                font=ctk.CTkFont(size=10),
                text_color="gray"
            )
            path_label.pack(anchor="w")

    def _clear_history(self):
        """Clear protection history"""
        from tkinter import messagebox
        
        if messagebox.askyesno(
            "Clear History",
            "Clear all protection history?\nThis cannot be undone."
        ):
            # Clear internal events list
            self.realtime_protection._events.clear()
            self.refresh()
