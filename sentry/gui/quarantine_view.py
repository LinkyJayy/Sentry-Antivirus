"""
Sentry Antivirus - Quarantine View
Always protects your stuff!
"""

import customtkinter as ctk
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .app import SentryApp
    from ..quarantine.manager import QuarantineManager, QuarantinedItem


class QuarantineView(ctk.CTkFrame):
    """View for managing quarantined files"""

    def __init__(self, parent, app: 'SentryApp', quarantine_manager: 'QuarantineManager'):
        super().__init__(parent, fg_color="transparent")
        
        self.app = app
        self.quarantine_manager = quarantine_manager

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._create_widgets()

    def _create_widgets(self):
        """Create quarantine view widgets"""
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))

        title = ctk.CTkLabel(
            header,
            text="Quarantine",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        title.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            header,
            text="Manage isolated threats and suspicious files",
            font=ctk.CTkFont(size=14),
            text_color="gray"
        )
        subtitle.pack(anchor="w")

        # Main content
        content = ctk.CTkFrame(self, corner_radius=15)
        content.grid(row=1, column=0, sticky="nsew")
        content.grid_rowconfigure(1, weight=1)
        content.grid_columnconfigure(0, weight=1)

        # Toolbar
        toolbar = ctk.CTkFrame(content, fg_color="transparent")
        toolbar.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))

        self.item_count_label = ctk.CTkLabel(
            toolbar,
            text="0 items in quarantine",
            font=ctk.CTkFont(size=14)
        )
        self.item_count_label.pack(side="left")

        delete_all_btn = ctk.CTkButton(
            toolbar,
            text="Delete All",
            font=ctk.CTkFont(size=12),
            width=100,
            height=32,
            fg_color="#FF4444",
            hover_color="#CC3333",
            command=self._delete_all_items
        )
        delete_all_btn.pack(side="right", padx=(10, 0))

        export_btn = ctk.CTkButton(
            toolbar,
            text="Export Report",
            font=ctk.CTkFont(size=12),
            width=100,
            height=32,
            fg_color=("gray75", "gray25"),
            hover_color=("gray65", "gray35"),
            command=self._export_report
        )
        export_btn.pack(side="right")

        # Items list
        self.items_frame = ctk.CTkScrollableFrame(content, fg_color="transparent")
        self.items_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))

    def refresh(self):
        """Refresh the quarantine list"""
        # Clear existing items
        for widget in self.items_frame.winfo_children():
            widget.destroy()

        items = self.quarantine_manager.get_all_items()
        
        # Update count
        self.item_count_label.configure(text=f"{len(items)} items in quarantine")

        if not items:
            empty_label = ctk.CTkLabel(
                self.items_frame,
                text="📦 Quarantine is empty\nNo threats have been isolated",
                font=ctk.CTkFont(size=14),
                text_color="gray"
            )
            empty_label.pack(pady=50)
            return

        # Add items
        for item in items:
            self._add_item_row(item)

    def _add_item_row(self, item: 'QuarantinedItem'):
        """Add a quarantine item row"""
        frame = ctk.CTkFrame(self.items_frame, corner_radius=10)
        frame.pack(fill="x", pady=3)

        # Threat icon
        level_colors = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FF4444",
            "MEDIUM": "#FFB800",
            "LOW": "#00D26A"
        }
        color = level_colors.get(item.threat_level, "gray")

        icon_frame = ctk.CTkFrame(frame, width=50, height=50, fg_color=color, corner_radius=8)
        icon_frame.pack(side="left", padx=15, pady=15)
        icon_frame.pack_propagate(False)

        icon_label = ctk.CTkLabel(
            icon_frame,
            text="⚠️",
            font=ctk.CTkFont(size=20)
        )
        icon_label.place(relx=0.5, rely=0.5, anchor="center")

        # Item info
        info_frame = ctk.CTkFrame(frame, fg_color="transparent")
        info_frame.pack(side="left", fill="x", expand=True, pady=10)

        name_label = ctk.CTkLabel(
            info_frame,
            text=item.threat_name,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=color
        )
        name_label.pack(anchor="w")

        path_label = ctk.CTkLabel(
            info_frame,
            text=item.original_path,
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        path_label.pack(anchor="w")

        # Format date
        try:
            dt = datetime.fromisoformat(item.quarantine_date)
            date_str = dt.strftime("%Y-%m-%d %H:%M")
        except:
            date_str = item.quarantine_date

        details_label = ctk.CTkLabel(
            info_frame,
            text=f"Quarantined: {date_str} | Size: {self._format_size(item.file_size)}",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        )
        details_label.pack(anchor="w")

        # Action buttons
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(side="right", padx=15)

        restore_btn = ctk.CTkButton(
            btn_frame,
            text="Restore",
            font=ctk.CTkFont(size=11),
            width=80,
            height=28,
            fg_color=("gray75", "gray25"),
            hover_color=("gray65", "gray35"),
            command=lambda i=item, f=frame: self._restore_item(i, f)
        )
        restore_btn.pack(pady=2)

        delete_btn = ctk.CTkButton(
            btn_frame,
            text="Delete",
            font=ctk.CTkFont(size=11),
            width=80,
            height=28,
            fg_color="#FF4444",
            hover_color="#CC3333",
            command=lambda i=item, f=frame: self._delete_item(i, f)
        )
        delete_btn.pack(pady=2)

    def _format_size(self, size: int) -> str:
        """Format file size for display"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _restore_item(self, item: 'QuarantinedItem', frame: ctk.CTkFrame):
        """Restore a quarantined item"""
        from tkinter import messagebox
        
        if messagebox.askyesno(
            "Restore File",
            f"Are you sure you want to restore this file?\n\n"
            f"Threat: {item.threat_name}\n"
            f"Path: {item.original_path}\n\n"
            f"Warning: This file was detected as a threat!"
        ):
            if self.quarantine_manager.restore_file(item.id):
                frame.destroy()
                self._update_count()
                self.app.show_notification("Success", "File restored successfully")
            else:
                self.app.show_notification("Error", "Failed to restore file", "error")

    def _delete_item(self, item: 'QuarantinedItem', frame: ctk.CTkFrame):
        """Permanently delete a quarantined item"""
        from tkinter import messagebox
        
        if messagebox.askyesno(
            "Delete File",
            f"Permanently delete this file?\n\n"
            f"Threat: {item.threat_name}\n\n"
            f"This action cannot be undone."
        ):
            if self.quarantine_manager.delete_permanently(item.id):
                frame.destroy()
                self._update_count()
            else:
                self.app.show_notification("Error", "Failed to delete file", "error")

    def _delete_all_items(self):
        """Delete all quarantined items"""
        from tkinter import messagebox
        
        items = self.quarantine_manager.get_all_items()
        if not items:
            return
        
        if messagebox.askyesno(
            "Delete All",
            f"Permanently delete all {len(items)} quarantined files?\n\n"
            f"This action cannot be undone."
        ):
            for item in items:
                self.quarantine_manager.delete_permanently(item.id)
            self.refresh()
            self.app.show_notification("Success", "All quarantined files deleted")

    def _export_report(self):
        """Export quarantine report"""
        from tkinter import filedialog
        
        path = filedialog.asksaveasfilename(
            title="Export Quarantine Report",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if path:
            if self.quarantine_manager.export_report(path):
                self.app.show_notification("Success", f"Report exported to {path}")
            else:
                self.app.show_notification("Error", "Failed to export report", "error")

    def _update_count(self):
        """Update the item count label"""
        count = self.quarantine_manager.get_item_count()
        self.item_count_label.configure(text=f"{count} items in quarantine")
        
        if count == 0:
            self.refresh()
