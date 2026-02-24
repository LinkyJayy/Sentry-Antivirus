"""
Sentry Antivirus - Real-time Protection Monitor
Always protects your stuff!
"""

import os
import time
import threading
import queue
from pathlib import Path
from typing import Optional, Callable, List, Set
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    Observer = None
    FileSystemEventHandler = object
    FileSystemEvent = None

from ..scanner.engine import ScanEngine, ScanResult, ThreatLevel


class ProtectionStatus(Enum):
    """Status of real-time protection"""
    DISABLED = 0
    ENABLED = 1
    PAUSED = 2
    ERROR = 3


@dataclass
class ProtectionEvent:
    """Represents a protection event"""
    timestamp: datetime
    event_type: str
    file_path: str
    action_taken: str
    threat_info: Optional[ScanResult] = None


class FileEventHandler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    """Handles file system events for real-time scanning"""

    def __init__(self, protection: 'RealtimeProtection'):
        if WATCHDOG_AVAILABLE:
            super().__init__()
        self.protection = protection

    def on_created(self, event):
        if not event.is_directory:
            self.protection._queue_file(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self.protection._queue_file(event.src_path, "modified")

    def on_moved(self, event):
        if not event.is_directory:
            self.protection._queue_file(event.dest_path, "moved")


class RealtimeProtection:
    """
    Real-time file system protection
    
    Features:
    - Monitors file system for new/modified files
    - Automatic scanning of suspicious files
    - Configurable monitored paths
    - Event callbacks for UI integration
    - Automatic threat response
    """

    # Default paths to monitor
    DEFAULT_WATCH_PATHS = [
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Documents"),
        os.path.expandvars("%TEMP%"),
        os.path.expandvars("%APPDATA%"),
    ]

    # File extensions to scan immediately
    HIGH_RISK_EXTENSIONS = {
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
        '.msi', '.scr', '.pif', '.com', '.hta', '.jar'
    }

    def __init__(self, scan_engine: Optional[ScanEngine] = None):
        self.scan_engine = scan_engine or ScanEngine(max_workers=2)
        self.status = ProtectionStatus.DISABLED
        self._observer: Optional[Observer] = None
        self._scan_queue: queue.Queue = queue.Queue()
        self._scan_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._watched_paths: Set[str] = set()
        self._event_callbacks: List[Callable[[ProtectionEvent], None]] = []
        self._threat_callbacks: List[Callable[[ScanResult], None]] = []
        self._recent_files: Set[str] = set()
        self._recent_lock = threading.Lock()
        self._events: List[ProtectionEvent] = []
        self._auto_quarantine = False

        if not WATCHDOG_AVAILABLE:
            print("Warning: watchdog module not available. Install with: pip install watchdog")

    def add_event_callback(self, callback: Callable[[ProtectionEvent], None]):
        """Add callback for protection events"""
        self._event_callbacks.append(callback)

    def add_threat_callback(self, callback: Callable[[ScanResult], None]):
        """Add callback for threat detections"""
        self._threat_callbacks.append(callback)

    def _notify_event(self, event: ProtectionEvent):
        """Notify callbacks of a protection event"""
        self._events.append(event)
        for callback in self._event_callbacks:
            try:
                callback(event)
            except Exception:
                pass

    def _notify_threat(self, result: ScanResult):
        """Notify callbacks of a threat detection"""
        for callback in self._threat_callbacks:
            try:
                callback(result)
            except Exception:
                pass

    def _queue_file(self, file_path: str, event_type: str):
        """Queue a file for scanning"""
        if self.status != ProtectionStatus.ENABLED:
            return

        # Debounce - skip if we've seen this file recently
        with self._recent_lock:
            if file_path in self._recent_files:
                return
            self._recent_files.add(file_path)
            # Clear old entries periodically
            if len(self._recent_files) > 1000:
                self._recent_files.clear()

        # Check if file should be scanned
        ext = os.path.splitext(file_path)[1].lower()
        if ext in self.HIGH_RISK_EXTENSIONS or ext in self.scan_engine.SCANNABLE_EXTENSIONS:
            self._scan_queue.put((file_path, event_type))

    def _scan_worker(self):
        """Worker thread for scanning queued files"""
        while not self._stop_event.is_set():
            try:
                file_path, event_type = self._scan_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if self._stop_event.is_set():
                break

            # Wait a bit for file to be fully written
            time.sleep(0.2)

            if not os.path.exists(file_path):
                continue

            try:
                # Scan the file
                result = self.scan_engine.scan_file(file_path)

                action = "scanned"
                if result.is_threat:
                    self._notify_threat(result)
                    
                    if self._auto_quarantine:
                        # Import here to avoid circular dependency
                        from ..quarantine.manager import QuarantineManager
                        qm = QuarantineManager()
                        if qm.quarantine_file(file_path, result):
                            action = "quarantined"
                        else:
                            action = "threat_detected"
                    else:
                        action = "threat_detected"

                event = ProtectionEvent(
                    timestamp=datetime.now(),
                    event_type=event_type,
                    file_path=file_path,
                    action_taken=action,
                    threat_info=result if result.is_threat else None
                )
                self._notify_event(event)

            except Exception as e:
                event = ProtectionEvent(
                    timestamp=datetime.now(),
                    event_type=event_type,
                    file_path=file_path,
                    action_taken=f"error: {str(e)}"
                )
                self._notify_event(event)

            # Remove from recent files after processing
            with self._recent_lock:
                self._recent_files.discard(file_path)

    def start(self, paths: Optional[List[str]] = None):
        """Start real-time protection"""
        if not WATCHDOG_AVAILABLE:
            self.status = ProtectionStatus.ERROR
            return False

        if self.status == ProtectionStatus.ENABLED:
            return True

        paths = paths or self.DEFAULT_WATCH_PATHS
        
        try:
            self._stop_event.clear()
            
            # Start file system observer
            self._observer = Observer()
            handler = FileEventHandler(self)
            
            for path in paths:
                if os.path.exists(path):
                    self._observer.schedule(handler, path, recursive=True)
                    self._watched_paths.add(path)

            self._observer.start()

            # Start scan worker thread
            self._scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
            self._scan_thread.start()

            self.status = ProtectionStatus.ENABLED
            
            event = ProtectionEvent(
                timestamp=datetime.now(),
                event_type="protection_started",
                file_path="",
                action_taken=f"Monitoring {len(self._watched_paths)} locations"
            )
            self._notify_event(event)
            
            return True

        except Exception as e:
            self.status = ProtectionStatus.ERROR
            return False

    def stop(self):
        """Stop real-time protection"""
        if self.status == ProtectionStatus.DISABLED:
            return

        self._stop_event.set()

        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

        if self._scan_thread:
            self._scan_thread.join(timeout=5)
            self._scan_thread = None

        self._watched_paths.clear()
        self.status = ProtectionStatus.DISABLED

        event = ProtectionEvent(
            timestamp=datetime.now(),
            event_type="protection_stopped",
            file_path="",
            action_taken="Real-time protection disabled"
        )
        self._notify_event(event)

    def pause(self):
        """Pause real-time protection temporarily"""
        if self.status == ProtectionStatus.ENABLED:
            self.status = ProtectionStatus.PAUSED

    def resume(self):
        """Resume paused real-time protection"""
        if self.status == ProtectionStatus.PAUSED:
            self.status = ProtectionStatus.ENABLED

    def add_watch_path(self, path: str) -> bool:
        """Add a path to monitor"""
        if not WATCHDOG_AVAILABLE or not self._observer:
            return False

        if not os.path.exists(path):
            return False

        if path in self._watched_paths:
            return True

        try:
            handler = FileEventHandler(self)
            self._observer.schedule(handler, path, recursive=True)
            self._watched_paths.add(path)
            return True
        except Exception:
            return False

    def remove_watch_path(self, path: str) -> bool:
        """Remove a path from monitoring"""
        if path in self._watched_paths:
            self._watched_paths.discard(path)
            # Note: watchdog doesn't easily support unscheduling
            # Would need to restart observer with new paths
            return True
        return False

    def set_auto_quarantine(self, enabled: bool):
        """Enable or disable automatic quarantine of threats"""
        self._auto_quarantine = enabled

    def get_watched_paths(self) -> List[str]:
        """Get list of currently watched paths"""
        return list(self._watched_paths)

    def get_recent_events(self, count: int = 50) -> List[ProtectionEvent]:
        """Get recent protection events"""
        return self._events[-count:]

    def get_status(self) -> ProtectionStatus:
        """Get current protection status"""
        return self.status

    def is_running(self) -> bool:
        """Check if protection is currently running"""
        return self.status == ProtectionStatus.ENABLED
