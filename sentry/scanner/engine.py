"""
Sentry Antivirus - Core Scanning Engine
Always protects your stuff!
"""

import os
import hashlib
import threading
import queue
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable, List, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed

from .types import ThreatLevel
from .signatures import SignatureDatabase
from .heuristics import HeuristicAnalyzer


@dataclass
class ScanResult:
    """Result of scanning a single file"""
    file_path: str
    threat_level: ThreatLevel
    threat_name: Optional[str] = None
    threat_description: Optional[str] = None
    file_hash: Optional[str] = None
    scan_time: datetime = field(default_factory=datetime.now)
    detection_method: str = "signature"

    @property
    def is_threat(self) -> bool:
        return self.threat_level != ThreatLevel.CLEAN


@dataclass
class ScanProgress:
    """Progress information for a scan"""
    total_files: int = 0
    scanned_files: int = 0
    threats_found: int = 0
    current_file: str = ""
    status: str = "idle"
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    @property
    def progress_percent(self) -> float:
        if self.total_files == 0:
            return 0.0
        return (self.scanned_files / self.total_files) * 100

    @property
    def elapsed_time(self) -> float:
        if not self.start_time:
            return 0.0
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()


class ScanEngine:
    """
    Core scanning engine for Sentry Antivirus
    
    Features:
    - Multi-threaded file scanning
    - Signature-based detection
    - Heuristic analysis
    - Progress callbacks
    """

    # Common locations for quick scan
    QUICK_SCAN_PATHS = [
        os.path.expanduser("~\\Downloads"),
        os.path.expanduser("~\\Desktop"),
        os.path.expanduser("~\\Documents"),
        os.path.expandvars("%TEMP%"),
        os.path.expandvars("%APPDATA%"),
        os.path.expandvars("%LOCALAPPDATA%\\Temp"),
    ]

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse',
        '.wsf', '.wsh', '.msi', '.scr', '.pif', '.com', '.hta',
        '.jar', '.py', '.rb', '.php', '.sh', '.reg', '.inf',
        '.zip', '.rar', '.7z', '.iso', '.img',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf',
        '.lnk', '.url'
    }

    # Skip these directories
    SKIP_DIRECTORIES = {
        'Windows', '$Recycle.Bin', 'System Volume Information',
        '.git', 'node_modules', '__pycache__', '.venv', 'venv'
    }

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.signatures = SignatureDatabase()
        self.heuristics = HeuristicAnalyzer()
        self.progress = ScanProgress()
        self._cancel_flag = threading.Event()
        self._pause_flag = threading.Event()
        self._results: List[ScanResult] = []
        self._results_lock = threading.Lock()
        self._callbacks: List[Callable] = []

    def add_progress_callback(self, callback: Callable[[ScanProgress], None]):
        """Add a callback to be notified of progress updates"""
        self._callbacks.append(callback)

    def _notify_progress(self):
        """Notify all callbacks of current progress"""
        for callback in self._callbacks:
            try:
                callback(self.progress)
            except Exception:
                pass

    def _calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate hash of a file"""
        try:
            hasher = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError, PermissionError):
            return None

    def _read_file_header(self, file_path: str, bytes_count: int = 8192) -> Optional[bytes]:
        """Read file header for analysis"""
        try:
            with open(file_path, 'rb') as f:
                return f.read(bytes_count)
        except (IOError, OSError, PermissionError):
            return None

    def _scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file for threats"""
        # Check for cancellation
        if self._cancel_flag.is_set():
            return ScanResult(
                file_path=file_path,
                threat_level=ThreatLevel.CLEAN,
                threat_description="Scan cancelled"
            )

        # Wait if paused
        while self._pause_flag.is_set() and not self._cancel_flag.is_set():
            threading.Event().wait(0.1)

        try:
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Check signature database
            if file_hash:
                signature_match = self.signatures.check_hash(file_hash)
                if signature_match:
                    return ScanResult(
                        file_path=file_path,
                        threat_level=signature_match['level'],
                        threat_name=signature_match['name'],
                        threat_description=signature_match['description'],
                        file_hash=file_hash,
                        detection_method="signature"
                    )

            # Read file header for heuristic analysis
            header = self._read_file_header(file_path)
            if header:
                # Check for known malicious patterns
                pattern_match = self.signatures.check_patterns(header)
                if pattern_match:
                    return ScanResult(
                        file_path=file_path,
                        threat_level=pattern_match['level'],
                        threat_name=pattern_match['name'],
                        threat_description=pattern_match['description'],
                        file_hash=file_hash,
                        detection_method="pattern"
                    )

                # Perform heuristic analysis
                heuristic_result = self.heuristics.analyze(file_path, header)
                if heuristic_result['is_suspicious']:
                    return ScanResult(
                        file_path=file_path,
                        threat_level=heuristic_result['level'],
                        threat_name=heuristic_result['name'],
                        threat_description=heuristic_result['description'],
                        file_hash=file_hash,
                        detection_method="heuristic"
                    )

            # File is clean
            return ScanResult(
                file_path=file_path,
                threat_level=ThreatLevel.CLEAN,
                file_hash=file_hash
            )

        except Exception as e:
            return ScanResult(
                file_path=file_path,
                threat_level=ThreatLevel.CLEAN,
                threat_description=f"Error scanning: {str(e)}"
            )

    def _enumerate_files(self, path: str, recursive: bool = True) -> Generator[str, None, None]:
        """Enumerate files to scan"""
        path = Path(path)
        
        if path.is_file():
            yield str(path)
            return

        try:
            if recursive:
                for root, dirs, files in os.walk(path):
                    # Skip excluded directories
                    dirs[:] = [d for d in dirs if d not in self.SKIP_DIRECTORIES]
                    
                    for file in files:
                        if self._cancel_flag.is_set():
                            return
                        file_path = os.path.join(root, file)
                        ext = os.path.splitext(file)[1].lower()
                        if ext in self.SCANNABLE_EXTENSIONS or not ext:
                            yield file_path
            else:
                for item in path.iterdir():
                    if item.is_file():
                        ext = item.suffix.lower()
                        if ext in self.SCANNABLE_EXTENSIONS or not ext:
                            yield str(item)
        except (PermissionError, OSError):
            pass

    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a single file"""
        return self._scan_file(file_path)

    def scan_directory(self, 
                       directory: str, 
                       recursive: bool = True,
                       on_threat_found: Optional[Callable[[ScanResult], None]] = None) -> List[ScanResult]:
        """Scan a directory for threats"""
        self._cancel_flag.clear()
        self._pause_flag.clear()
        self._results = []
        
        self.progress = ScanProgress(
            status="counting",
            start_time=datetime.now()
        )
        self._notify_progress()

        # Count files first
        files_to_scan = list(self._enumerate_files(directory, recursive))
        self.progress.total_files = len(files_to_scan)
        self.progress.status = "scanning"
        self._notify_progress()

        # Scan files using thread pool
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._scan_file, f): f for f in files_to_scan}
            
            for future in as_completed(futures):
                if self._cancel_flag.is_set():
                    break
                    
                result = future.result()
                
                with self._results_lock:
                    self._results.append(result)
                    self.progress.scanned_files += 1
                    self.progress.current_file = result.file_path
                    
                    if result.is_threat:
                        self.progress.threats_found += 1
                        if on_threat_found:
                            on_threat_found(result)
                
                self._notify_progress()

        self.progress.status = "completed" if not self._cancel_flag.is_set() else "cancelled"
        self.progress.end_time = datetime.now()
        self._notify_progress()

        return self._results

    def quick_scan(self, on_threat_found: Optional[Callable[[ScanResult], None]] = None) -> List[ScanResult]:
        """Perform a quick scan of common threat locations"""
        self._cancel_flag.clear()
        self._pause_flag.clear()
        self._results = []
        
        self.progress = ScanProgress(
            status="counting",
            start_time=datetime.now()
        )
        self._notify_progress()

        # Collect files from all quick scan paths
        all_files = []
        for path in self.QUICK_SCAN_PATHS:
            if os.path.exists(path):
                all_files.extend(self._enumerate_files(path, recursive=False))

        self.progress.total_files = len(all_files)
        self.progress.status = "scanning"
        self._notify_progress()

        # Scan collected files
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._scan_file, f): f for f in all_files}
            
            for future in as_completed(futures):
                if self._cancel_flag.is_set():
                    break
                    
                result = future.result()
                
                with self._results_lock:
                    self._results.append(result)
                    self.progress.scanned_files += 1
                    self.progress.current_file = result.file_path
                    
                    if result.is_threat:
                        self.progress.threats_found += 1
                        if on_threat_found:
                            on_threat_found(result)
                
                self._notify_progress()

        self.progress.status = "completed" if not self._cancel_flag.is_set() else "cancelled"
        self.progress.end_time = datetime.now()
        self._notify_progress()

        return self._results

    def full_scan(self, on_threat_found: Optional[Callable[[ScanResult], None]] = None) -> List[ScanResult]:
        """Perform a full system scan"""
        # Get all drive letters
        drives = []
        for letter in 'CDEFGHIJKLMNOPQRSTUVWXYZ':
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)

        self._cancel_flag.clear()
        self._pause_flag.clear()
        self._results = []
        
        self.progress = ScanProgress(
            status="counting",
            start_time=datetime.now()
        )
        self._notify_progress()

        # Collect all files
        all_files = []
        for drive in drives:
            all_files.extend(self._enumerate_files(drive, recursive=True))

        self.progress.total_files = len(all_files)
        self.progress.status = "scanning"
        self._notify_progress()

        # Scan all files
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._scan_file, f): f for f in all_files}
            
            for future in as_completed(futures):
                if self._cancel_flag.is_set():
                    break
                    
                result = future.result()
                
                with self._results_lock:
                    self._results.append(result)
                    self.progress.scanned_files += 1
                    self.progress.current_file = result.file_path
                    
                    if result.is_threat:
                        self.progress.threats_found += 1
                        if on_threat_found:
                            on_threat_found(result)
                
                self._notify_progress()

        self.progress.status = "completed" if not self._cancel_flag.is_set() else "cancelled"
        self.progress.end_time = datetime.now()
        self._notify_progress()

        return self._results

    def cancel(self):
        """Cancel the current scan"""
        self._cancel_flag.set()

    def pause(self):
        """Pause the current scan"""
        self._pause_flag.set()
        self.progress.status = "paused"
        self._notify_progress()

    def resume(self):
        """Resume a paused scan"""
        self._pause_flag.clear()
        self.progress.status = "scanning"
        self._notify_progress()

    def get_results(self) -> List[ScanResult]:
        """Get all scan results"""
        with self._results_lock:
            return list(self._results)

    def get_threats(self) -> List[ScanResult]:
        """Get only threat results"""
        with self._results_lock:
            return [r for r in self._results if r.is_threat]
