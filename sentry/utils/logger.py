"""
Sentry Antivirus - Logging Utilities
Always protects your computer!
"""

import os
import logging
from datetime import datetime
from typing import Optional


class Logger:
    """
    Logging utility for Sentry Antivirus
    
    Provides consistent logging across all modules
    """

    LOG_DIR = os.path.join(
        os.path.expandvars("%LOCALAPPDATA%"),
        "Sentry",
        "Logs"
    )

    def __init__(self, name: str = "sentry", log_level: int = logging.INFO):
        self.name = name
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        # Ensure log directory exists
        os.makedirs(self.LOG_DIR, exist_ok=True)
        
        # File handler
        log_file = os.path.join(
            self.LOG_DIR,
            f"sentry_{datetime.now().strftime('%Y%m%d')}.log"
        )
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
            self.logger.addHandler(console_handler)

    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)

    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)

    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)

    def error(self, message: str):
        """Log error message"""
        self.logger.error(message)

    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(message)

    def threat_detected(self, file_path: str, threat_name: str, action: str):
        """Log a threat detection event"""
        self.logger.warning(
            f"THREAT DETECTED - File: {file_path}, Threat: {threat_name}, Action: {action}"
        )

    def scan_started(self, scan_type: str, target: Optional[str] = None):
        """Log scan start"""
        if target:
            self.logger.info(f"SCAN STARTED - Type: {scan_type}, Target: {target}")
        else:
            self.logger.info(f"SCAN STARTED - Type: {scan_type}")

    def scan_completed(self, files_scanned: int, threats_found: int, duration: float):
        """Log scan completion"""
        self.logger.info(
            f"SCAN COMPLETED - Files: {files_scanned}, Threats: {threats_found}, "
            f"Duration: {duration:.2f}s"
        )

    def protection_status(self, status: str):
        """Log protection status change"""
        self.logger.info(f"PROTECTION STATUS - {status}")

    def quarantine_action(self, action: str, file_path: str):
        """Log quarantine action"""
        self.logger.info(f"QUARANTINE - Action: {action}, File: {file_path}")

    @classmethod
    def cleanup_old_logs(cls, days: int = 30):
        """Remove log files older than specified days"""
        from datetime import timedelta
        
        cutoff = datetime.now() - timedelta(days=days)
        
        if os.path.exists(cls.LOG_DIR):
            for filename in os.listdir(cls.LOG_DIR):
                filepath = os.path.join(cls.LOG_DIR, filename)
                if os.path.isfile(filepath):
                    file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if file_time < cutoff:
                        try:
                            os.remove(filepath)
                        except:
                            pass
