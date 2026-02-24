"""
Sentry Antivirus - Configuration Manager
Always protects your stuff!
"""

import os
import json
from typing import Any, Optional
from pathlib import Path


class Config:
    """
    Configuration manager for Sentry Antivirus
    
    Handles loading and saving application settings
    """

    DEFAULT_CONFIG = {
        "realtime_protection_enabled": True,
        "auto_quarantine": False,
        "scan_threads": 4,
        "heuristic_sensitivity": "Medium",
        "appearance_mode": "dark",
        "last_scan_date": None,
        "excluded_paths": [],
        "excluded_extensions": [],
        "update_check_enabled": True,
        "notification_enabled": True,
        "start_with_windows": False,
        "minimize_to_tray": True,
    }

    def __init__(self, config_path: Optional[str] = None):
        self.config_dir = os.path.join(
            os.path.expandvars("%LOCALAPPDATA%"),
            "Sentry"
        )
        self.config_path = config_path or os.path.join(
            self.config_dir,
            "config.json"
        )
        self._config = dict(self.DEFAULT_CONFIG)
        
        # Ensure config directory exists
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Load existing config
        self._load()

    def _load(self):
        """Load configuration from file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    loaded = json.load(f)
                    # Merge with defaults (in case new settings were added)
                    self._config.update(loaded)
            except Exception as e:
                print(f"Warning: Could not load config: {e}")

    def save(self):
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save config: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        return self._config.get(key, default)

    def set(self, key: str, value: Any):
        """Set a configuration value"""
        self._config[key] = value
        self.save()

    def reset(self):
        """Reset to default configuration"""
        self._config = dict(self.DEFAULT_CONFIG)
        self.save()

    def get_all(self) -> dict:
        """Get all configuration values"""
        return dict(self._config)

    def add_excluded_path(self, path: str):
        """Add a path to exclusion list"""
        excluded = self._config.get("excluded_paths", [])
        if path not in excluded:
            excluded.append(path)
            self._config["excluded_paths"] = excluded
            self.save()

    def remove_excluded_path(self, path: str):
        """Remove a path from exclusion list"""
        excluded = self._config.get("excluded_paths", [])
        if path in excluded:
            excluded.remove(path)
            self._config["excluded_paths"] = excluded
            self.save()

    def add_excluded_extension(self, ext: str):
        """Add an extension to exclusion list"""
        if not ext.startswith('.'):
            ext = '.' + ext
        excluded = self._config.get("excluded_extensions", [])
        if ext not in excluded:
            excluded.append(ext)
            self._config["excluded_extensions"] = excluded
            self.save()

    def remove_excluded_extension(self, ext: str):
        """Remove an extension from exclusion list"""
        if not ext.startswith('.'):
            ext = '.' + ext
        excluded = self._config.get("excluded_extensions", [])
        if ext in excluded:
            excluded.remove(ext)
            self._config["excluded_extensions"] = excluded
            self.save()
