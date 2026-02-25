"""
Sentry Antivirus - Quarantine Manager
Always protects your computer!
"""

import os
import json
import shutil
import hashlib
import base64
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict
from dataclasses import dataclass, asdict
from enum import Enum

from ..scanner.engine import ScanResult, ThreatLevel


@dataclass
class QuarantinedItem:
    """Represents a quarantined file"""
    id: str
    original_path: str
    quarantine_path: str
    file_hash: str
    file_size: int
    threat_name: str
    threat_level: str
    threat_description: str
    quarantine_date: str
    detection_method: str

    @classmethod
    def from_dict(cls, data: Dict) -> 'QuarantinedItem':
        return cls(**data)

    def to_dict(self) -> Dict:
        return asdict(self)


class QuarantineManager:
    """
    Manages quarantined files
    
    Features:
    - Secure file isolation
    - File encryption in quarantine
    - Restore functionality
    - Permanent deletion
    - Quarantine database
    """

    DEFAULT_QUARANTINE_DIR = os.path.join(
        os.path.expandvars("%LOCALAPPDATA%"),
        "Sentry",
        "Quarantine"
    )

    def __init__(self, quarantine_dir: Optional[str] = None):
        self.quarantine_dir = quarantine_dir or self.DEFAULT_QUARANTINE_DIR
        self.database_path = os.path.join(self.quarantine_dir, "quarantine.json")
        self._items: Dict[str, QuarantinedItem] = {}
        
        # Ensure quarantine directory exists
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Load existing database
        self._load_database()

    def _load_database(self):
        """Load quarantine database from disk"""
        if os.path.exists(self.database_path):
            try:
                with open(self.database_path, 'r') as f:
                    data = json.load(f)
                    for item_data in data.get('items', []):
                        item = QuarantinedItem.from_dict(item_data)
                        self._items[item.id] = item
            except Exception as e:
                print(f"Warning: Could not load quarantine database: {e}")

    def _save_database(self):
        """Save quarantine database to disk"""
        try:
            data = {
                'version': '1.0',
                'last_updated': datetime.now().isoformat(),
                'items': [item.to_dict() for item in self._items.values()]
            }
            with open(self.database_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save quarantine database: {e}")

    def _generate_id(self, file_path: str) -> str:
        """Generate unique ID for quarantined item"""
        unique_str = f"{file_path}{datetime.now().isoformat()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:16]

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

    def _encrypt_file(self, src_path: str, dest_path: str) -> bool:
        """
        Simple XOR encryption for quarantine
        Note: This is basic obfuscation - real AV would use stronger encryption
        """
        try:
            key = b'SENTRY_QUARANTINE_KEY_2024'
            
            with open(src_path, 'rb') as f:
                data = f.read()
            
            # XOR encrypt
            encrypted = bytearray()
            for i, byte in enumerate(data):
                encrypted.append(byte ^ key[i % len(key)])
            
            # Write with header
            with open(dest_path, 'wb') as f:
                f.write(b'SENTRY_Q1')  # Magic header
                f.write(encrypted)
            
            return True
        except Exception as e:
            print(f"Encryption error: {e}")
            return False

    def _decrypt_file(self, src_path: str, dest_path: str) -> bool:
        """Decrypt a quarantined file"""
        try:
            key = b'SENTRY_QUARANTINE_KEY_2024'
            
            with open(src_path, 'rb') as f:
                header = f.read(9)
                if header != b'SENTRY_Q1':
                    return False
                data = f.read()
            
            # XOR decrypt
            decrypted = bytearray()
            for i, byte in enumerate(data):
                decrypted.append(byte ^ key[i % len(key)])
            
            with open(dest_path, 'wb') as f:
                f.write(decrypted)
            
            return True
        except Exception as e:
            print(f"Decryption error: {e}")
            return False

    def quarantine_file(self, file_path: str, scan_result: Optional[ScanResult] = None) -> Optional[QuarantinedItem]:
        """Move a file to quarantine"""
        if not os.path.exists(file_path):
            return None

        try:
            # Generate quarantine info
            item_id = self._generate_id(file_path)
            file_hash = self._calculate_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            # Create quarantine subdirectory by date
            date_folder = datetime.now().strftime("%Y-%m")
            quarantine_subdir = os.path.join(self.quarantine_dir, date_folder)
            os.makedirs(quarantine_subdir, exist_ok=True)
            
            # Quarantine file path
            quarantine_path = os.path.join(quarantine_subdir, f"{item_id}.quarantine")
            
            # Encrypt and move to quarantine
            if not self._encrypt_file(file_path, quarantine_path):
                return None
            
            # Delete original file
            try:
                os.remove(file_path)
            except PermissionError:
                # Try to remove read-only attribute
                os.chmod(file_path, 0o777)
                os.remove(file_path)

            # Create quarantine item
            item = QuarantinedItem(
                id=item_id,
                original_path=file_path,
                quarantine_path=quarantine_path,
                file_hash=file_hash,
                file_size=file_size,
                threat_name=scan_result.threat_name if scan_result else "Unknown Threat",
                threat_level=scan_result.threat_level.name if scan_result else "UNKNOWN",
                threat_description=scan_result.threat_description if scan_result else "",
                quarantine_date=datetime.now().isoformat(),
                detection_method=scan_result.detection_method if scan_result else "manual"
            )
            
            self._items[item_id] = item
            self._save_database()
            
            return item

        except Exception as e:
            print(f"Quarantine error: {e}")
            return None

    def restore_file(self, item_id: str, restore_path: Optional[str] = None) -> bool:
        """Restore a file from quarantine"""
        if item_id not in self._items:
            return False

        item = self._items[item_id]
        
        if not os.path.exists(item.quarantine_path):
            # Remove orphaned entry
            del self._items[item_id]
            self._save_database()
            return False

        try:
            # Determine restore path
            dest_path = restore_path or item.original_path
            
            # Ensure destination directory exists
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            
            # Decrypt and restore
            if not self._decrypt_file(item.quarantine_path, dest_path):
                return False
            
            # Remove quarantine file
            os.remove(item.quarantine_path)
            
            # Remove from database
            del self._items[item_id]
            self._save_database()
            
            return True

        except Exception as e:
            print(f"Restore error: {e}")
            return False

    def delete_permanently(self, item_id: str) -> bool:
        """Permanently delete a quarantined file"""
        if item_id not in self._items:
            return False

        item = self._items[item_id]

        try:
            # Delete quarantine file
            if os.path.exists(item.quarantine_path):
                os.remove(item.quarantine_path)
            
            # Remove from database
            del self._items[item_id]
            self._save_database()
            
            return True

        except Exception as e:
            print(f"Delete error: {e}")
            return False

    def get_all_items(self) -> List[QuarantinedItem]:
        """Get all quarantined items"""
        return list(self._items.values())

    def get_item(self, item_id: str) -> Optional[QuarantinedItem]:
        """Get a specific quarantined item"""
        return self._items.get(item_id)

    def get_item_count(self) -> int:
        """Get count of quarantined items"""
        return len(self._items)

    def get_total_size(self) -> int:
        """Get total size of quarantined files"""
        return sum(item.file_size for item in self._items.values())

    def clean_old_items(self, days: int = 30) -> int:
        """Delete quarantined items older than specified days"""
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=days)
        items_to_delete = []
        
        for item_id, item in self._items.items():
            try:
                item_date = datetime.fromisoformat(item.quarantine_date)
                if item_date < cutoff_date:
                    items_to_delete.append(item_id)
            except:
                continue
        
        deleted_count = 0
        for item_id in items_to_delete:
            if self.delete_permanently(item_id):
                deleted_count += 1
        
        return deleted_count

    def export_report(self, output_path: str) -> bool:
        """Export quarantine report to file"""
        try:
            report = {
                'generated': datetime.now().isoformat(),
                'total_items': len(self._items),
                'total_size_bytes': self.get_total_size(),
                'items': []
            }
            
            for item in self._items.values():
                report['items'].append({
                    'id': item.id,
                    'original_path': item.original_path,
                    'threat_name': item.threat_name,
                    'threat_level': item.threat_level,
                    'quarantine_date': item.quarantine_date,
                    'file_size': item.file_size,
                    'file_hash': item.file_hash
                })
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            return True

        except Exception as e:
            print(f"Export error: {e}")
            return False
