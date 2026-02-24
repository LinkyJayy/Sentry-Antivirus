"""
Sentry Antivirus - Virus Signature Database
Always protects your stuff!
"""

import os
import re
import yaml
from pathlib import Path
from typing import Dict, Optional, List
from .types import ThreatLevel


class SignatureDatabase:
    """
    Manages virus signatures for detection
    
    Features:
    - Hash-based signatures (SHA256)
    - Pattern-based signatures (byte patterns)
    - YARA-like rule matching
    - Signature updates
    """

    # Known malicious file hashes (SHA256)
    # These are example/test signatures - real AV would have millions
    KNOWN_HASHES: Dict[str, Dict] = {
        # EICAR test file hash
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
            "name": "EICAR-Test-File",
            "level": ThreatLevel.LOW,
            "description": "EICAR antivirus test file - not a real threat"
        },
        # Example malware hashes (fictional for demonstration)
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "name": "Empty.File.Suspicion",
            "level": ThreatLevel.LOW,
            "description": "Empty file - commonly used as placeholder by malware"
        },
    }

    # Byte patterns to detect (simplified YARA-like rules)
    MALICIOUS_PATTERNS: List[Dict] = [
        {
            "name": "EICAR-Test-Pattern",
            "pattern": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
            "level": ThreatLevel.LOW,
            "description": "EICAR standard antivirus test pattern"
        },
        {
            "name": "Suspicious.PowerShell.Download",
            "pattern": rb"(?i)(invoke-webrequest|wget|curl).*(-outfile|-o)\s*[\"']?[\w:\\/.]+\.exe",
            "is_regex": True,
            "level": ThreatLevel.MEDIUM,
            "description": "PowerShell script downloading executable files"
        },
        {
            "name": "Suspicious.Base64.Payload",
            "pattern": rb"(?i)powershell.*-e(nc(odedcommand)?)?.*[A-Za-z0-9+/=]{100,}",
            "is_regex": True,
            "level": ThreatLevel.HIGH,
            "description": "Encoded PowerShell command - possible obfuscated malware"
        },
        {
            "name": "Suspicious.Registry.Run",
            "pattern": rb"(?i)reg\s+add.*\\(run|runonce)",
            "is_regex": True,
            "level": ThreatLevel.MEDIUM,
            "description": "Attempts to add registry run key for persistence"
        },
        {
            "name": "Suspicious.Disable.Security",
            "pattern": rb"(?i)(disable|stop).*windows\s*(defender|firewall|security)",
            "is_regex": True,
            "level": ThreatLevel.HIGH,
            "description": "Attempts to disable Windows security features"
        },
        {
            "name": "Suspicious.Shadow.Delete",
            "pattern": rb"(?i)vssadmin.*delete\s*shadows",
            "is_regex": True,
            "level": ThreatLevel.CRITICAL,
            "description": "Volume shadow copy deletion - ransomware indicator"
        },
        {
            "name": "Suspicious.BCDEdit.NoRecovery",
            "pattern": rb"(?i)bcdedit.*/set.*recoveryenabled.*no",
            "is_regex": True,
            "level": ThreatLevel.CRITICAL,
            "description": "Disabling recovery mode - ransomware indicator"
        },
        {
            "name": "Trojan.Generic.Shellcode",
            "pattern": b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5",
            "level": ThreatLevel.CRITICAL,
            "description": "Common shellcode pattern detected"
        },
        {
            "name": "Suspicious.Mimikatz.Strings",
            "pattern": rb"(?i)(sekurlsa|kerberos|wdigest|logonpasswords)",
            "is_regex": True,
            "level": ThreatLevel.CRITICAL,
            "description": "Mimikatz-related strings detected - credential theft tool"
        },
        {
            "name": "Suspicious.Keylogger.Pattern",
            "pattern": rb"(?i)(getkeystate|getasynckeystate|setwindowshook).*log",
            "is_regex": True,
            "level": ThreatLevel.HIGH,
            "description": "Potential keylogger activity detected"
        },
    ]

    def __init__(self, signatures_path: Optional[str] = None):
        self.signatures_path = signatures_path
        self.custom_hashes: Dict[str, Dict] = {}
        self.custom_patterns: List[Dict] = []
        
        # Load custom signatures if path provided
        if signatures_path and os.path.exists(signatures_path):
            self._load_custom_signatures(signatures_path)

    def _load_custom_signatures(self, path: str):
        """Load custom signatures from YAML file"""
        try:
            with open(path, 'r') as f:
                data = yaml.safe_load(f)
                
            if 'hashes' in data:
                for hash_sig in data['hashes']:
                    self.custom_hashes[hash_sig['hash']] = {
                        'name': hash_sig['name'],
                        'level': ThreatLevel[hash_sig['level'].upper()],
                        'description': hash_sig.get('description', 'Custom signature detection')
                    }
                    
            if 'patterns' in data:
                for pattern_sig in data['patterns']:
                    self.custom_patterns.append({
                        'name': pattern_sig['name'],
                        'pattern': pattern_sig['pattern'].encode() if isinstance(pattern_sig['pattern'], str) else pattern_sig['pattern'],
                        'is_regex': pattern_sig.get('is_regex', False),
                        'level': ThreatLevel[pattern_sig['level'].upper()],
                        'description': pattern_sig.get('description', 'Custom pattern detection')
                    })
        except Exception as e:
            print(f"Warning: Could not load custom signatures: {e}")

    def check_hash(self, file_hash: str) -> Optional[Dict]:
        """Check if a file hash matches known malware"""
        file_hash = file_hash.lower()
        
        # Check built-in signatures
        if file_hash in self.KNOWN_HASHES:
            return self.KNOWN_HASHES[file_hash]
        
        # Check custom signatures
        if file_hash in self.custom_hashes:
            return self.custom_hashes[file_hash]
        
        return None

    def check_patterns(self, data: bytes) -> Optional[Dict]:
        """Check if data contains known malicious patterns"""
        # Check built-in patterns
        for pattern_info in self.MALICIOUS_PATTERNS:
            try:
                if pattern_info.get('is_regex', False):
                    if re.search(pattern_info['pattern'], data):
                        return {
                            'name': pattern_info['name'],
                            'level': pattern_info['level'],
                            'description': pattern_info['description']
                        }
                else:
                    if pattern_info['pattern'] in data:
                        return {
                            'name': pattern_info['name'],
                            'level': pattern_info['level'],
                            'description': pattern_info['description']
                        }
            except Exception:
                continue
        
        # Check custom patterns
        for pattern_info in self.custom_patterns:
            try:
                if pattern_info.get('is_regex', False):
                    if re.search(pattern_info['pattern'], data):
                        return {
                            'name': pattern_info['name'],
                            'level': pattern_info['level'],
                            'description': pattern_info['description']
                        }
                else:
                    if pattern_info['pattern'] in data:
                        return {
                            'name': pattern_info['name'],
                            'level': pattern_info['level'],
                            'description': pattern_info['description']
                        }
            except Exception:
                continue
        
        return None

    def add_hash_signature(self, file_hash: str, name: str, level: ThreatLevel, description: str = ""):
        """Add a custom hash signature"""
        self.custom_hashes[file_hash.lower()] = {
            'name': name,
            'level': level,
            'description': description
        }

    def add_pattern_signature(self, pattern: bytes, name: str, level: ThreatLevel, 
                             description: str = "", is_regex: bool = False):
        """Add a custom pattern signature"""
        self.custom_patterns.append({
            'name': name,
            'pattern': pattern,
            'is_regex': is_regex,
            'level': level,
            'description': description
        })

    def save_signatures(self, path: str):
        """Save custom signatures to YAML file"""
        data = {
            'hashes': [
                {
                    'hash': h,
                    'name': info['name'],
                    'level': info['level'].name,
                    'description': info['description']
                }
                for h, info in self.custom_hashes.items()
            ],
            'patterns': [
                {
                    'name': p['name'],
                    'pattern': p['pattern'].decode('utf-8', errors='ignore'),
                    'is_regex': p.get('is_regex', False),
                    'level': p['level'].name,
                    'description': p['description']
                }
                for p in self.custom_patterns
            ]
        }
        
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)

    def get_signature_count(self) -> Dict[str, int]:
        """Get count of loaded signatures"""
        return {
            'hash_signatures': len(self.KNOWN_HASHES) + len(self.custom_hashes),
            'pattern_signatures': len(self.MALICIOUS_PATTERNS) + len(self.custom_patterns),
            'total': (len(self.KNOWN_HASHES) + len(self.custom_hashes) + 
                     len(self.MALICIOUS_PATTERNS) + len(self.custom_patterns))
        }
