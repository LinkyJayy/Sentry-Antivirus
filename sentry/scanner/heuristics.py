"""
Sentry Antivirus - Heuristic Analysis Engine
Always protects your stuff!
"""

import os
import re
import struct
from typing import Dict, Optional
from .types import ThreatLevel


class HeuristicAnalyzer:
    """
    Performs heuristic analysis on files to detect unknown threats
    
    Features:
    - PE header analysis
    - Entropy calculation
    - Suspicious string detection
    - Behavioral indicators
    """

    # Suspicious strings commonly found in malware
    SUSPICIOUS_STRINGS = [
        # Network-related
        (rb"(?i)http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Hardcoded IP address", 10),
        (rb"(?i)(tor2web|onion)", "Tor network reference", 15),
        
        # System manipulation
        (rb"(?i)(createremotethread|virtualallocex|writeprocessmemory)", "Process injection APIs", 25),
        (rb"(?i)(ntcreatethreadex|rtlcreateuserthread)", "Low-level thread creation", 20),
        (rb"(?i)setwindowshookex", "Keyboard/mouse hooking", 15),
        
        # Anti-analysis
        (rb"(?i)(isdebuggerpresent|checkremotedebuggerpresent)", "Anti-debugging", 20),
        (rb"(?i)(vmware|virtualbox|qemu|vbox)", "VM detection", 15),
        (rb"(?i)(sandboxie|wireshark|procmon|processmonitor)", "Analysis tool detection", 20),
        
        # Persistence
        (rb"(?i)schtasks.*/create", "Scheduled task creation", 15),
        (rb"(?i)(currentversion\\run|currentversion\\runonce)", "Registry run key", 15),
        
        # Data exfiltration
        (rb"(?i)(password|passwd|credential|login).*=", "Credential harvesting", 15),
        (rb"(?i)(credit.*card|ssn|social.*security)", "Sensitive data keywords", 10),
        
        # Crypto/ransomware
        (rb"(?i)(encrypt|decrypt|aes|rsa|cipher)", "Cryptographic operations", 10),
        (rb"(?i)(bitcoin|btc|monero|xmr|wallet)", "Cryptocurrency reference", 15),
        (rb"(?i)your\s*files?\s*(have\s*been|are)\s*encrypted", "Ransomware message", 30),
    ]

    # High entropy threshold (indicates packing/encryption)
    ENTROPY_THRESHOLD = 7.2

    def __init__(self):
        self.score_threshold = 50  # Minimum score to flag as suspicious

    def analyze(self, file_path: str, header: bytes) -> Dict:
        """Perform heuristic analysis on a file"""
        score = 0
        findings = []

        # Check file extension vs content
        ext_mismatch = self._check_extension_mismatch(file_path, header)
        if ext_mismatch:
            score += ext_mismatch['score']
            findings.append(ext_mismatch['finding'])

        # Check for PE file characteristics
        if self._is_pe_file(header):
            pe_analysis = self._analyze_pe(header)
            score += pe_analysis['score']
            findings.extend(pe_analysis['findings'])

        # Check entropy
        entropy = self._calculate_entropy(header)
        if entropy > self.ENTROPY_THRESHOLD:
            score += 20
            findings.append(f"High entropy ({entropy:.2f}) - possible packing/encryption")

        # Check for suspicious strings
        string_analysis = self._check_suspicious_strings(header)
        score += string_analysis['score']
        findings.extend(string_analysis['findings'])

        # Check for script-based threats
        script_analysis = self._check_script_threats(header, file_path)
        score += script_analysis['score']
        findings.extend(script_analysis['findings'])

        # Determine threat level based on score
        if score >= 80:
            level = ThreatLevel.CRITICAL
        elif score >= 60:
            level = ThreatLevel.HIGH
        elif score >= 40:
            level = ThreatLevel.MEDIUM
        elif score >= 20:
            level = ThreatLevel.LOW
        else:
            level = ThreatLevel.CLEAN

        return {
            'is_suspicious': score >= self.score_threshold,
            'score': score,
            'level': level,
            'name': f"Heuristic.Suspicious.Gen" if score >= self.score_threshold else None,
            'description': "; ".join(findings) if findings else "No suspicious indicators",
            'findings': findings
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        data_len = len(data)
        byte_counts = [0] * 256
        
        for byte in data:
            byte_counts[byte] += 1
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability and __import__('math').log2(probability))
        
        return entropy

    def _is_pe_file(self, header: bytes) -> bool:
        """Check if file is a PE (Portable Executable)"""
        if len(header) < 64:
            return False
        
        # Check for MZ header
        if header[:2] != b'MZ':
            return False
        
        try:
            # Get PE header offset
            pe_offset = struct.unpack('<I', header[60:64])[0]
            if pe_offset + 4 > len(header):
                return False
            
            # Check for PE signature
            return header[pe_offset:pe_offset+4] == b'PE\x00\x00'
        except:
            return False

    def _analyze_pe(self, header: bytes) -> Dict:
        """Analyze PE file characteristics"""
        score = 0
        findings = []

        try:
            pe_offset = struct.unpack('<I', header[60:64])[0]
            
            if pe_offset + 24 <= len(header):
                # Check characteristics
                characteristics = struct.unpack('<H', header[pe_offset+22:pe_offset+24])[0]
                
                # Check for DLL
                if characteristics & 0x2000:
                    findings.append("DLL file detected")
                
                # Check if no relocation (common in packed malware)
                if characteristics & 0x0001:
                    score += 10
                    findings.append("No relocation info (common in packed malware)")

            # Check for suspicious section names
            suspicious_sections = [b'.UPX', b'.aspack', b'.adata', b'UPX0', b'UPX1', b'.nsp']
            for section in suspicious_sections:
                if section in header:
                    score += 15
                    findings.append(f"Suspicious section name: {section.decode('utf-8', errors='ignore')}")

            # Check for overlay data (common in packed/crypted malware)
            if b'This program cannot be run in DOS mode' in header:
                pass  # Normal PE
            elif b'MZ' in header[512:]:
                score += 10
                findings.append("Possible embedded executable")

        except Exception:
            pass

        return {'score': score, 'findings': findings}

    def _check_extension_mismatch(self, file_path: str, header: bytes) -> Optional[Dict]:
        """Check if file extension matches actual content"""
        ext = os.path.splitext(file_path)[1].lower()
        
        # Define expected magic bytes for common extensions
        magic_bytes = {
            '.exe': [b'MZ'],
            '.dll': [b'MZ'],
            '.pdf': [b'%PDF'],
            '.zip': [b'PK\x03\x04', b'PK\x05\x06'],
            '.rar': [b'Rar!'],
            '.7z': [b'7z\xbc\xaf\x27\x1c'],
            '.png': [b'\x89PNG'],
            '.jpg': [b'\xff\xd8\xff'],
            '.gif': [b'GIF87a', b'GIF89a'],
            '.doc': [b'\xd0\xcf\x11\xe0'],
            '.docx': [b'PK\x03\x04'],
        }

        if ext in magic_bytes:
            expected = magic_bytes[ext]
            matches = any(header.startswith(m) for m in expected)
            
            if not matches and len(header) > 2:
                # Check if it's actually an executable disguised as something else
                if header[:2] == b'MZ' and ext not in ['.exe', '.dll', '.scr', '.com']:
                    return {
                        'score': 30,
                        'finding': f"Executable disguised as {ext} file"
                    }
                elif ext in ['.exe', '.dll'] and header[:2] != b'MZ':
                    return {
                        'score': 15,
                        'finding': f"File extension mismatch - not a valid {ext}"
                    }
        
        return None

    def _check_suspicious_strings(self, data: bytes) -> Dict:
        """Check for suspicious strings in file content"""
        score = 0
        findings = []

        for pattern, description, points in self.SUSPICIOUS_STRINGS:
            try:
                if re.search(pattern, data):
                    score += points
                    findings.append(description)
            except:
                continue

        return {'score': score, 'findings': findings}

    def _check_script_threats(self, header: bytes, file_path: str) -> Dict:
        """Check for script-based threats"""
        score = 0
        findings = []
        ext = os.path.splitext(file_path)[1].lower()

        # PowerShell scripts
        if ext in ['.ps1', '.psm1', '.psd1'] or b'powershell' in header.lower():
            # Check for encoded commands
            if re.search(rb'(?i)-e(nc(odedcommand)?)?', header):
                score += 20
                findings.append("Encoded PowerShell command")
            
            # Check for download and execute
            if re.search(rb'(?i)(downloadstring|downloadfile|invoke-expression|iex)', header):
                score += 25
                findings.append("Download and execute pattern")
            
            # Check for bypass attempts
            if re.search(rb'(?i)(bypass|unrestricted|hidden)', header):
                score += 15
                findings.append("Execution policy bypass attempt")

        # Batch/CMD scripts
        if ext in ['.bat', '.cmd']:
            # Check for obfuscation
            if header.count(b'^') > 10:
                score += 15
                findings.append("Heavy caret obfuscation in batch file")
            
            # Check for variable substitution obfuscation
            if re.search(rb'%[^%]+:~\d+,\d+%', header):
                score += 15
                findings.append("Variable substring obfuscation")

        # VBScript
        if ext in ['.vbs', '.vbe']:
            if re.search(rb'(?i)(wscript\.shell|createobject|execute)', header):
                score += 15
                findings.append("Script execution via WScript")

        # JavaScript
        if ext in ['.js', '.jse']:
            if re.search(rb'(?i)(eval\s*\(|new\s+function|activexobject)', header):
                score += 15
                findings.append("Dynamic code execution in JavaScript")

        return {'score': score, 'findings': findings}

    def set_threshold(self, threshold: int):
        """Set the score threshold for suspicious detection"""
        self.score_threshold = threshold
