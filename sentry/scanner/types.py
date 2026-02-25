"""
Sentry Antivirus - Scanner Types
Always protects your computer!
"""

from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    CLEAN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
