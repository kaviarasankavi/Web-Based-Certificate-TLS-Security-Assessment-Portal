"""
TLS Vulnerability Scanners Module

This module contains scanners for detecting real TLS/SSL vulnerabilities:
- Heartbleed (CVE-2014-0160)
- POODLE (CVE-2014-3566)
- BEAST (CVE-2011-3389)
- ROBOT (CVE-2017-13099)
- SWEET32 (CVE-2016-2183)
- CRIME/BREACH compression attacks

Each scanner tests for actual exploitable conditions, not just configuration issues.
"""

from .heartbleed import HeartbleedScanner
from .poodle import PoodleScanner
from .beast import BeastScanner
from .robot import RobotScanner
from .sweet32 import Sweet32Scanner
from .compression import CompressionScanner
from .orchestrator import (
    VulnerabilityOrchestrator,
    VulnerabilityScanResult,
    VulnerabilityResult,
)

__all__ = [
    "HeartbleedScanner",
    "PoodleScanner",
    "BeastScanner",
    "RobotScanner",
    "Sweet32Scanner",
    "CompressionScanner",
    "VulnerabilityOrchestrator",
    "VulnerabilityScanResult",
    "VulnerabilityResult",
]
