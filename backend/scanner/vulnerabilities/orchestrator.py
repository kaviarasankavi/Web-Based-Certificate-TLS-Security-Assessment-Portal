"""
Vulnerability Scanner Orchestrator

Coordinates all TLS vulnerability scanners and aggregates results.
Provides a single interface for running comprehensive vulnerability assessments.
"""

import logging
import concurrent.futures
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable
from enum import Enum

from .heartbleed import HeartbleedScanner
from .poodle import PoodleScanner
from .beast import BeastScanner
from .robot import RobotScanner
from .sweet32 import Sweet32Scanner
from .compression import CompressionScanner

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    UNKNOWN = "Unknown"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Convert string to Severity enum."""
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
        }
        return mapping.get(value.lower(), cls.UNKNOWN)


@dataclass
class VulnerabilityResult:
    """Individual vulnerability scan result."""

    name: str
    cve: str
    vulnerable: bool
    severity: Severity
    details: Optional[str] = None
    error: Optional[str] = None
    mitigation: Optional[str] = None
    raw_result: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "cve": self.cve,
            "vulnerable": self.vulnerable,
            "severity": self.severity.value,
            "details": self.details,
            "error": self.error,
            "mitigation": self.mitigation,
        }


@dataclass
class VulnerabilityScanResult:
    """Complete vulnerability scan results for a target."""

    hostname: str
    port: int
    scan_time_seconds: float = 0.0
    vulnerabilities: List[VulnerabilityResult] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        """Count of critical vulnerabilities found."""
        return sum(
            1
            for v in self.vulnerabilities
            if v.vulnerable and v.severity == Severity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        """Count of high severity vulnerabilities found."""
        return sum(
            1
            for v in self.vulnerabilities
            if v.vulnerable and v.severity == Severity.HIGH
        )

    @property
    def medium_count(self) -> int:
        """Count of medium severity vulnerabilities found."""
        return sum(
            1
            for v in self.vulnerabilities
            if v.vulnerable and v.severity == Severity.MEDIUM
        )

    @property
    def low_count(self) -> int:
        """Count of low severity vulnerabilities found."""
        return sum(
            1
            for v in self.vulnerabilities
            if v.vulnerable and v.severity == Severity.LOW
        )

    @property
    def total_vulnerabilities(self) -> int:
        """Total number of vulnerabilities found."""
        return sum(1 for v in self.vulnerabilities if v.vulnerable)

    @property
    def has_critical(self) -> bool:
        """Check if any critical vulnerabilities were found."""
        return self.critical_count > 0

    @property
    def vulnerability_score(self) -> int:
        """
        Calculate a vulnerability score (0-100).
        100 = no vulnerabilities, lower = more vulnerabilities.
        """
        if not self.vulnerabilities:
            return 100

        # Weight by severity
        penalty = (
            self.critical_count * 40
            + self.high_count * 25
            + self.medium_count * 15
            + self.low_count * 5
        )

        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        """Get letter grade based on vulnerability score."""
        score = self.vulnerability_score
        if self.critical_count > 0:
            return "F"
        if self.high_count > 0:
            return "D"
        if score >= 95:
            return "A+"
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "hostname": self.hostname,
            "port": self.port,
            "scan_time_seconds": self.scan_time_seconds,
            "vulnerability_score": self.vulnerability_score,
            "grade": self.grade,
            "summary": {
                "total_vulnerabilities": self.total_vulnerabilities,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


class VulnerabilityOrchestrator:
    """
    Coordinates all vulnerability scans for a target.

    Usage:
        orchestrator = VulnerabilityOrchestrator()
        result = orchestrator.scan("example.com")
        print(f"Found {result.total_vulnerabilities} vulnerabilities")
    """

    # Scanner registry: (name, scanner_class, default_enabled)
    SCANNER_REGISTRY = [
        ("Heartbleed", HeartbleedScanner, True),
        ("POODLE", PoodleScanner, True),
        ("BEAST", BeastScanner, True),
        ("ROBOT", RobotScanner, True),
        ("SWEET32", Sweet32Scanner, True),
        ("CRIME/BREACH", CompressionScanner, True),
    ]

    def __init__(
        self,
        timeout: int = 10,
        parallel: bool = True,
        max_workers: int = 6,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ):
        """
        Initialize the vulnerability orchestrator.

        Args:
            timeout: Timeout for each scanner in seconds
            parallel: Run scanners in parallel (faster but more connections)
            max_workers: Maximum concurrent scanners when parallel=True
            progress_callback: Optional callback(scanner_name, progress_pct)
        """
        self.timeout = timeout
        self.parallel = parallel
        self.max_workers = max_workers
        self.progress_callback = progress_callback

        # Initialize scanners
        self.scanners: List[tuple] = []
        for name, scanner_class, enabled in self.SCANNER_REGISTRY:
            if enabled:
                scanner = (
                    scanner_class(timeout=timeout)
                    if hasattr(scanner_class, "__init__")
                    else scanner_class()
                )
                if hasattr(scanner, "timeout"):
                    scanner.timeout = timeout
                self.scanners.append((name, scanner))

    def _run_scanner(
        self, name: str, scanner: Any, hostname: str, port: int
    ) -> VulnerabilityResult:
        """Run a single scanner and convert result."""
        try:
            raw_result = scanner.test(hostname, port)

            # Extract common fields
            vulnerable = raw_result.get("vulnerable", False)
            cve = raw_result.get("cve", "N/A")
            severity_str = raw_result.get("severity", "Unknown")
            severity = Severity.from_string(severity_str)
            details = raw_result.get("details")
            error = raw_result.get("error")
            mitigation = raw_result.get("mitigation")

            return VulnerabilityResult(
                name=name,
                cve=cve,
                vulnerable=vulnerable,
                severity=severity,
                details=details,
                error=error,
                mitigation=mitigation,
                raw_result=raw_result,
            )

        except Exception as e:
            logger.exception(f"Error running {name} scanner")
            return VulnerabilityResult(
                name=name,
                cve="N/A",
                vulnerable=False,
                severity=Severity.UNKNOWN,
                error=f"Scanner error: {str(e)}",
            )

    def scan(self, hostname: str, port: int = 443) -> VulnerabilityScanResult:
        """
        Run all vulnerability scans against a target.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            VulnerabilityScanResult with all findings
        """
        import time

        start_time = time.time()

        result = VulnerabilityScanResult(hostname=hostname, port=port)
        total_scanners = len(self.scanners)

        logger.info(
            f"Starting vulnerability scan of {hostname}:{port} with {total_scanners} scanners"
        )

        if self.parallel and total_scanners > 1:
            # Run scanners in parallel
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_workers
            ) as executor:
                future_to_scanner = {
                    executor.submit(
                        self._run_scanner, name, scanner, hostname, port
                    ): name
                    for name, scanner in self.scanners
                }

                completed = 0
                for future in concurrent.futures.as_completed(future_to_scanner):
                    scanner_name = future_to_scanner[future]
                    try:
                        vuln_result = future.result()
                        result.vulnerabilities.append(vuln_result)

                        if vuln_result.vulnerable:
                            logger.warning(f"VULNERABLE: {hostname} - {scanner_name}")

                    except Exception as e:
                        logger.error(f"Scanner {scanner_name} failed: {e}")
                        result.vulnerabilities.append(
                            VulnerabilityResult(
                                name=scanner_name,
                                cve="N/A",
                                vulnerable=False,
                                severity=Severity.UNKNOWN,
                                error=str(e),
                            )
                        )

                    completed += 1
                    if self.progress_callback:
                        progress = completed / total_scanners * 100
                        self.progress_callback(scanner_name, progress)
        else:
            # Run scanners sequentially
            for i, (name, scanner) in enumerate(self.scanners):
                vuln_result = self._run_scanner(name, scanner, hostname, port)
                result.vulnerabilities.append(vuln_result)

                if vuln_result.vulnerable:
                    logger.warning(f"VULNERABLE: {hostname} - {name}")

                if self.progress_callback:
                    progress = (i + 1) / total_scanners * 100
                    self.progress_callback(name, progress)

        result.scan_time_seconds = time.time() - start_time

        logger.info(
            f"Vulnerability scan complete: {hostname}:{port} - "
            f"Found {result.total_vulnerabilities} vulnerabilities "
            f"(Critical: {result.critical_count}, High: {result.high_count}, "
            f"Medium: {result.medium_count}) in {result.scan_time_seconds:.2f}s"
        )

        return result

    def scan_quick(self, hostname: str, port: int = 443) -> VulnerabilityScanResult:
        """
        Run a quick scan checking only critical vulnerabilities.

        Args:
            hostname: Target hostname
            port: Target port

        Returns:
            VulnerabilityScanResult with critical vulnerability findings only
        """
        # Only run critical vulnerability scanners
        critical_scanners = [
            ("Heartbleed", HeartbleedScanner(timeout=self.timeout)),
        ]

        original_scanners = self.scanners
        self.scanners = critical_scanners

        try:
            return self.scan(hostname, port)
        finally:
            self.scanners = original_scanners


# Convenience function for quick vulnerability check
def check_vulnerabilities(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Quick vulnerability check returning a simple dictionary.

    Args:
        hostname: Target hostname
        port: Target port

    Returns:
        Dictionary with vulnerability summary
    """
    orchestrator = VulnerabilityOrchestrator()
    result = orchestrator.scan(hostname, port)
    return result.to_dict()
