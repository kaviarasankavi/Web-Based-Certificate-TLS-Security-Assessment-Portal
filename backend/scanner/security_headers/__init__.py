"""
Security Headers Analyzer

Analyzes HTTP security headers based on OWASP recommendations.
Checks for presence and proper configuration of:
- HSTS (HTTP Strict Transport Security)
- CSP (Content Security Policy)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- And more...

Provides security scores and recommendations for missing/misconfigured headers.
"""

import logging
import ssl
import socket
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class HeaderCheck:
    """Individual security header check result."""

    header_name: str
    present: bool
    value: Optional[str] = None
    score: int = 0  # 0-100
    severity: str = "Info"  # Critical, High, Medium, Low, Info
    recommendation: Optional[str] = None
    details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "header": self.header_name,
            "present": self.present,
            "value": self.value,
            "score": self.score,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "details": self.details,
        }


@dataclass
class SecurityHeadersResult:
    """Complete security headers analysis result."""

    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    checks: List[HeaderCheck] = field(default_factory=list)
    overall_score: int = 0
    grade: str = "F"
    error: Optional[str] = None

    @property
    def missing_headers(self) -> List[str]:
        """Get list of missing security headers."""
        return [check.header_name for check in self.checks if not check.present]

    @property
    def critical_issues(self) -> int:
        """Count of critical security issues."""
        return sum(
            1
            for check in self.checks
            if check.severity == "Critical" and not check.present
        )

    @property
    def high_issues(self) -> int:
        """Count of high severity issues."""
        return sum(
            1 for check in self.checks if check.severity == "High" and not check.present
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "overall_score": self.overall_score,
            "grade": self.grade,
            "missing_headers": self.missing_headers,
            "critical_issues": self.critical_issues,
            "high_issues": self.high_issues,
            "checks": [c.to_dict() for c in self.checks],
            "error": self.error,
        }


class SecurityHeadersAnalyzer:
    """
    Analyzes HTTP security headers for a website.

    Based on OWASP Secure Headers Project recommendations.
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize analyzer.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout

    def _fetch_headers(
        self, hostname: str, port: int = 443, use_ssl: bool = True
    ) -> Dict[str, str]:
        """
        Fetch HTTP headers from a server.

        Args:
            hostname: Target hostname
            port: Target port
            use_ssl: Use HTTPS connection

        Returns:
            Dictionary of response headers
        """
        headers = {}

        try:
            # Create socket connection
            sock = socket.create_connection((hostname, port), timeout=self.timeout)

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=hostname)

            # Send HTTP request
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: TLS-Security-Assessment-Tool/1.0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            )
            sock.send(request.encode())

            # Read response
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    # Stop after headers (before body)
                    if b"\r\n\r\n" in response:
                        break
                except socket.timeout:
                    break

            sock.close()

            # Parse headers
            response_str = response.decode("utf-8", errors="ignore")
            lines = response_str.split("\r\n")

            for line in lines[1:]:  # Skip status line
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()

        except Exception as e:
            logger.error(f"Error fetching headers from {hostname}: {e}")

        return headers

    def _check_hsts(self, headers: Dict[str, str]) -> HeaderCheck:
        """Check HTTP Strict Transport Security header."""
        header_name = "Strict-Transport-Security"
        header_key = "strict-transport-security"

        if header_key not in headers:
            return HeaderCheck(
                header_name=header_name,
                present=False,
                score=0,
                severity="High",
                recommendation="Add Strict-Transport-Security header with max-age >= 31536000",
                details="HSTS forces browsers to use HTTPS, preventing protocol downgrade attacks.",
            )

        value = headers[header_key]
        score = 50  # Base score for presence

        # Check max-age
        if "max-age=" in value:
            try:
                max_age = int(value.split("max-age=")[1].split(";")[0].strip())
                if max_age >= 31536000:  # 1 year
                    score += 30
                elif max_age >= 15552000:  # 6 months
                    score += 20
                else:
                    score += 10
            except:
                pass

        # Check includeSubDomains
        if "includesubdomains" in value.lower():
            score += 10

        # Check preload
        if "preload" in value.lower():
            score += 10

        details = f"max-age should be >= 31536000 (1 year). "
        if "includesubdomains" not in value.lower():
            details += "Consider adding includeSubDomains. "
        if "preload" not in value.lower():
            details += "Consider adding preload."

        return HeaderCheck(
            header_name=header_name,
            present=True,
            value=value,
            score=score,
            severity="Info" if score >= 90 else "Medium",
            recommendation=details if score < 90 else None,
            details="HSTS is properly configured." if score >= 90 else details,
        )

    def _check_csp(self, headers: Dict[str, str]) -> HeaderCheck:
        """Check Content Security Policy header."""
        header_name = "Content-Security-Policy"
        header_key = "content-security-policy"

        if header_key not in headers:
            return HeaderCheck(
                header_name=header_name,
                present=False,
                score=0,
                severity="High",
                recommendation="Add Content-Security-Policy header to prevent XSS attacks",
                details="CSP helps prevent XSS, clickjacking, and other code injection attacks.",
            )

        value = headers[header_key]
        score = 60  # Base score

        # Check for unsafe directives
        if "unsafe-inline" in value:
            score -= 20
        if "unsafe-eval" in value:
            score -= 15
        if "*" in value and "default-src" in value:
            score -= 10

        # Bonus for strict policy
        if "default-src" in value and "'self'" in value:
            score += 20

        return HeaderCheck(
            header_name=header_name,
            present=True,
            value=value[:100] + "..." if len(value) > 100 else value,
            score=max(0, score),
            severity="Info" if score >= 70 else "Medium",
            recommendation="Avoid 'unsafe-inline' and 'unsafe-eval' if possible"
            if score < 70
            else None,
            details="CSP is configured.",
        )

    def _check_x_frame_options(self, headers: Dict[str, str]) -> HeaderCheck:
        """Check X-Frame-Options header."""
        header_name = "X-Frame-Options"
        header_key = "x-frame-options"

        if header_key not in headers:
            return HeaderCheck(
                header_name=header_name,
                present=False,
                score=0,
                severity="Medium",
                recommendation="Add X-Frame-Options: DENY or SAMEORIGIN",
                details="Prevents clickjacking attacks by controlling if site can be framed.",
            )

        value = headers[header_key]
        score = 100 if value.upper() in ["DENY", "SAMEORIGIN"] else 70

        return HeaderCheck(
            header_name=header_name,
            present=True,
            value=value,
            score=score,
            severity="Info",
            details=f"Set to {value}",
        )

    def _check_x_content_type_options(self, headers: Dict[str, str]) -> HeaderCheck:
        """Check X-Content-Type-Options header."""
        header_name = "X-Content-Type-Options"
        header_key = "x-content-type-options"

        if header_key not in headers:
            return HeaderCheck(
                header_name=header_name,
                present=False,
                score=0,
                severity="Low",
                recommendation="Add X-Content-Type-Options: nosniff",
                details="Prevents MIME-type sniffing attacks.",
            )

        value = headers[header_key]
        score = 100 if value.lower() == "nosniff" else 70

        return HeaderCheck(
            header_name=header_name,
            present=True,
            value=value,
            score=score,
            severity="Info",
            details="Properly configured to prevent MIME sniffing.",
        )

    def _check_referrer_policy(self, headers: Dict[str, str]) -> HeaderCheck:
        """Check Referrer-Policy header."""
        header_name = "Referrer-Policy"
        header_key = "referrer-policy"

        if header_key not in headers:
            return HeaderCheck(
                header_name=header_name,
                present=False,
                score=0,
                severity="Low",
                recommendation="Add Referrer-Policy header (e.g., no-referrer or strict-origin-when-cross-origin)",
                details="Controls how much referrer information is sent with requests.",
            )

        value = headers[header_key]

        # Preferred policies
        good_policies = [
            "no-referrer",
            "strict-origin",
            "strict-origin-when-cross-origin",
        ]
        score = 100 if value.lower() in good_policies else 70

        return HeaderCheck(
            header_name=header_name,
            present=True,
            value=value,
            score=score,
            severity="Info",
            details=f"Set to {value}",
        )

    def _check_permissions_policy(self, headers: Dict[str, str]) -> HeaderCheck:
        """Check Permissions-Policy header."""
        header_name = "Permissions-Policy"
        header_key = "permissions-policy"

        # Also check for deprecated Feature-Policy
        if header_key not in headers and "feature-policy" in headers:
            header_key = "feature-policy"
            header_name = "Feature-Policy (deprecated)"

        if header_key not in headers:
            return HeaderCheck(
                header_name=header_name,
                present=False,
                score=0,
                severity="Low",
                recommendation="Consider adding Permissions-Policy to control browser features",
                details="Controls which browser features can be used (camera, microphone, geolocation, etc.)",
            )

        value = headers[header_key]

        return HeaderCheck(
            header_name=header_name,
            present=True,
            value=value[:100] + "..." if len(value) > 100 else value,
            score=100,
            severity="Info",
            details="Permissions policy is configured.",
        )

    def _check_x_xss_protection(self, headers: Dict[str, str]) -> HeaderCheck:
        """Check X-XSS-Protection header (deprecated but still checked)."""
        header_name = "X-XSS-Protection"
        header_key = "x-xss-protection"

        if header_key not in headers:
            return HeaderCheck(
                header_name=header_name,
                present=False,
                score=0,
                severity="Info",
                recommendation="Header is deprecated but can add X-XSS-Protection: 0 (or use CSP instead)",
                details="Deprecated header, modern browsers rely on CSP.",
            )

        value = headers[header_key]
        # Modern recommendation is to set to "0" to disable legacy XSS filter
        score = 100 if value == "0" else 70

        return HeaderCheck(
            header_name=header_name,
            present=True,
            value=value,
            score=score,
            severity="Info",
            details="Present (header is deprecated, CSP is preferred).",
        )

    def analyze(self, hostname: str, port: int = 443) -> SecurityHeadersResult:
        """
        Analyze security headers for a hostname.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            SecurityHeadersResult with analysis
        """
        url = (
            f"https://{hostname}:{port}"
            if port == 443
            else f"https://{hostname}:{port}"
        )
        result = SecurityHeadersResult(url=url)

        try:
            # Fetch headers
            logger.info(f"Fetching security headers from {hostname}:{port}")
            result.headers = self._fetch_headers(hostname, port, use_ssl=(port == 443))

            if not result.headers:
                result.error = "Failed to fetch headers"
                return result

            # Run all checks
            result.checks.append(self._check_hsts(result.headers))
            result.checks.append(self._check_csp(result.headers))
            result.checks.append(self._check_x_frame_options(result.headers))
            result.checks.append(self._check_x_content_type_options(result.headers))
            result.checks.append(self._check_referrer_policy(result.headers))
            result.checks.append(self._check_permissions_policy(result.headers))
            result.checks.append(self._check_x_xss_protection(result.headers))

            # Calculate overall score (weighted average)
            weights = {
                "Strict-Transport-Security": 3.0,
                "Content-Security-Policy": 3.0,
                "X-Frame-Options": 2.0,
                "X-Content-Type-Options": 1.5,
                "Referrer-Policy": 1.0,
                "Permissions-Policy": 1.0,
                "X-XSS-Protection": 0.5,
            }

            total_weight = sum(weights.values())
            weighted_score = sum(
                check.score * weights.get(check.header_name, 1.0)
                for check in result.checks
            )

            result.overall_score = int(weighted_score / total_weight)

            # Assign grade
            if result.overall_score >= 90:
                result.grade = "A"
            elif result.overall_score >= 80:
                result.grade = "B"
            elif result.overall_score >= 70:
                result.grade = "C"
            elif result.overall_score >= 60:
                result.grade = "D"
            else:
                result.grade = "F"

            logger.info(
                f"Security headers analysis complete for {hostname}: "
                f"Score {result.overall_score}/100, Grade {result.grade}"
            )

        except Exception as e:
            result.error = f"Analysis error: {str(e)}"
            logger.exception(f"Error analyzing security headers for {hostname}")

        return result


# Convenience function
def check_security_headers(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Quick check of security headers.

    Args:
        hostname: Target hostname
        port: Target port

    Returns:
        Dictionary with security headers analysis
    """
    analyzer = SecurityHeadersAnalyzer()
    result = analyzer.analyze(hostname, port)
    return result.to_dict()
