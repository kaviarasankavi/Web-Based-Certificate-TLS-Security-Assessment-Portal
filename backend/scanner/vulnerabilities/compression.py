"""
CRIME/BREACH Compression Attack Scanner

CRIME (CVE-2012-4929): TLS-level compression oracle attack
BREACH (CVE-2013-3587): HTTP-level compression oracle attack

Both attacks exploit compression to recover secrets (like CSRF tokens,
session IDs) from encrypted traffic by observing response sizes.

CRIME exploits TLS compression (now disabled in most implementations).
BREACH exploits HTTP compression (gzip/deflate) which is still common.

CRIME CVSS: 6.8 (Medium)
BREACH CVSS: 5.3 (Medium)

Mitigation:
- CRIME: Disable TLS compression (usually already done)
- BREACH: More complex - disable HTTP compression for sensitive pages,
  or use secret masking, or add random padding
"""

import socket
import ssl
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class CompressionScanner:
    """
    Tests for CRIME and BREACH vulnerabilities by checking:
    1. TLS compression (CRIME)
    2. HTTP compression (BREACH)

    CRIME is largely mitigated in modern TLS implementations.
    BREACH remains a concern where HTTP compression is used.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def _check_tls_compression(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check if TLS compression is enabled (CRIME vulnerability)."""
        result = {
            "compression_enabled": False,
            "compression_method": None,
            "error": None,
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Check compression
                compression = ssock.compression()
                if compression:
                    result["compression_enabled"] = True
                    result["compression_method"] = compression

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_http_compression(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check if HTTP compression is enabled (BREACH vulnerability)."""
        result = {
            "compression_enabled": False,
            "compression_types": [],
            "reflects_user_input": None,  # Would need deeper analysis
            "error": None,
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Send HTTP request with Accept-Encoding header
                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {hostname}\r\n"
                    f"Accept-Encoding: gzip, deflate, br\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                ssock.send(request.encode())

                # Read response headers
                response = b""
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        # Stop after headers
                        if b"\r\n\r\n" in response:
                            break
                    except socket.timeout:
                        break

                response_str = response.decode("utf-8", errors="ignore").lower()

                # Check for compression headers
                if "content-encoding: gzip" in response_str:
                    result["compression_enabled"] = True
                    result["compression_types"].append("gzip")
                if "content-encoding: deflate" in response_str:
                    result["compression_enabled"] = True
                    result["compression_types"].append("deflate")
                if "content-encoding: br" in response_str:
                    result["compression_enabled"] = True
                    result["compression_types"].append("brotli")

        except Exception as e:
            result["error"] = str(e)

        return result

    def test(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Test target for CRIME and BREACH vulnerabilities.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            Dictionary with vulnerability assessment results
        """
        result = {
            "crime_vulnerable": False,
            "breach_vulnerable": False,
            "tls_compression": False,
            "http_compression": False,
            "http_compression_types": [],
            "cve_crime": "CVE-2012-4929",
            "cve_breach": "CVE-2013-3587",
            "severity": "Medium",
            "error": None,
            "details": None,
            "mitigation_crime": "Disable TLS compression",
            "mitigation_breach": (
                "Disable HTTP compression for sensitive responses, "
                "or implement secret masking/random padding"
            ),
        }

        try:
            # Check TLS compression (CRIME)
            tls_result = self._check_tls_compression(hostname, port)

            if tls_result.get("compression_enabled"):
                result["crime_vulnerable"] = True
                result["tls_compression"] = True
                logger.warning(
                    f"CRIME VULNERABLE: {hostname} has TLS compression enabled: "
                    f"{tls_result.get('compression_method')}"
                )

            # Check HTTP compression (BREACH)
            http_result = self._check_http_compression(hostname, port)

            if http_result.get("compression_enabled"):
                result["breach_vulnerable"] = True  # Potentially
                result["http_compression"] = True
                result["http_compression_types"] = http_result.get(
                    "compression_types", []
                )

            # Build details message
            details_parts = []

            if result["crime_vulnerable"]:
                details_parts.append(
                    f"TLS compression is ENABLED (CRIME vulnerable). "
                    f"Method: {tls_result.get('compression_method', 'unknown')}"
                )
            else:
                details_parts.append(
                    "TLS compression is disabled (CRIME not vulnerable)"
                )

            if result["breach_vulnerable"]:
                compression_str = ", ".join(result["http_compression_types"])
                details_parts.append(
                    f"HTTP compression is ENABLED ({compression_str}). "
                    "This may indicate BREACH vulnerability if responses contain "
                    "secrets and reflect user input. Further analysis needed."
                )
            else:
                details_parts.append("HTTP compression not detected on homepage")

            result["details"] = " | ".join(details_parts)

            # Set overall vulnerability status
            if result["crime_vulnerable"]:
                result["severity"] = "High"  # CRIME is more serious
            elif result["breach_vulnerable"]:
                result["severity"] = "Medium"

        except socket.gaierror as e:
            result["error"] = f"DNS resolution failed: {str(e)}"
        except socket.timeout:
            result["error"] = f"Connection timed out after {self.timeout} seconds"
        except ConnectionRefusedError:
            result["error"] = f"Connection refused on port {port}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            logger.exception(f"Error testing {hostname} for CRIME/BREACH")

        return result


# Convenience functions
def check_crime(hostname: str, port: int = 443) -> bool:
    """Quick check if host is vulnerable to CRIME."""
    scanner = CompressionScanner()
    result = scanner.test(hostname, port)
    return result["crime_vulnerable"]


def check_breach(hostname: str, port: int = 443) -> bool:
    """Quick check if host potentially has BREACH vulnerability."""
    scanner = CompressionScanner()
    result = scanner.test(hostname, port)
    return result["breach_vulnerable"]
