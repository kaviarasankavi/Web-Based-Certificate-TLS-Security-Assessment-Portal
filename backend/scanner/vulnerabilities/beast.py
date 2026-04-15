"""
BEAST Vulnerability Scanner (CVE-2011-3389)

BEAST (Browser Exploit Against SSL/TLS) is an attack against TLS 1.0 when
using CBC cipher suites. It exploits a predictable IV (Initialization Vector)
weakness in the CBC mode implementation.

The attack allows an attacker in a MITM position to decrypt portions of
HTTPS traffic, particularly session cookies.

Note: Modern browsers implement client-side mitigations (1/n-1 record splitting),
but server-side the vulnerability remains if TLS 1.0 + CBC is supported.

CVSS Score: 4.3 (Medium)
Affected: TLS 1.0 with CBC cipher suites
Mitigation: Disable TLS 1.0, or use only AEAD ciphers (GCM)
"""

import socket
import ssl
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class BeastScanner:
    """
    Tests for BEAST vulnerability by checking if the server
    supports TLS 1.0 with CBC cipher suites.

    While client-side mitigations exist in modern browsers,
    servers should still disable TLS 1.0 or CBC ciphers.
    """

    # CBC cipher suites vulnerable to BEAST when used with TLS 1.0
    CBC_CIPHERS = [
        "AES256-SHA",
        "AES128-SHA",
        "DES-CBC3-SHA",
        "ECDHE-RSA-AES256-SHA",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-ECDSA-AES256-SHA",
        "ECDHE-ECDSA-AES128-SHA",
        "DHE-RSA-AES256-SHA",
        "DHE-RSA-AES128-SHA",
        "DHE-DSS-AES256-SHA",
        "DHE-DSS-AES128-SHA",
        "ECDH-RSA-AES256-SHA",
        "ECDH-RSA-AES128-SHA",
        "ECDH-ECDSA-AES256-SHA",
        "ECDH-ECDSA-AES128-SHA",
        "CAMELLIA256-SHA",
        "CAMELLIA128-SHA",
        "SEED-SHA",
    ]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def _check_tls10_support(self, hostname: str, port: int) -> bool:
        """Check if server supports TLS 1.0."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.maximum_version = ssl.TLSVersion.TLSv1
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                return ssock.version() == "TLSv1"

        except ssl.SSLError:
            return False
        except Exception:
            return False

    def _check_cbc_cipher(self, hostname: str, port: int, cipher: str) -> bool:
        """Check if a specific CBC cipher is supported on TLS 1.0."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            context.maximum_version = ssl.TLSVersion.TLSv1
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                context.set_ciphers(cipher)
            except ssl.SSLError:
                # Cipher not supported by this OpenSSL version
                return False

            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                negotiated = ssock.cipher()
                if negotiated:
                    return True

        except ssl.SSLError:
            return False
        except Exception:
            return False

        return False

    def test(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Test target for BEAST vulnerability.

        Server is vulnerable if it supports TLS 1.0 with CBC cipher suites.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            Dictionary with vulnerability assessment results
        """
        result = {
            "vulnerable": False,
            "tls10_supported": False,
            "cbc_ciphers_supported": [],
            "cve": "CVE-2011-3389",
            "severity": "Medium",
            "error": None,
            "details": None,
            "mitigation": "Disable TLS 1.0 or use only AEAD cipher suites (GCM)",
        }

        try:
            # First check if TLS 1.0 is supported at all
            result["tls10_supported"] = self._check_tls10_support(hostname, port)

            if not result["tls10_supported"]:
                result["details"] = "TLS 1.0 not supported (server is not vulnerable)"
                return result

            # TLS 1.0 is supported - now check for CBC ciphers
            logger.debug(f"TLS 1.0 supported on {hostname}, checking CBC ciphers...")

            for cipher in self.CBC_CIPHERS:
                if self._check_cbc_cipher(hostname, port, cipher):
                    result["cbc_ciphers_supported"].append(cipher)
                    # Found at least one - we can stop here for efficiency
                    # or continue to get full list
                    if len(result["cbc_ciphers_supported"]) >= 3:
                        # Found enough evidence
                        break

            if result["cbc_ciphers_supported"]:
                result["vulnerable"] = True
                result["details"] = (
                    f"Server supports TLS 1.0 with {len(result['cbc_ciphers_supported'])} "
                    f"CBC cipher(s): {', '.join(result['cbc_ciphers_supported'][:3])}. "
                    "This combination is vulnerable to BEAST attacks. "
                    "Modern browsers mitigate this client-side, but server should still "
                    "disable TLS 1.0 for defense in depth."
                )
                logger.warning(
                    f"BEAST VULNERABLE: {hostname} supports TLS 1.0 with CBC ciphers"
                )
            else:
                result["details"] = (
                    "TLS 1.0 is supported but no CBC ciphers detected. "
                    "Server is not vulnerable to BEAST, but TLS 1.0 should still be disabled."
                )

        except socket.gaierror as e:
            result["error"] = f"DNS resolution failed: {str(e)}"
        except socket.timeout:
            result["error"] = f"Connection timed out after {self.timeout} seconds"
        except ConnectionRefusedError:
            result["error"] = f"Connection refused on port {port}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            logger.exception(f"Error testing {hostname} for BEAST")

        return result


# Convenience function
def check_beast(hostname: str, port: int = 443) -> bool:
    """Quick check if host is vulnerable to BEAST."""
    scanner = BeastScanner()
    result = scanner.test(hostname, port)
    return result["vulnerable"]
