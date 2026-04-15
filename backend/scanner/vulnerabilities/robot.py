"""
ROBOT Vulnerability Scanner (CVE-2017-13099)

ROBOT (Return Of Bleichenbacher's Oracle Threat) is an attack against
RSA key exchange in TLS. It exploits subtle differences in server behavior
when processing malformed RSA-encrypted premaster secrets.

The attack allows decryption of recorded TLS sessions if RSA key exchange
was used, and potentially signing of arbitrary messages.

A full ROBOT test requires timing analysis and multiple probes, which is
complex and time-consuming. This scanner performs a simpler check:
1. Determines if RSA key exchange is supported (prerequisite)
2. Recommends ECDHE/DHE-only configurations

CVSS Score: 7.5 (High)
Affected: Servers using RSA key exchange (non-PFS ciphers)
Mitigation: Disable RSA key exchange, use only ECDHE/DHE ciphers
"""

import socket
import ssl
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class RobotScanner:
    """
    Tests for ROBOT vulnerability by checking if the server
    supports RSA key exchange (non-forward-secrecy ciphers).

    RSA key exchange is a prerequisite for ROBOT attacks. While this
    scanner doesn't perform the full oracle detection (which requires
    timing analysis), it identifies at-risk servers.
    """

    # RSA key exchange ciphers (no forward secrecy)
    # These are the ones vulnerable to ROBOT
    RSA_KEY_EXCHANGE_CIPHERS = [
        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA256",
        "AES128-SHA256",
        "AES256-SHA",
        "AES128-SHA",
        "DES-CBC3-SHA",
        "RC4-SHA",
        "RC4-MD5",
    ]

    # Forward secrecy ciphers (not vulnerable)
    PFS_CIPHER_PREFIXES = ["ECDHE", "DHE", "EDH"]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def _check_rsa_cipher(self, hostname: str, port: int, cipher: str) -> bool:
        """Check if a specific RSA key exchange cipher is supported."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                context.set_ciphers(cipher)
            except ssl.SSLError:
                return False

            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                negotiated = ssock.cipher()
                if negotiated:
                    # Make sure it's actually an RSA key exchange cipher
                    cipher_name = negotiated[0]
                    if not any(
                        cipher_name.startswith(prefix)
                        for prefix in self.PFS_CIPHER_PREFIXES
                    ):
                        return True

        except ssl.SSLError:
            return False
        except Exception:
            return False

        return False

    def _get_all_supported_ciphers(self, hostname: str, port: int) -> List[str]:
        """Get list of all ciphers supported by the server."""
        supported = []

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the negotiated cipher
                cipher = ssock.cipher()
                if cipher:
                    supported.append(cipher[0])

        except Exception:
            pass

        return supported

    def test(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Test target for ROBOT vulnerability prerequisites.

        Checks if RSA key exchange is supported. If yes, the server
        is potentially vulnerable to ROBOT attacks.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            Dictionary with vulnerability assessment results
        """
        result = {
            "vulnerable": False,
            "rsa_key_exchange_supported": False,
            "rsa_ciphers": [],
            "pfs_only": False,
            "oracle_detected": False,  # Would need timing analysis
            "cve": "CVE-2017-13099",
            "severity": "High",
            "error": None,
            "details": None,
            "mitigation": "Disable RSA key exchange, use only ECDHE/DHE cipher suites",
        }

        try:
            # Check each RSA cipher
            for cipher in self.RSA_KEY_EXCHANGE_CIPHERS:
                if self._check_rsa_cipher(hostname, port, cipher):
                    result["rsa_key_exchange_supported"] = True
                    result["rsa_ciphers"].append(cipher)
                    # Continue checking to get full list (or stop after a few)
                    if len(result["rsa_ciphers"]) >= 3:
                        break

            if result["rsa_key_exchange_supported"]:
                result["vulnerable"] = True  # Potentially vulnerable
                result["details"] = (
                    f"Server supports RSA key exchange with {len(result['rsa_ciphers'])} "
                    f"cipher(s): {', '.join(result['rsa_ciphers'][:3])}. "
                    "RSA key exchange is a prerequisite for ROBOT attacks. "
                    "Full ROBOT vulnerability requires timing oracle detection. "
                    "Recommendation: Disable RSA key exchange and use only ECDHE/DHE."
                )
                logger.warning(
                    f"ROBOT RISK: {hostname} supports RSA key exchange "
                    f"({', '.join(result['rsa_ciphers'][:3])})"
                )
            else:
                result["pfs_only"] = True
                result["details"] = (
                    "Server does not support RSA key exchange. "
                    "Only forward-secrecy ciphers (ECDHE/DHE) are available. "
                    "Server is not vulnerable to ROBOT attacks."
                )

        except socket.gaierror as e:
            result["error"] = f"DNS resolution failed: {str(e)}"
        except socket.timeout:
            result["error"] = f"Connection timed out after {self.timeout} seconds"
        except ConnectionRefusedError:
            result["error"] = f"Connection refused on port {port}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            logger.exception(f"Error testing {hostname} for ROBOT")

        return result


# Convenience function
def check_robot(hostname: str, port: int = 443) -> bool:
    """Quick check if host is potentially vulnerable to ROBOT."""
    scanner = RobotScanner()
    result = scanner.test(hostname, port)
    return result["vulnerable"]
