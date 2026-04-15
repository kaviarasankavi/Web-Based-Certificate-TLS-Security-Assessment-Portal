"""
SWEET32 Vulnerability Scanner (CVE-2016-2183)

SWEET32 is a birthday attack against 64-bit block ciphers in TLS,
particularly 3DES (Triple DES). After capturing approximately 785 GB
of traffic, an attacker can recover plaintext with high probability.

The attack exploits the small block size (64 bits) which makes birthday
collisions feasible in modern high-traffic scenarios.

CVSS Score: 5.3 (Medium)
Affected: Servers supporting 3DES or other 64-bit block ciphers
Mitigation: Disable 3DES and all 64-bit block ciphers (DES, IDEA, RC2)
"""

import socket
import ssl
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class Sweet32Scanner:
    """
    Tests for SWEET32 vulnerability by checking if the server
    supports 64-bit block cipher suites (3DES, DES, etc.).

    These ciphers are vulnerable to birthday attacks due to their
    small block size, making collision attacks practical.
    """

    # 64-bit block ciphers vulnerable to SWEET32
    VULNERABLE_CIPHERS = [
        # 3DES ciphers
        "DES-CBC3-SHA",
        "ECDHE-RSA-DES-CBC3-SHA",
        "ECDHE-ECDSA-DES-CBC3-SHA",
        "EDH-RSA-DES-CBC3-SHA",
        "EDH-DSS-DES-CBC3-SHA",
        "DHE-RSA-DES-CBC3-SHA",
        "DHE-DSS-DES-CBC3-SHA",
        "ECDH-RSA-DES-CBC3-SHA",
        "ECDH-ECDSA-DES-CBC3-SHA",
        "ADH-DES-CBC3-SHA",
        # Single DES ciphers (also vulnerable, plus weak encryption)
        "DES-CBC-SHA",
        "EDH-RSA-DES-CBC-SHA",
        "EDH-DSS-DES-CBC-SHA",
        # Export DES ciphers
        "EXP-DES-CBC-SHA",
        "EXP-EDH-RSA-DES-CBC-SHA",
        "EXP-EDH-DSS-DES-CBC-SHA",
        # IDEA (also 64-bit)
        "IDEA-CBC-SHA",
        # RC2 (64-bit)
        "RC2-CBC-MD5",
        "EXP-RC2-CBC-MD5",
    ]

    # OpenSSL cipher names may vary - also check these patterns
    VULNERABLE_PATTERNS = ["DES", "3DES", "IDEA", "RC2"]

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def _check_cipher(self, hostname: str, port: int, cipher: str) -> bool:
        """Check if a specific 64-bit cipher is supported."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            try:
                context.set_ciphers(cipher)
            except ssl.SSLError:
                # Cipher not available in this OpenSSL
                return False

            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                negotiated = ssock.cipher()
                return negotiated is not None

        except ssl.SSLError:
            return False
        except Exception:
            return False

    def _is_64bit_cipher(self, cipher_name: str) -> bool:
        """Check if a cipher uses 64-bit block size."""
        # Check for known 64-bit cipher patterns
        cipher_upper = cipher_name.upper()

        # 3DES / DES patterns
        if "DES" in cipher_upper:
            return True
        # IDEA (64-bit block)
        if "IDEA" in cipher_upper:
            return True
        # RC2 (64-bit block)
        if "RC2" in cipher_upper:
            return True
        # Blowfish (64-bit block) - rarely seen in TLS
        if "BF" in cipher_upper or "BLOWFISH" in cipher_upper:
            return True

        return False

    def test(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Test target for SWEET32 vulnerability.

        Server is vulnerable if it supports any 64-bit block cipher.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            Dictionary with vulnerability assessment results
        """
        result = {
            "vulnerable": False,
            "weak_ciphers": [],
            "cve": "CVE-2016-2183",
            "severity": "Medium",
            "error": None,
            "details": None,
            "mitigation": "Disable all 64-bit block ciphers (3DES, DES, IDEA, RC2)",
        }

        try:
            # Check each vulnerable cipher
            for cipher in self.VULNERABLE_CIPHERS:
                if self._check_cipher(hostname, port, cipher):
                    result["weak_ciphers"].append(cipher)
                    # Continue to get a fuller picture (but limit for efficiency)
                    if len(result["weak_ciphers"]) >= 5:
                        break

            if result["weak_ciphers"]:
                result["vulnerable"] = True

                # Categorize the weak ciphers
                des3_ciphers = [
                    c
                    for c in result["weak_ciphers"]
                    if "CBC3" in c or "3DES" in c.upper()
                ]
                des_ciphers = [
                    c
                    for c in result["weak_ciphers"]
                    if "DES" in c and "CBC3" not in c and "3DES" not in c.upper()
                ]
                other_ciphers = [
                    c
                    for c in result["weak_ciphers"]
                    if c not in des3_ciphers and c not in des_ciphers
                ]

                details_parts = []
                if des3_ciphers:
                    details_parts.append(f"3DES ciphers: {', '.join(des3_ciphers[:2])}")
                if des_ciphers:
                    details_parts.append(
                        f"Single DES ciphers: {', '.join(des_ciphers[:2])}"
                    )
                if other_ciphers:
                    details_parts.append(
                        f"Other 64-bit ciphers: {', '.join(other_ciphers[:2])}"
                    )

                result["details"] = (
                    f"Server supports {len(result['weak_ciphers'])} weak 64-bit block cipher(s). "
                    f"{'; '.join(details_parts)}. "
                    "These are vulnerable to SWEET32 birthday attacks. "
                    "An attacker capturing ~785GB of traffic can recover plaintext."
                )
                logger.warning(
                    f"SWEET32 VULNERABLE: {hostname} supports 64-bit ciphers: "
                    f"{', '.join(result['weak_ciphers'][:3])}"
                )
            else:
                result["details"] = (
                    "Server does not support any 64-bit block ciphers. "
                    "Server is not vulnerable to SWEET32 attacks."
                )

        except socket.gaierror as e:
            result["error"] = f"DNS resolution failed: {str(e)}"
        except socket.timeout:
            result["error"] = f"Connection timed out after {self.timeout} seconds"
        except ConnectionRefusedError:
            result["error"] = f"Connection refused on port {port}"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            logger.exception(f"Error testing {hostname} for SWEET32")

        return result


# Convenience function
def check_sweet32(hostname: str, port: int = 443) -> bool:
    """Quick check if host is vulnerable to SWEET32."""
    scanner = Sweet32Scanner()
    result = scanner.test(hostname, port)
    return result["vulnerable"]
