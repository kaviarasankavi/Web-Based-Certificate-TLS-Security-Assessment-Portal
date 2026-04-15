"""
POODLE Vulnerability Scanner (CVE-2014-3566)

POODLE (Padding Oracle On Downgraded Legacy Encryption) is a vulnerability
in the SSLv3 protocol that allows attackers to decrypt encrypted traffic
by exploiting the way SSLv3 handles block cipher padding.

The attack requires:
1. SSLv3 support on the server
2. CBC cipher suites enabled
3. A man-in-the-middle position

CVSS Score: 3.4 (Medium) - requires MITM position
Affected: Any server supporting SSLv3 with CBC ciphers
Mitigation: Disable SSLv3 entirely
"""

import socket
import ssl
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class PoodleScanner:
    """
    Tests for POODLE vulnerability by checking if the server
    supports SSLv3 with CBC cipher suites.

    Since modern Python may not have SSLv3 support compiled in,
    we use raw socket connection with manual TLS negotiation as fallback.
    """

    # CBC ciphers vulnerable to POODLE
    CBC_CIPHERS = [
        "AES256-SHA",
        "AES128-SHA",
        "DES-CBC3-SHA",
        "DES-CBC-SHA",
        "IDEA-CBC-SHA",
        "RC2-CBC-MD5",
    ]

    # SSLv3 client hello for manual testing
    SSLV3_CLIENT_HELLO = bytes(
        [
            0x16,  # Content type: Handshake
            0x03,
            0x00,  # SSLv3
            0x00,
            0x61,  # Length
            0x01,  # Handshake type: ClientHello
            0x00,
            0x00,
            0x5D,  # Length
            0x03,
            0x00,  # SSLv3 version
            # 32 bytes random
            0x53,
            0x43,
            0x5B,
            0x90,
            0x9D,
            0x9B,
            0x72,
            0x0B,
            0xBC,
            0x0C,
            0xBC,
            0x2B,
            0x92,
            0xA8,
            0x48,
            0x97,
            0xCF,
            0xBD,
            0x39,
            0x04,
            0xCC,
            0x16,
            0x0A,
            0x85,
            0x03,
            0x90,
            0x9F,
            0x77,
            0x04,
            0x33,
            0xD4,
            0xDE,
            0x00,  # Session ID length: 0
            0x00,
            0x2C,  # Cipher suites length (44 bytes = 22 ciphers)
            # CBC cipher suites
            0x00,
            0x39,  # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
            0x00,
            0x38,  # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
            0x00,
            0x35,  # TLS_RSA_WITH_AES_256_CBC_SHA
            0x00,
            0x33,  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
            0x00,
            0x32,  # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
            0x00,
            0x2F,  # TLS_RSA_WITH_AES_128_CBC_SHA
            0x00,
            0x16,  # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
            0x00,
            0x13,  # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
            0x00,
            0x0A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
            0x00,
            0x15,  # TLS_DHE_RSA_WITH_DES_CBC_SHA
            0x00,
            0x12,  # TLS_DHE_DSS_WITH_DES_CBC_SHA
            0x00,
            0x09,  # TLS_RSA_WITH_DES_CBC_SHA
            0x00,
            0x14,  # TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x00,
            0x11,  # TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
            0x00,
            0x08,  # TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
            0x00,
            0x06,  # TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
            0x00,
            0x05,  # TLS_RSA_WITH_RC4_128_SHA (not CBC but included)
            0x00,
            0x04,  # TLS_RSA_WITH_RC4_128_MD5 (not CBC but included)
            0x00,
            0x03,  # TLS_RSA_EXPORT_WITH_RC4_40_MD5
            0x00,
            0xFF,  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            0x00,
            0x02,  # TLS_RSA_WITH_NULL_SHA
            0x00,
            0x01,  # TLS_RSA_WITH_NULL_MD5
            0x01,  # Compression methods length
            0x00,  # Compression: null
        ]
    )

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def _test_with_ssl_context(self, hostname: str, port: int) -> Dict[str, Any]:
        """
        Test using Python's ssl module (if SSLv3 is available).
        """
        result = {
            "vulnerable": False,
            "sslv3_supported": False,
            "cbc_ciphers": [],
            "method": "ssl_context",
        }

        try:
            # Check if SSLv3 is available
            if not hasattr(ssl, "PROTOCOL_SSLv3"):
                result["error"] = "SSLv3 not available in this Python build"
                return result

            # Try to connect with SSLv3
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Try CBC ciphers
            context.set_ciphers(":".join(self.CBC_CIPHERS))

            sock = socket.create_connection((hostname, port), timeout=self.timeout)
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["sslv3_supported"] = True
                cipher = ssock.cipher()
                if cipher:
                    cipher_name = cipher[0]
                    # Check if it's a CBC cipher
                    if "CBC" in cipher_name or any(
                        c in cipher_name for c in ["DES", "AES", "IDEA"]
                    ):
                        result["vulnerable"] = True
                        result["cbc_ciphers"].append(cipher_name)

        except ssl.SSLError as e:
            error_str = str(e)
            if "SSLV3_ALERT_HANDSHAKE_FAILURE" in error_str:
                result["details"] = "SSLv3 not supported (good)"
            elif "wrong version number" in error_str.lower():
                result["details"] = "SSLv3 not supported (good)"
            elif "no ciphers" in error_str.lower():
                result["details"] = "No CBC ciphers supported on SSLv3"
            else:
                result["error"] = error_str
        except AttributeError:
            result["error"] = "SSLv3 not available in this Python build"
        except socket.timeout:
            result["error"] = "Connection timed out"
        except Exception as e:
            result["error"] = str(e)

        return result

    def _test_raw_socket(self, hostname: str, port: int) -> Dict[str, Any]:
        """
        Test using raw socket with manual SSLv3 ClientHello.
        This works even when Python doesn't have SSLv3 compiled in.
        """
        result = {
            "vulnerable": False,
            "sslv3_supported": False,
            "cbc_ciphers": [],
            "method": "raw_socket",
        }

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((hostname, port))

            # Send SSLv3 ClientHello
            sock.send(self.SSLV3_CLIENT_HELLO)

            # Receive response
            response = sock.recv(4096)

            if len(response) >= 5:
                content_type = response[0]
                version_major = response[1]
                version_minor = response[2]

                # Check if we got a valid TLS record
                if content_type == 0x16:  # Handshake
                    # Check version
                    if version_major == 0x03 and version_minor == 0x00:
                        # SSLv3 supported!
                        result["sslv3_supported"] = True
                        result["vulnerable"] = True
                        result["details"] = (
                            "Server accepted SSLv3 connection with CBC ciphers"
                        )
                        logger.warning(f"POODLE VULNERABLE: {hostname} supports SSLv3")
                    elif version_major == 0x03:
                        # Server upgraded to TLS (good)
                        result["details"] = f"Server upgraded to TLS {version_minor}"

                elif content_type == 0x15:  # Alert
                    # Server sent alert - SSLv3 rejected
                    result["details"] = "Server rejected SSLv3 (alert sent)"

        except socket.timeout:
            result["error"] = "Connection timed out"
        except ConnectionRefusedError:
            result["error"] = f"Connection refused on port {port}"
        except Exception as e:
            result["error"] = str(e)
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        return result

    def test(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Test target for POODLE vulnerability.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            Dictionary with vulnerability assessment results
        """
        result = {
            "vulnerable": False,
            "sslv3_supported": False,
            "cbc_ciphers": [],
            "cve": "CVE-2014-3566",
            "severity": "Medium",
            "error": None,
            "details": None,
        }

        # First try using ssl context
        ssl_result = self._test_with_ssl_context(hostname, port)

        # If ssl context method found vulnerability, we're done
        if ssl_result.get("vulnerable"):
            result.update(ssl_result)
            result["details"] = (
                "Server supports SSLv3 with CBC cipher suites. "
                "This allows POODLE attacks in MITM scenarios."
            )
            return result

        # If ssl context had error (SSLv3 not available), try raw socket
        if ssl_result.get("error") and "SSLv3 not available" in str(
            ssl_result.get("error", "")
        ):
            raw_result = self._test_raw_socket(hostname, port)
            if raw_result.get("vulnerable"):
                result.update(raw_result)
                return result
            elif raw_result.get("sslv3_supported"):
                result["sslv3_supported"] = True
                result["vulnerable"] = True
                result["details"] = raw_result.get("details")
                return result

        # SSLv3 not supported - server is safe
        if not result["vulnerable"]:
            result["details"] = ssl_result.get(
                "details", "SSLv3 not supported (server is not vulnerable)"
            )

        return result


# Convenience function
def check_poodle(hostname: str, port: int = 443) -> bool:
    """Quick check if host is vulnerable to POODLE."""
    scanner = PoodleScanner()
    result = scanner.test(hostname, port)
    return result["vulnerable"]
