"""
Cipher Suite Auditor — Enumerates and classifies server cipher suites.
"""
import ssl
import socket
from dataclasses import dataclass, field
from typing import Optional

from config import settings


@dataclass
class CipherSuiteData:
    cipher_name: str = ""
    protocol: str = ""
    key_exchange: str = ""
    strength: str = "Unknown"  # Strong / Acceptable / Weak
    is_dangerous: bool = False
    bits: int = 0


# Dangerous cipher keywords
DANGEROUS_CIPHERS = {"RC4", "3DES", "DES", "NULL", "EXPORT", "RC2", "MD5", "anon"}

WEAK_KEY_EXCHANGES = {"RSA"}  # No forward secrecy


def classify_cipher(name: str, bits: int) -> tuple[str, bool]:
    """Classify a cipher as Strong/Acceptable/Weak and flag if dangerous."""
    name_upper = name.upper()

    # Check dangerous patterns
    for pattern in DANGEROUS_CIPHERS:
        if pattern in name_upper:
            return "Weak", True

    # Classify by bit strength
    if bits >= 256:
        return "Strong", False
    elif bits >= 128:
        return "Acceptable", False
    else:
        return "Weak", True


def extract_key_exchange(cipher_name: str) -> str:
    """Extract the key exchange method from cipher name."""
    if "ECDHE" in cipher_name:
        return "ECDHE"
    elif "DHE" in cipher_name or "EDH" in cipher_name:
        return "DHE"
    elif "ECDH" in cipher_name:
        return "ECDH"
    elif "RSA" in cipher_name:
        return "RSA"
    elif "PSK" in cipher_name:
        return "PSK"
    return "Unknown"


class CipherSuiteAuditor:
    """Enumerates cipher suites supported by the server and classifies their strength."""

    def analyze(self, hostname: str, port: int = 443) -> list[CipherSuiteData]:
        """Get server's supported cipher suites via default connection."""
        results = []

        # Try to get ciphers via a standard connection
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=settings.SCAN_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    # Get the negotiated cipher
                    cipher_info = tls_sock.cipher()
                    protocol_version = tls_sock.version()

                    if cipher_info:
                        name, proto, bits = cipher_info
                        strength, dangerous = classify_cipher(name, bits)
                        results.append(CipherSuiteData(
                            cipher_name=name,
                            protocol=protocol_version or proto,
                            key_exchange=extract_key_exchange(name),
                            strength=strength,
                            is_dangerous=dangerous,
                            bits=bits,
                        ))

                    # Get all shared ciphers
                    shared = tls_sock.shared_ciphers()
                    if shared:
                        seen = {results[0].cipher_name} if results else set()
                        for cipher_tuple in shared:
                            name, proto, bits = cipher_tuple
                            if name in seen:
                                continue
                            seen.add(name)
                            strength, dangerous = classify_cipher(name, bits)
                            results.append(CipherSuiteData(
                                cipher_name=name,
                                protocol=proto,
                                key_exchange=extract_key_exchange(name),
                                strength=strength,
                                is_dangerous=dangerous,
                                bits=bits,
                            ))
        except Exception:
            pass

        # Try older context to discover additional weak ciphers
        self._probe_weak_ciphers(hostname, port, results)

        return results

    def _probe_weak_ciphers(self, hostname: str, port: int, existing: list[CipherSuiteData]):
        """Try connecting with a permissive context to find weak/legacy ciphers."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers("ALL:COMPLEMENTOFALL:@SECLEVEL=0")

            if hasattr(ssl, "TLSVersion"):
                context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

            with socket.create_connection((hostname, port), timeout=settings.SCAN_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    shared = tls_sock.shared_ciphers()
                    if shared:
                        seen = {c.cipher_name for c in existing}
                        for cipher_tuple in shared:
                            name, proto, bits = cipher_tuple
                            if name in seen:
                                continue
                            seen.add(name)
                            strength, dangerous = classify_cipher(name, bits)
                            existing.append(CipherSuiteData(
                                cipher_name=name,
                                protocol=proto,
                                key_exchange=extract_key_exchange(name),
                                strength=strength,
                                is_dangerous=dangerous,
                                bits=bits,
                            ))
        except (ssl.SSLError, ConnectionError, OSError):
            pass
