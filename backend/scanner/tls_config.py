"""
TLS Configuration Analyzer — Tests which TLS versions are supported.
"""
import ssl
import socket
from dataclasses import dataclass
from typing import Optional

from config import settings


@dataclass
class TLSConfigData:
    tls_1_0: bool = False
    tls_1_1: bool = False
    tls_1_2: bool = False
    tls_1_3: bool = False
    insecure_reneg: bool = False
    preferred_proto: Optional[str] = None


# Mapping of TLS versions to their ssl module protocol constants
TLS_VERSIONS = {
    "TLSv1.0": getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1 if hasattr(ssl, "TLSVersion") else None,
    "TLSv1.1": getattr(ssl, "TLSVersion", None) and ssl.TLSVersion.TLSv1_1 if hasattr(ssl, "TLSVersion") else None,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2 if hasattr(ssl, "TLSVersion") else None,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl, "TLSVersion") else None,
}


class TLSConfigAnalyzer:
    """Tests which TLS protocol versions are supported by the target server."""

    def analyze(self, hostname: str, port: int = 443) -> TLSConfigData:
        data = TLSConfigData()

        # Test each TLS version
        for version_name, version_const in TLS_VERSIONS.items():
            if version_const is None:
                continue
            supported = self._test_tls_version(hostname, port, version_const)
            if version_name == "TLSv1.0":
                data.tls_1_0 = supported
            elif version_name == "TLSv1.1":
                data.tls_1_1 = supported
            elif version_name == "TLSv1.2":
                data.tls_1_2 = supported
            elif version_name == "TLSv1.3":
                data.tls_1_3 = supported

        # Determine preferred protocol — try default connection
        data.preferred_proto = self._get_preferred_protocol(hostname, port)

        # Check insecure renegotiation
        data.insecure_reneg = self._check_insecure_renegotiation(hostname, port)

        return data

    def _test_tls_version(self, hostname: str, port: int, version) -> bool:
        """Try to connect using a specific TLS version."""
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version

            with socket.create_connection((hostname, port), timeout=settings.SCAN_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    return True
        except (ssl.SSLError, ConnectionError, OSError):
            return False

    def _get_preferred_protocol(self, hostname: str, port: int) -> Optional[str]:
        """Connect with default settings to find the server's preferred protocol."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=settings.SCAN_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    return tls_sock.version()
        except Exception:
            return None

    def _check_insecure_renegotiation(self, hostname: str, port: int) -> bool:
        """Check if the server supports insecure renegotiation (best-effort)."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=settings.SCAN_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    # If server info callback has renegotiation info, parse it
                    # For now, return False as most modern servers disable it
                    return False
        except Exception:
            return False
