"""
Certificate Analyzer — Extracts and analyzes X.509 certificate data.
"""
import ssl
import socket
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

from config import settings


@dataclass
class CertificateData:
    subject_cn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    valid_from: Optional[datetime] = None
    valid_to: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False
    serial_number: Optional[str] = None
    signature_algo: Optional[str] = None
    public_key_type: Optional[str] = None
    public_key_size: Optional[int] = None
    san_list: list[str] = field(default_factory=list)
    raw_pem: Optional[str] = None
    cert_obj: Optional[x509.Certificate] = None


class CertificateAnalyzer:
    """Connects to a host via SSL and extracts X.509 certificate details."""

    def analyze(self, hostname: str, port: int = 443) -> CertificateData:
        """Fetch and analyze the certificate from the given hostname."""
        pem_data = self._fetch_certificate(hostname, port)
        cert = x509.load_pem_x509_certificate(pem_data)
        return self._parse_certificate(cert, pem_data)

    def _fetch_certificate(self, hostname: str, port: int) -> bytes:
        """Connect to the server and get the PEM-encoded certificate."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=settings.SCAN_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der_cert = tls_sock.getpeercert(binary_form=True)

        # Convert DER to PEM
        from cryptography.x509 import load_der_x509_certificate
        cert = load_der_x509_certificate(der_cert)
        return cert.public_bytes(serialization.Encoding.PEM)

    def _parse_certificate(self, cert: x509.Certificate, pem_data: bytes) -> CertificateData:
        """Extract all relevant fields from an X.509 certificate."""
        data = CertificateData()
        data.cert_obj = cert
        data.raw_pem = pem_data.decode("utf-8")

        # Subject CN
        try:
            cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            data.subject_cn = cn_attrs[0].value if cn_attrs else str(cert.subject)
        except Exception:
            data.subject_cn = str(cert.subject)

        # Issuer CN & Org
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            data.issuer_cn = issuer_cn[0].value if issuer_cn else str(cert.issuer)
        except Exception:
            data.issuer_cn = str(cert.issuer)

        try:
            issuer_org = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            data.issuer_org = issuer_org[0].value if issuer_org else None
        except Exception:
            data.issuer_org = None

        # Validity
        data.valid_from = cert.not_valid_before_utc
        data.valid_to = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        data.days_until_expiry = (data.valid_to - now).days
        data.is_expired = now > data.valid_to

        # Self-signed check
        data.is_self_signed = cert.issuer == cert.subject

        # Serial
        data.serial_number = format(cert.serial_number, "X")

        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid
        data.signature_algo = sig_algo._name if hasattr(sig_algo, "_name") else str(sig_algo.dotted_string)

        # Public key
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            data.public_key_type = "RSA"
            data.public_key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            data.public_key_type = "ECC"
            data.public_key_size = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            data.public_key_type = "DSA"
            data.public_key_size = pub_key.key_size
        else:
            data.public_key_type = type(pub_key).__name__
            data.public_key_size = None

        # SAN (Subject Alternative Names)
        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            data.san_list = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            data.san_list = []

        return data
