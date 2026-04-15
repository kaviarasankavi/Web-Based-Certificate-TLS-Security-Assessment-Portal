"""
Certificate Chain Validator — Retrieves and validates the full certificate chain.
"""
import ssl
import socket
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from config import settings


@dataclass
class ChainCert:
    subject: str = ""
    issuer: str = ""
    is_root: bool = False
    is_expired: bool = False
    valid_from: str = ""
    valid_to: str = ""


@dataclass
class ChainData:
    chain_depth: int = 0
    chain_valid: bool = True
    chain_certs: list[ChainCert] = field(default_factory=list)
    has_broken_chain: bool = False
    has_expired_intermediate: bool = False
    raw_certs: list[x509.Certificate] = field(default_factory=list)


class ChainValidator:
    """Validates the certificate chain from the server."""

    def validate(self, hostname: str, port: int = 443) -> ChainData:
        data = ChainData()
        certs = self._fetch_chain(hostname, port)
        data.raw_certs = certs
        data.chain_depth = len(certs)

        if not certs:
            data.chain_valid = False
            data.has_broken_chain = True
            return data

        now = datetime.now(timezone.utc)

        for i, cert in enumerate(certs):
            # Extract subject & issuer CN
            try:
                subj_cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                subject = subj_cn[0].value if subj_cn else str(cert.subject)
            except Exception:
                subject = str(cert.subject)

            try:
                iss_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                issuer = iss_cn[0].value if iss_cn else str(cert.issuer)
            except Exception:
                issuer = str(cert.issuer)

            is_root = cert.issuer == cert.subject
            is_expired = now > cert.not_valid_after_utc

            chain_cert = ChainCert(
                subject=subject,
                issuer=issuer,
                is_root=is_root,
                is_expired=is_expired,
                valid_from=cert.not_valid_before_utc.isoformat(),
                valid_to=cert.not_valid_after_utc.isoformat(),
            )
            data.chain_certs.append(chain_cert)

            # Check intermediate expiry
            if i > 0 and is_expired:
                data.has_expired_intermediate = True
                data.chain_valid = False

        # Verify chain linkage: each cert's issuer should match next cert's subject
        for i in range(len(certs) - 1):
            if certs[i].issuer != certs[i + 1].subject:
                data.has_broken_chain = True
                data.chain_valid = False
                break

        return data

    def _fetch_chain(self, hostname: str, port: int) -> list[x509.Certificate]:
        """Retrieve the full certificate chain from the server."""
        certs = []
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=settings.SCAN_TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    der_chain = tls_sock.get_verified_chain()
                    if der_chain is None:
                        # Fallback: try unverified chain
                        der_chain = tls_sock.get_unverified_chain()

                    if der_chain:
                        for der_cert in der_chain:
                            cert = x509.load_der_x509_certificate(der_cert.public_bytes(serialization.Encoding.DER))
                            certs.append(cert)
        except AttributeError:
            # Python < 3.13 might not have get_verified_chain
            # Fallback: fetch just the leaf cert
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=settings.SCAN_TIMEOUT) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                        der_cert = tls_sock.getpeercert(binary_form=True)
                        cert = x509.load_der_x509_certificate(der_cert)
                        certs.append(cert)
            except Exception:
                pass
        except Exception:
            pass

        return certs
