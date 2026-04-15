"""
Revocation Checker — Performs OCSP and CRL revocation checks.
"""
import hashlib
from dataclasses import dataclass
from typing import Optional

import requests
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.hashes import SHA1


@dataclass
class RevocationData:
    ocsp_status: str = "Unknown"  # Good / Revoked / Unknown / Error
    ocsp_url: Optional[str] = None
    crl_present: bool = False
    crl_url: Optional[str] = None
    stapling_support: bool = False


class RevocationChecker:
    """Checks certificate revocation status via OCSP and CRL."""

    def check(self, cert: x509.Certificate, issuer_cert: Optional[x509.Certificate] = None) -> RevocationData:
        data = RevocationData()

        # Extract OCSP URL
        data.ocsp_url = self._get_ocsp_url(cert)

        # Extract CRL URL
        data.crl_url = self._get_crl_url(cert)
        data.crl_present = data.crl_url is not None

        # Perform OCSP check
        if data.ocsp_url and issuer_cert:
            data.ocsp_status = self._check_ocsp(cert, issuer_cert, data.ocsp_url)
        elif data.ocsp_url:
            data.ocsp_status = "Unknown"  # Cannot check without issuer cert
        else:
            data.ocsp_status = "No OCSP URL"

        return data

    def _get_ocsp_url(self, cert: x509.Certificate) -> Optional[str]:
        """Extract the OCSP responder URL from the certificate's AIA extension."""
        try:
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            for desc in aia.value:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    return desc.access_location.value
        except (x509.ExtensionNotFound, Exception):
            pass
        return None

    def _get_crl_url(self, cert: x509.Certificate) -> Optional[str]:
        """Extract the CRL distribution point URL."""
        try:
            crl_ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            for dp in crl_ext.value:
                if dp.full_name:
                    for name in dp.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            return name.value
        except (x509.ExtensionNotFound, Exception):
            pass
        return None

    def _check_ocsp(self, cert: x509.Certificate, issuer: x509.Certificate, ocsp_url: str) -> str:
        """Send an OCSP request and interpret the response."""
        try:
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer, SHA1())
            ocsp_request = builder.build()
            request_data = ocsp_request.public_bytes(serialization.Encoding.DER)

            response = requests.post(
                ocsp_url,
                data=request_data,
                headers={"Content-Type": "application/ocsp-request"},
                timeout=10,
            )

            if response.status_code != 200:
                return "Error"

            ocsp_response = ocsp.load_der_ocsp_response(response.content)

            if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                status = ocsp_response.certificate_status
                if status == ocsp.OCSPCertStatus.GOOD:
                    return "Good"
                elif status == ocsp.OCSPCertStatus.REVOKED:
                    return "Revoked"
                else:
                    return "Unknown"
            else:
                return "Error"

        except Exception as e:
            return "Error"
