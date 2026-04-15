"""
Scan Orchestrator — Coordinates all scanner modules into a complete scan.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from scanner.certificate import CertificateAnalyzer, CertificateData
from scanner.tls_config import TLSConfigAnalyzer, TLSConfigData
from scanner.cipher_suites import CipherSuiteAuditor, CipherSuiteData
from scanner.revocation import RevocationChecker, RevocationData
from scanner.chain import ChainValidator, ChainData
from scanner.scorer import SecurityScorer, SecurityScore
from scanner.vulnerabilities import VulnerabilityOrchestrator, VulnerabilityScanResult

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    hostname: str = ""
    port: int = 443
    certificate: Optional[CertificateData] = None
    tls_config: Optional[TLSConfigData] = None
    cipher_suites: list[CipherSuiteData] = field(default_factory=list)
    revocation: Optional[RevocationData] = None
    chain: Optional[ChainData] = None
    vulnerabilities: Optional[VulnerabilityScanResult] = None
    score: Optional[SecurityScore] = None
    recommendations: list[dict] = field(default_factory=list)
    error: Optional[str] = None


class ScanOrchestrator:
    """Runs all scan modules in sequence and aggregates results."""

    def __init__(self, include_vulnerability_scan: bool = True):
        self.cert_analyzer = CertificateAnalyzer()
        self.tls_analyzer = TLSConfigAnalyzer()
        self.cipher_auditor = CipherSuiteAuditor()
        self.revocation_checker = RevocationChecker()
        self.chain_validator = ChainValidator()
        self.scorer = SecurityScorer()
        self.include_vulnerability_scan = include_vulnerability_scan
        if include_vulnerability_scan:
            self.vulnerability_orchestrator = VulnerabilityOrchestrator()

    def run_scan(self, hostname: str, port: int = 443) -> ScanResult:
        """Execute a full security scan on the target."""
        result = ScanResult(hostname=hostname, port=port)

        try:
            # Step 1: Certificate analysis
            logger.info(f"[{hostname}] Analyzing certificate...")
            result.certificate = self.cert_analyzer.analyze(hostname, port)

            # Step 2: TLS configuration
            logger.info(f"[{hostname}] Checking TLS configuration...")
            result.tls_config = self.tls_analyzer.analyze(hostname, port)

            # Step 3: Cipher suites
            logger.info(f"[{hostname}] Auditing cipher suites...")
            result.cipher_suites = self.cipher_auditor.analyze(hostname, port)

            # Step 4: Certificate chain
            logger.info(f"[{hostname}] Validating certificate chain...")
            result.chain = self.chain_validator.validate(hostname, port)

            # Step 5: Revocation check
            logger.info(f"[{hostname}] Checking revocation status...")
            issuer_cert = None
            if result.chain and len(result.chain.raw_certs) > 1:
                issuer_cert = result.chain.raw_certs[1]
            if result.certificate and result.certificate.cert_obj:
                result.revocation = self.revocation_checker.check(
                    result.certificate.cert_obj, issuer_cert
                )
            else:
                result.revocation = RevocationData()

            # Step 6: Vulnerability scan (optional but recommended)
            if self.include_vulnerability_scan:
                logger.info(f"[{hostname}] Running vulnerability scans...")
                result.vulnerabilities = self.vulnerability_orchestrator.scan(
                    hostname, port
                )
                if result.vulnerabilities.total_vulnerabilities > 0:
                    logger.warning(
                        f"[{hostname}] Found {result.vulnerabilities.total_vulnerabilities} vulnerabilities"
                    )

            # Step 7: Calculate score
            logger.info(f"[{hostname}] Calculating security score...")
            result.score = self.scorer.calculate(
                cert=result.certificate,
                tls=result.tls_config,
                ciphers=result.cipher_suites,
                revocation=result.revocation,
                chain=result.chain,
            )

            # Step 8: Generate recommendations
            result.recommendations = self._generate_recommendations(result)

            logger.info(
                f"[{hostname}] Scan complete — Score: {result.score.score}, Grade: {result.score.grade}"
            )

        except Exception as e:
            logger.error(f"[{hostname}] Scan failed: {e}")
            result.error = str(e)

        return result

    def _generate_recommendations(self, result: ScanResult) -> list[dict]:
        """Generate actionable security recommendations based on scan findings."""
        recs = []

        # Certificate recommendations
        if result.certificate:
            if result.certificate.is_expired:
                recs.append(
                    {
                        "severity": "Critical",
                        "title": "Certificate has expired",
                        "description": "The SSL/TLS certificate for this domain has expired.",
                        "fix_suggestion": "Renew the certificate immediately with your Certificate Authority.",
                    }
                )
            elif (
                result.certificate.days_until_expiry is not None
                and result.certificate.days_until_expiry < 30
            ):
                recs.append(
                    {
                        "severity": "Warning",
                        "title": "Certificate expiring soon",
                        "description": f"Certificate expires in {result.certificate.days_until_expiry} days.",
                        "fix_suggestion": "Renew the certificate before the expiry date to avoid service disruption.",
                    }
                )
            if result.certificate.is_self_signed:
                recs.append(
                    {
                        "severity": "Warning",
                        "title": "Self-signed certificate detected",
                        "description": "Self-signed certificates are not trusted by browsers.",
                        "fix_suggestion": "Obtain a certificate from a trusted Certificate Authority (e.g., Let's Encrypt).",
                    }
                )
            if (
                result.certificate.public_key_type == "RSA"
                and result.certificate.public_key_size
                and result.certificate.public_key_size < 2048
            ):
                recs.append(
                    {
                        "severity": "Critical",
                        "title": "Weak RSA key size",
                        "description": f"RSA key size is {result.certificate.public_key_size} bits, which is considered weak.",
                        "fix_suggestion": "Use at least 2048-bit RSA keys, or preferably 4096-bit or ECC keys.",
                    }
                )

        # TLS recommendations
        if result.tls_config:
            if result.tls_config.tls_1_0:
                recs.append(
                    {
                        "severity": "Critical",
                        "title": "TLS 1.0 is supported",
                        "description": "TLS 1.0 is deprecated and has known vulnerabilities (BEAST, POODLE).",
                        "fix_suggestion": "Disable TLS 1.0 on your server. Use TLS 1.2 or TLS 1.3 only.",
                    }
                )
            if result.tls_config.tls_1_1:
                recs.append(
                    {
                        "severity": "Warning",
                        "title": "TLS 1.1 is supported",
                        "description": "TLS 1.1 is deprecated and should not be used.",
                        "fix_suggestion": "Disable TLS 1.1. Upgrade to TLS 1.2 or TLS 1.3.",
                    }
                )
            if not result.tls_config.tls_1_3:
                recs.append(
                    {
                        "severity": "Info",
                        "title": "TLS 1.3 not supported",
                        "description": "TLS 1.3 offers improved security and performance.",
                        "fix_suggestion": "Enable TLS 1.3 on your server for better security and faster handshakes.",
                    }
                )
            if result.tls_config.insecure_reneg:
                recs.append(
                    {
                        "severity": "Critical",
                        "title": "Insecure renegotiation supported",
                        "description": "The server allows insecure TLS renegotiation.",
                        "fix_suggestion": "Disable insecure renegotiation and enable secure renegotiation.",
                    }
                )

        # Cipher recommendations
        if result.cipher_suites:
            dangerous = [c for c in result.cipher_suites if c.is_dangerous]
            if dangerous:
                names = ", ".join(c.cipher_name for c in dangerous[:5])
                recs.append(
                    {
                        "severity": "Critical",
                        "title": "Dangerous cipher suites detected",
                        "description": f"Found {len(dangerous)} dangerous cipher(s): {names}",
                        "fix_suggestion": "Remove weak cipher suites (RC4, 3DES, NULL, EXPORT, DES) from your server configuration.",
                    }
                )

        # Chain recommendations
        if result.chain:
            if result.chain.has_broken_chain:
                recs.append(
                    {
                        "severity": "Critical",
                        "title": "Broken certificate chain",
                        "description": "The certificate chain is incomplete or broken.",
                        "fix_suggestion": "Install all intermediate certificates on your server.",
                    }
                )
            if result.chain.has_expired_intermediate:
                recs.append(
                    {
                        "severity": "Critical",
                        "title": "Expired intermediate certificate",
                        "description": "One or more intermediate certificates in the chain have expired.",
                        "fix_suggestion": "Replace expired intermediate certificates with valid ones from your CA.",
                    }
                )

        # Revocation recommendations
        if result.revocation:
            if result.revocation.ocsp_status == "Revoked":
                recs.append(
                    {
                        "severity": "Critical",
                        "title": "Certificate has been revoked",
                        "description": "The OCSP responder reports this certificate as revoked.",
                        "fix_suggestion": "Obtain a new certificate immediately. The current one is compromised or invalid.",
                    }
                )
            if not result.revocation.crl_present:
                recs.append(
                    {
                        "severity": "Info",
                        "title": "No CRL distribution point",
                        "description": "The certificate does not include a CRL distribution point.",
                        "fix_suggestion": "This is informational — most modern systems rely on OCSP instead of CRL.",
                    }
                )

        # Vulnerability recommendations
        if result.vulnerabilities:
            for vuln in result.vulnerabilities.vulnerabilities:
                if vuln.vulnerable:
                    recs.append(
                        {
                            "severity": vuln.severity.value,
                            "title": f"Vulnerable to {vuln.name} ({vuln.cve})",
                            "description": vuln.details
                            or f"Server is vulnerable to {vuln.name} attack.",
                            "fix_suggestion": vuln.mitigation
                            or f"Apply patches and updates to mitigate {vuln.name}.",
                        }
                    )

        # If no issues found
        if not recs:
            recs.append(
                {
                    "severity": "Info",
                    "title": "No significant issues found",
                    "description": "The TLS configuration appears to follow best practices.",
                    "fix_suggestion": "Continue monitoring certificate expiry and keep TLS configuration up to date.",
                }
            )

        return recs
