"""
Security Scorer — Calculates a weighted security score and letter grade.
"""
from dataclasses import dataclass

from scanner.certificate import CertificateData
from scanner.tls_config import TLSConfigData
from scanner.cipher_suites import CipherSuiteData
from scanner.revocation import RevocationData
from scanner.chain import ChainData


@dataclass
class SecurityScore:
    score: int = 0  # 0-100
    grade: str = "F"
    breakdown: dict = None

    def __post_init__(self):
        if self.breakdown is None:
            self.breakdown = {}


# Weight distribution
WEIGHTS = {
    "certificate": 25,
    "tls_version": 25,
    "cipher_strength": 20,
    "revocation": 15,
    "chain": 15,
}


def _score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"


class SecurityScorer:
    """Aggregates all scan results and calculates a weighted security score."""

    def calculate(
        self,
        cert: CertificateData,
        tls: TLSConfigData,
        ciphers: list[CipherSuiteData],
        revocation: RevocationData,
        chain: ChainData,
    ) -> SecurityScore:
        breakdown = {}

        # 1. Certificate score (25%)
        cert_score = 100
        if cert.is_expired:
            cert_score = 0
        elif cert.is_self_signed:
            cert_score -= 40
        if cert.days_until_expiry is not None and cert.days_until_expiry < 30:
            cert_score -= 20
        if cert.public_key_type == "RSA" and cert.public_key_size and cert.public_key_size < 2048:
            cert_score -= 30
        cert_score = max(0, cert_score)
        breakdown["certificate"] = cert_score

        # 2. TLS version score (25%)
        tls_score = 100
        if tls.tls_1_0:
            tls_score -= 30
        if tls.tls_1_1:
            tls_score -= 20
        if not tls.tls_1_2 and not tls.tls_1_3:
            tls_score = 0
        if tls.insecure_reneg:
            tls_score -= 20
        if tls.tls_1_3:
            tls_score = min(tls_score + 10, 100)  # Bonus for TLS 1.3
        tls_score = max(0, tls_score)
        breakdown["tls_version"] = tls_score

        # 3. Cipher suite score (20%)
        cipher_score = 100
        if ciphers:
            total = len(ciphers)
            weak = sum(1 for c in ciphers if c.strength == "Weak")
            dangerous = sum(1 for c in ciphers if c.is_dangerous)
            if dangerous > 0:
                cipher_score -= 40
            if total > 0:
                weak_pct = weak / total
                cipher_score -= int(weak_pct * 40)
        else:
            cipher_score = 50  # No data
        cipher_score = max(0, cipher_score)
        breakdown["cipher_strength"] = cipher_score

        # 4. Revocation score (15%)
        rev_score = 100
        if revocation.ocsp_status == "Good":
            rev_score = 100
        elif revocation.ocsp_status == "Revoked":
            rev_score = 0
        elif revocation.ocsp_status == "Unknown":
            rev_score = 60
        elif revocation.ocsp_status == "Error":
            rev_score = 50
        else:
            rev_score = 40  # No OCSP URL
        if not revocation.crl_present:
            rev_score -= 10
        rev_score = max(0, rev_score)
        breakdown["revocation"] = rev_score

        # 5. Chain score (15%)
        chain_score = 100
        if chain.has_broken_chain:
            chain_score = 0
        elif chain.has_expired_intermediate:
            chain_score = 20
        elif not chain.chain_valid:
            chain_score = 30
        breakdown["chain"] = chain_score

        # Weighted total
        total = sum(
            breakdown[key] * (WEIGHTS[key] / 100)
            for key in WEIGHTS
        )
        total = int(round(total))

        return SecurityScore(
            score=total,
            grade=_score_to_grade(total),
            breakdown=breakdown,
        )
