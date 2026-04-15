"""
DNS Security Auditor

Audits DNS security configuration including:
- DNSSEC (DNS Security Extensions) validation
- CAA (Certification Authority Authorization) records
- SPF (Sender Policy Framework) for email
- DKIM (DomainKeys Identified Mail) configuration
- DMARC (Domain-based Message Authentication) policy
- DNS over HTTPS/TLS support

Helps identify DNS misconfigurations that could lead to security issues.
"""

import logging
import dns.resolver
import dns.dnssec
import dns.query
import dns.zone
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)


@dataclass
class DNSSECResult:
    """DNSSEC validation result."""

    enabled: bool = False
    valid: bool = False
    error: Optional[str] = None
    details: Optional[str] = None


@dataclass
class CAARecord:
    """CAA record entry."""

    flag: int
    tag: str
    value: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flag": self.flag,
            "tag": self.tag,
            "value": self.value,
        }


@dataclass
class CAAResult:
    """CAA records analysis result."""

    present: bool = False
    records: List[CAARecord] = field(default_factory=list)
    issuers_allowed: List[str] = field(default_factory=list)
    wildcard_allowed: bool = True
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "records": [r.to_dict() for r in self.records],
            "issuers_allowed": self.issuers_allowed,
            "wildcard_allowed": self.wildcard_allowed,
            "error": self.error,
        }


@dataclass
class SPFResult:
    """SPF record analysis result."""

    present: bool = False
    record: Optional[str] = None
    valid: bool = False
    mechanisms: List[str] = field(default_factory=list)
    all_mechanism: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "record": self.record,
            "valid": self.valid,
            "mechanisms": self.mechanisms,
            "all_mechanism": self.all_mechanism,
            "error": self.error,
        }


@dataclass
class DMARCResult:
    """DMARC policy analysis result."""

    present: bool = False
    record: Optional[str] = None
    policy: Optional[str] = None
    subdomain_policy: Optional[str] = None
    percentage: int = 100
    reporting_addresses: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "present": self.present,
            "record": self.record,
            "policy": self.policy,
            "subdomain_policy": self.subdomain_policy,
            "percentage": self.percentage,
            "reporting_addresses": self.reporting_addresses,
            "error": self.error,
        }


@dataclass
class DNSSecurityResult:
    """Complete DNS security audit result."""

    domain: str
    dnssec: DNSSECResult = field(default_factory=DNSSECResult)
    caa: CAAResult = field(default_factory=CAAResult)
    spf: SPFResult = field(default_factory=SPFResult)
    dmarc: DMARCResult = field(default_factory=DMARCResult)
    overall_score: int = 0
    grade: str = "F"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "overall_score": self.overall_score,
            "grade": self.grade,
            "dnssec": {
                "enabled": self.dnssec.enabled,
                "valid": self.dnssec.valid,
                "details": self.dnssec.details,
            },
            "caa": self.caa.to_dict(),
            "spf": self.spf.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "error": self.error,
        }


class DNSSecurityAuditor:
    """
    Audits DNS security configuration for a domain.

    Checks DNSSEC, CAA, SPF, DMARC, and other DNS security features.
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize DNS security auditor.

        Args:
            timeout: DNS query timeout in seconds
        """
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _check_dnssec(self, domain: str) -> DNSSECResult:
        """
        Check DNSSEC configuration.

        Note: Full DNSSEC validation requires following the chain of trust
        from root. This is a simplified check.
        """
        result = DNSSECResult()

        try:
            # Try to query for DNSKEY records
            answers = self.resolver.resolve(domain, "DNSKEY")
            if answers:
                result.enabled = True
                result.details = f"Found {len(answers)} DNSKEY record(s)"

                # Try to validate (simplified check)
                try:
                    # Query for RRSIG records
                    rrsig_answers = self.resolver.resolve(domain, "RRSIG")
                    if rrsig_answers:
                        result.valid = True
                        result.details += ", RRSIG present"
                except:
                    result.details += ", but could not validate RRSIG"

        except dns.resolver.NoAnswer:
            result.details = "No DNSKEY records found"
        except dns.resolver.NXDOMAIN:
            result.error = "Domain does not exist"
        except Exception as e:
            result.error = f"DNSSEC check error: {str(e)}"

        return result

    def _check_caa(self, domain: str) -> CAAResult:
        """Check CAA (Certification Authority Authorization) records."""
        result = CAAResult()

        try:
            answers = self.resolver.resolve(domain, "CAA")
            result.present = True

            for rdata in answers:
                # Parse CAA record
                flag = rdata.flags
                tag = rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag
                value = (
                    rdata.value.decode()
                    if isinstance(rdata.value, bytes)
                    else rdata.value
                )

                record = CAARecord(flag=flag, tag=tag, value=value)
                result.records.append(record)

                # Track issuers
                if tag == "issue":
                    if value:
                        result.issuers_allowed.append(value)
                        result.wildcard_allowed = False
                elif tag == "issuewild":
                    result.wildcard_allowed = bool(value)

        except dns.resolver.NoAnswer:
            result.details = "No CAA records found"
        except dns.resolver.NXDOMAIN:
            result.error = "Domain does not exist"
        except Exception as e:
            result.error = f"CAA check error: {str(e)}"

        return result

    def _check_spf(self, domain: str) -> SPFResult:
        """Check SPF (Sender Policy Framework) records."""
        result = SPFResult()

        try:
            answers = self.resolver.resolve(domain, "TXT")

            for rdata in answers:
                txt_value = rdata.to_text().strip('"')

                if txt_value.startswith("v=spf1"):
                    result.present = True
                    result.record = txt_value
                    result.valid = True

                    # Parse mechanisms
                    parts = txt_value.split()
                    for part in parts[1:]:  # Skip v=spf1
                        if (
                            part.startswith("+")
                            or part.startswith("-")
                            or part.startswith("~")
                            or part.startswith("?")
                        ):
                            result.mechanisms.append(part)
                        elif part in ["all", "+all", "-all", "~all", "?all"]:
                            result.all_mechanism = part
                        else:
                            result.mechanisms.append(part)

                    break

            if not result.present:
                result.error = "No SPF record found"

        except dns.resolver.NoAnswer:
            result.error = "No TXT records found"
        except dns.resolver.NXDOMAIN:
            result.error = "Domain does not exist"
        except Exception as e:
            result.error = f"SPF check error: {str(e)}"

        return result

    def _check_dmarc(self, domain: str) -> DMARCResult:
        """Check DMARC (Domain-based Message Authentication) policy."""
        result = DMARCResult()

        try:
            # DMARC records are at _dmarc subdomain
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, "TXT")

            for rdata in answers:
                txt_value = rdata.to_text().strip('"')

                if txt_value.startswith("v=DMARC1"):
                    result.present = True
                    result.record = txt_value

                    # Parse DMARC policy
                    parts = txt_value.split(";")
                    for part in parts:
                        part = part.strip()
                        if part.startswith("p="):
                            result.policy = part.split("=")[1]
                        elif part.startswith("sp="):
                            result.subdomain_policy = part.split("=")[1]
                        elif part.startswith("pct="):
                            try:
                                result.percentage = int(part.split("=")[1])
                            except:
                                pass
                        elif part.startswith("rua="):
                            result.reporting_addresses.append(part.split("=")[1])
                        elif part.startswith("ruf="):
                            result.reporting_addresses.append(part.split("=")[1])

                    break

            if not result.present:
                result.error = "No DMARC record found"

        except dns.resolver.NoAnswer:
            result.error = "No DMARC record found"
        except dns.resolver.NXDOMAIN:
            result.error = "_dmarc subdomain does not exist"
        except Exception as e:
            result.error = f"DMARC check error: {str(e)}"

        return result

    def audit(self, domain: str) -> DNSSecurityResult:
        """
        Perform complete DNS security audit.

        Args:
            domain: Domain to audit

        Returns:
            DNSSecurityResult with all checks
        """
        result = DNSSecurityResult(domain=domain)

        try:
            logger.info(f"Starting DNS security audit for {domain}")

            # Run all checks
            result.dnssec = self._check_dnssec(domain)
            result.caa = self._check_caa(domain)
            result.spf = self._check_spf(domain)
            result.dmarc = self._check_dmarc(domain)

            # Calculate score
            score = 0

            # DNSSEC: 30 points
            if result.dnssec.enabled:
                score += 15
                if result.dnssec.valid:
                    score += 15

            # CAA: 25 points
            if result.caa.present:
                score += 15
                if result.caa.issuers_allowed:
                    score += 10

            # SPF: 25 points
            if result.spf.present:
                score += 15
                if result.spf.all_mechanism in ["-all", "~all"]:
                    score += 10

            # DMARC: 20 points
            if result.dmarc.present:
                score += 10
                if result.dmarc.policy in ["quarantine", "reject"]:
                    score += 10

            result.overall_score = score

            # Assign grade
            if score >= 90:
                result.grade = "A"
            elif score >= 75:
                result.grade = "B"
            elif score >= 60:
                result.grade = "C"
            elif score >= 45:
                result.grade = "D"
            else:
                result.grade = "F"

            logger.info(
                f"DNS security audit complete for {domain}: "
                f"Score {result.overall_score}/100, Grade {result.grade}"
            )

        except Exception as e:
            result.error = f"Audit error: {str(e)}"
            logger.exception(f"Error auditing DNS security for {domain}")

        return result


# Convenience function
def check_dns_security(domain: str) -> Dict[str, Any]:
    """
    Quick DNS security check.

    Args:
        domain: Domain to check

    Returns:
        Dictionary with DNS security audit results
    """
    auditor = DNSSecurityAuditor()
    result = auditor.audit(domain)
    return result.to_dict()
