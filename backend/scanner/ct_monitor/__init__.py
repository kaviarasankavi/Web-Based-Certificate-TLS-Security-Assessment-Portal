"""
Certificate Transparency (CT) Monitor

Monitors Certificate Transparency logs for certificates issued to a domain.
This can detect:
- Unauthorized certificate issuance
- Phishing attempts using similar domains
- Certificate mis-issuance
- Historical certificate data

Uses the crt.sh API as the primary data source for CT logs.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import requests

logger = logging.getLogger(__name__)


@dataclass
class CTCertificate:
    """Represents a certificate found in CT logs."""

    id: int
    issuer_name: str
    common_name: str
    name_value: str  # All names (CN + SANs)
    not_before: datetime
    not_after: datetime
    serial_number: str
    entry_timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "issuer": self.issuer_name,
            "common_name": self.common_name,
            "all_names": self.name_value,
            "valid_from": self.not_before.isoformat() if self.not_before else None,
            "valid_to": self.not_after.isoformat() if self.not_after else None,
            "serial_number": self.serial_number,
            "logged_at": self.entry_timestamp.isoformat()
            if self.entry_timestamp
            else None,
        }


@dataclass
class CTMonitorResult:
    """Results from Certificate Transparency log monitoring."""

    domain: str
    total_certificates: int = 0
    certificates: List[CTCertificate] = field(default_factory=list)
    new_certificates_24h: int = 0
    new_certificates_7d: int = 0
    suspicious_issuers: List[str] = field(default_factory=list)
    recent_certificates: List[CTCertificate] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def unique_issuers(self) -> List[str]:
        """Get list of unique certificate issuers."""
        return list(set(cert.issuer_name for cert in self.certificates))

    @property
    def active_certificates(self) -> List[CTCertificate]:
        """Get certificates that are currently valid."""
        now = datetime.now()
        return [
            cert
            for cert in self.certificates
            if cert.not_before <= now <= cert.not_after
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "total_certificates": self.total_certificates,
            "new_last_24h": self.new_certificates_24h,
            "new_last_7d": self.new_certificates_7d,
            "unique_issuers": self.unique_issuers,
            "suspicious_issuers": self.suspicious_issuers,
            "active_certificates_count": len(self.active_certificates),
            "recent_certificates": [c.to_dict() for c in self.recent_certificates[:10]],
            "error": self.error,
        }


class CTMonitor:
    """
    Monitor Certificate Transparency logs for a domain.

    Uses crt.sh (Sectigo's CT search) as the primary data source.
    crt.sh aggregates data from all major CT logs.
    """

    CRT_SH_API = "https://crt.sh"

    # Known trusted CAs - others might be suspicious
    TRUSTED_ISSUERS = {
        "Let's Encrypt",
        "DigiCert",
        "Google Trust Services",
        "Cloudflare",
        "Amazon",
        "Sectigo",
        "GlobalSign",
        "GoDaddy",
        "Entrust",
        "IdenTrust",
        "Microsoft",
        "Apple",
        "Certum",
        "SSL.com",
    }

    def __init__(self, timeout: int = 30):
        """
        Initialize CT Monitor.

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "TLS-Security-Assessment-Tool/1.0"})

    def _parse_ct_entry(self, entry: Dict[str, Any]) -> Optional[CTCertificate]:
        """Parse a CT log entry from crt.sh API response."""
        try:
            # Parse dates
            not_before = datetime.fromisoformat(
                entry["not_before"].replace("Z", "+00:00")
            )
            not_after = datetime.fromisoformat(
                entry["not_after"].replace("Z", "+00:00")
            )
            entry_timestamp = datetime.fromisoformat(
                entry["entry_timestamp"].replace("Z", "+00:00")
            )

            return CTCertificate(
                id=entry["id"],
                issuer_name=entry["issuer_name"],
                common_name=entry.get("common_name", ""),
                name_value=entry.get("name_value", ""),
                not_before=not_before,
                not_after=not_after,
                serial_number=entry.get("serial_number", ""),
                entry_timestamp=entry_timestamp,
            )
        except Exception as e:
            logger.error(f"Error parsing CT entry: {e}")
            return None

    def _is_suspicious_issuer(self, issuer_name: str) -> bool:
        """Check if an issuer is potentially suspicious."""
        # Check if issuer contains any trusted CA name
        for trusted in self.TRUSTED_ISSUERS:
            if trusted.lower() in issuer_name.lower():
                return False

        # Unknown issuer - potentially suspicious
        return True

    def search(self, domain: str, match_wildcards: bool = True) -> CTMonitorResult:
        """
        Search Certificate Transparency logs for a domain.

        Args:
            domain: Domain name to search for
            match_wildcards: Include wildcard certificates (*.example.com)

        Returns:
            CTMonitorResult with all found certificates
        """
        result = CTMonitorResult(domain=domain)

        try:
            # Query crt.sh API
            params = {
                "q": f"%.{domain}" if match_wildcards else domain,
                "output": "json",
            }

            logger.info(f"Querying CT logs for {domain}...")
            response = self.session.get(
                self.CRT_SH_API, params=params, timeout=self.timeout
            )

            if response.status_code != 200:
                result.error = f"CT API returned status {response.status_code}"
                logger.error(result.error)
                return result

            # Parse response
            ct_entries = response.json()

            if not ct_entries:
                logger.info(f"No certificates found in CT logs for {domain}")
                return result

            result.total_certificates = len(ct_entries)

            # Calculate time thresholds
            now = datetime.now().replace(tzinfo=None)
            threshold_24h = now - timedelta(hours=24)
            threshold_7d = now - timedelta(days=7)

            # Process each certificate
            for entry in ct_entries:
                cert = self._parse_ct_entry(entry)
                if not cert:
                    continue

                result.certificates.append(cert)

                # Remove timezone info for comparison
                logged_at = cert.entry_timestamp.replace(tzinfo=None)

                # Count recent certificates
                if logged_at >= threshold_24h:
                    result.new_certificates_24h += 1
                if logged_at >= threshold_7d:
                    result.new_certificates_7d += 1
                    result.recent_certificates.append(cert)

                # Check for suspicious issuers
                if self._is_suspicious_issuer(cert.issuer_name):
                    if cert.issuer_name not in result.suspicious_issuers:
                        result.suspicious_issuers.append(cert.issuer_name)
                        logger.warning(
                            f"Suspicious issuer found for {domain}: {cert.issuer_name}"
                        )

            # Sort recent certificates by timestamp (newest first)
            result.recent_certificates.sort(
                key=lambda c: c.entry_timestamp, reverse=True
            )

            logger.info(
                f"CT search complete for {domain}: "
                f"{result.total_certificates} total, "
                f"{result.new_certificates_24h} in last 24h, "
                f"{len(result.active_certificates)} currently active"
            )

        except requests.Timeout:
            result.error = f"Request timed out after {self.timeout}s"
            logger.error(f"CT API timeout for {domain}")
        except requests.RequestException as e:
            result.error = f"Request error: {str(e)}"
            logger.error(f"CT API request error for {domain}: {e}")
        except ValueError as e:
            result.error = f"JSON parsing error: {str(e)}"
            logger.error(f"CT API response parsing error: {e}")
        except Exception as e:
            result.error = f"Unexpected error: {str(e)}"
            logger.exception(f"Unexpected error in CT search for {domain}")

        return result

    def monitor_recent(self, domain: str, hours: int = 24) -> CTMonitorResult:
        """
        Monitor for certificates issued in the last N hours.

        Useful for detecting unauthorized certificate issuance.

        Args:
            domain: Domain to monitor
            hours: Number of hours to look back

        Returns:
            CTMonitorResult with only recent certificates
        """
        result = self.search(domain)

        if result.error:
            return result

        # Filter to only recent certificates
        threshold = datetime.now().replace(tzinfo=None) - timedelta(hours=hours)
        recent_certs = [
            cert
            for cert in result.certificates
            if cert.entry_timestamp.replace(tzinfo=None) >= threshold
        ]

        result.certificates = recent_certs
        result.total_certificates = len(recent_certs)
        result.recent_certificates = recent_certs

        return result

    def get_issuer_summary(self, domain: str) -> Dict[str, int]:
        """
        Get a summary of certificate issuers for a domain.

        Returns:
            Dictionary mapping issuer names to certificate counts
        """
        result = self.search(domain)

        if result.error:
            return {}

        issuer_counts = {}
        for cert in result.certificates:
            issuer = cert.issuer_name
            issuer_counts[issuer] = issuer_counts.get(issuer, 0) + 1

        return issuer_counts


# Convenience function
def check_ct_logs(domain: str) -> Dict[str, Any]:
    """
    Quick check of Certificate Transparency logs.

    Args:
        domain: Domain to check

    Returns:
        Dictionary with CT log summary
    """
    monitor = CTMonitor()
    result = monitor.search(domain)
    return result.to_dict()
