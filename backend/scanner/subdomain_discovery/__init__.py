"""
Subdomain Discovery Module

Discovers subdomains for a given domain using multiple techniques:
1. Certificate Transparency (CT) logs - Most reliable
2. DNS brute-force with common subdomain wordlist
3. DNS zone transfer attempt (rarely works but worth trying)

This helps identify the attack surface and discover forgotten/misconfigured subdomains.
"""

import logging
import dns.resolver
import dns.zone
import dns.query
import requests
from dataclasses import dataclass, field
from typing import List, Set, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


@dataclass
class Subdomain:
    """Represents a discovered subdomain."""

    name: str
    source: str  # How it was discovered: CT, brute-force, zone-transfer
    ip_addresses: List[str] = field(default_factory=list)
    has_cert: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "ip_addresses": self.ip_addresses,
            "has_cert": self.has_cert,
        }


@dataclass
class SubdomainDiscoveryResult:
    """Results from subdomain discovery."""

    domain: str
    total_subdomains: int = 0
    subdomains: List[Subdomain] = field(default_factory=list)
    sources_used: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def unique_subdomains(self) -> List[str]:
        """Get list of unique subdomain names."""
        return sorted(set(sub.name for sub in self.subdomains))

    @property
    def subdomains_by_source(self) -> Dict[str, int]:
        """Count subdomains by discovery source."""
        counts = {}
        for sub in self.subdomains:
            counts[sub.source] = counts.get(sub.source, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "total_subdomains": self.total_subdomains,
            "unique_count": len(self.unique_subdomains),
            "sources_used": self.sources_used,
            "sources_breakdown": self.subdomains_by_source,
            "subdomains": [s.to_dict() for s in self.subdomains],
            "error": self.error,
        }


class SubdomainDiscovery:
    """
    Discovers subdomains using multiple techniques.

    Primary method is Certificate Transparency logs (most reliable).
    Falls back to brute-force with common wordlist if needed.
    """

    # Common subdomain names for brute-force
    COMMON_SUBDOMAINS = [
        "www",
        "mail",
        "ftp",
        "webmail",
        "smtp",
        "pop",
        "ns1",
        "ns2",
        "admin",
        "blog",
        "dev",
        "staging",
        "test",
        "api",
        "cdn",
        "shop",
        "store",
        "mobile",
        "portal",
        "app",
        "vpn",
        "remote",
        "server",
        "mysql",
        "backup",
        "old",
        "new",
        "forum",
        "help",
        "support",
        "wiki",
        "docs",
        "status",
        "monitor",
        "secure",
        "assets",
        "static",
        "images",
        "img",
        "css",
        "js",
        "git",
        "svn",
        "cpanel",
        "whm",
        "plesk",
        "webdisk",
        "ns",
        "dns",
        "mx",
        "email",
        "direct",
    ]

    def __init__(self, timeout: int = 10, max_workers: int = 10):
        """
        Initialize subdomain discovery.

        Args:
            timeout: Timeout for DNS queries and HTTP requests
            max_workers: Maximum concurrent workers for brute-force
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _discover_via_ct(self, domain: str) -> Set[str]:
        """
        Discover subdomains via Certificate Transparency logs.

        This is the most reliable method as CT logs contain all
        issued certificates including SANs.
        """
        subdomains = set()

        try:
            # Query crt.sh for certificates
            params = {
                "q": f"%.{domain}",
                "output": "json",
            }

            logger.info(f"Querying CT logs for subdomains of {domain}...")
            response = requests.get(
                "https://crt.sh", params=params, timeout=self.timeout
            )

            if response.status_code == 200:
                entries = response.json()

                for entry in entries:
                    # Extract names from name_value field (includes CN and SANs)
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower()
                        # Filter to only subdomains of target domain
                        if name.endswith(domain) and name != domain:
                            # Remove wildcards
                            name = name.replace("*.", "")
                            if name and name.count(".") > domain.count("."):
                                subdomains.add(name)

                logger.info(f"Found {len(subdomains)} unique subdomains from CT logs")

        except Exception as e:
            logger.error(f"Error querying CT logs: {e}")

        return subdomains

    def _resolve_subdomain(self, subdomain: str) -> Optional[Subdomain]:
        """Try to resolve a subdomain and return Subdomain object if it exists."""
        try:
            answers = self.resolver.resolve(subdomain, "A")
            ip_addresses = [str(rdata) for rdata in answers]

            return Subdomain(
                name=subdomain, source="brute-force", ip_addresses=ip_addresses
            )
        except:
            return None

    def _brute_force(self, domain: str) -> Set[str]:
        """
        Brute-force common subdomains.

        Uses parallel workers to speed up DNS resolution.
        """
        discovered = set()

        logger.info(f"Brute-forcing {len(self.COMMON_SUBDOMAINS)} common subdomains...")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all subdomain checks
            future_to_subdomain = {
                executor.submit(self._resolve_subdomain, f"{prefix}.{domain}"): prefix
                for prefix in self.COMMON_SUBDOMAINS
            }

            # Collect results
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    discovered.add(result.name)

        logger.info(f"Brute-force found {len(discovered)} subdomains")
        return discovered

    def _try_zone_transfer(self, domain: str) -> Set[str]:
        """
        Attempt DNS zone transfer (AXFR).

        This rarely works on modern servers but is worth attempting.
        """
        discovered = set()

        try:
            # Get nameservers
            ns_answers = self.resolver.resolve(domain, "NS")

            for ns in ns_answers:
                ns_name = str(ns.target)
                logger.info(f"Attempting zone transfer from {ns_name}...")

                try:
                    # Get NS IP address
                    ns_ip = str(self.resolver.resolve(ns_name, "A")[0])

                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_ip, domain, timeout=self.timeout)
                    )

                    # Extract all records
                    for name, node in zone.nodes.items():
                        subdomain = f"{name}.{domain}" if name != "@" else domain
                        if subdomain != domain:
                            discovered.add(subdomain)

                    logger.warning(
                        f"Zone transfer successful from {ns_name}! "
                        f"Found {len(discovered)} records. "
                        "This is a security misconfiguration!"
                    )
                    break

                except Exception as e:
                    logger.debug(f"Zone transfer failed from {ns_name}: {e}")
                    continue

        except Exception as e:
            logger.debug(f"Could not attempt zone transfer: {e}")

        return discovered

    def discover(
        self,
        domain: str,
        use_ct: bool = True,
        use_brute_force: bool = False,
        use_zone_transfer: bool = True,
    ) -> SubdomainDiscoveryResult:
        """
        Discover subdomains using enabled methods.

        Args:
            domain: Target domain
            use_ct: Use Certificate Transparency logs (recommended)
            use_brute_force: Use brute-force with common names (slower)
            use_zone_transfer: Attempt zone transfer (rarely works)

        Returns:
            SubdomainDiscoveryResult with all discovered subdomains
        """
        result = SubdomainDiscoveryResult(domain=domain)
        all_subdomains = {}  # name -> Subdomain object

        try:
            # Method 1: Certificate Transparency (fastest and most comprehensive)
            if use_ct:
                result.sources_used.append("Certificate Transparency")
                ct_subdomains = self._discover_via_ct(domain)

                for subdomain_name in ct_subdomains:
                    all_subdomains[subdomain_name] = Subdomain(
                        name=subdomain_name, source="CT", has_cert=True
                    )

            # Method 2: Zone Transfer (rarely works)
            if use_zone_transfer:
                result.sources_used.append("Zone Transfer")
                zt_subdomains = self._try_zone_transfer(domain)

                for subdomain_name in zt_subdomains:
                    if subdomain_name not in all_subdomains:
                        all_subdomains[subdomain_name] = Subdomain(
                            name=subdomain_name, source="zone-transfer"
                        )

            # Method 3: Brute Force (slower, but finds active subdomains)
            if use_brute_force:
                result.sources_used.append("Brute Force")
                bf_subdomains = self._brute_force(domain)

                for subdomain_name in bf_subdomains:
                    if subdomain_name not in all_subdomains:
                        # Resolve to get IP
                        sub = self._resolve_subdomain(subdomain_name)
                        if sub:
                            all_subdomains[subdomain_name] = sub

            # Populate result
            result.subdomains = sorted(all_subdomains.values(), key=lambda x: x.name)
            result.total_subdomains = len(result.subdomains)

            logger.info(
                f"Subdomain discovery complete for {domain}: "
                f"Found {result.total_subdomains} unique subdomains"
            )

        except Exception as e:
            result.error = f"Discovery error: {str(e)}"
            logger.exception(f"Error during subdomain discovery for {domain}")

        return result


# Convenience function
def discover_subdomains(domain: str, quick: bool = True) -> Dict[str, Any]:
    """
    Quick subdomain discovery.

    Args:
        domain: Target domain
        quick: If True, only use CT logs (fast). If False, also brute-force (slower).

    Returns:
        Dictionary with discovered subdomains
    """
    discovery = SubdomainDiscovery()
    result = discovery.discover(
        domain, use_ct=True, use_brute_force=not quick, use_zone_transfer=True
    )
    return result.to_dict()
