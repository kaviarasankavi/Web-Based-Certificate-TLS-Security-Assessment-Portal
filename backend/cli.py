#!/usr/bin/env python3
"""
TLS Security Assessment CLI
A command-line tool for analyzing SSL/TLS certificate security.
"""

import sys
import json
import argparse
from datetime import datetime
from typing import Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
except ImportError:
    print("Error: Rich library not installed. Install it with: pip install rich")
    sys.exit(1)

from scanner.orchestrator import ScanOrchestrator, ScanResult
from scanner.certificate import CertificateData
from scanner.tls_config import TLSConfigData
from scanner.cipher_suites import CipherSuiteData
from scanner.vulnerabilities import VulnerabilityOrchestrator, VulnerabilityScanResult

console = Console()


def get_grade_color(grade: str) -> str:
    """Return color based on security grade."""
    colors = {
        "A+": "bold green",
        "A": "green",
        "B": "yellow",
        "C": "orange1",
        "D": "red",
        "F": "bold red",
    }
    return colors.get(grade, "white")


def get_severity_color(severity: str) -> str:
    """Return color based on severity level."""
    colors = {
        "Critical": "bold red",
        "High": "red",
        "Medium": "yellow",
        "Warning": "yellow",
        "Low": "cyan",
        "Info": "cyan",
    }
    return colors.get(severity, "white")


def create_grade_display(score: int, grade: str) -> Panel:
    """Create a visually appealing grade display."""
    grade_color = get_grade_color(grade)
    grade_text = Text()
    grade_text.append(f"\n  {grade}  \n", style=f"{grade_color} on default")

    return Panel(
        f"[{grade_color}]{grade}[/{grade_color}]\n[dim]Score: {score}/100[/dim]",
        title="Security Grade",
        border_style=grade_color,
        padding=(1, 4),
    )


def display_certificate_info(cert: CertificateData) -> Panel:
    """Display certificate information in a formatted panel."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Subject CN", cert.subject_cn or "N/A")
    table.add_row("Issuer CN", cert.issuer_cn or "N/A")
    table.add_row("Issuer Org", cert.issuer_org or "N/A")

    if cert.valid_from:
        table.add_row("Valid From", cert.valid_from.strftime("%Y-%m-%d %H:%M:%S"))
    if cert.valid_to:
        expiry_style = (
            "red"
            if cert.is_expired
            else (
                "yellow"
                if cert.days_until_expiry and cert.days_until_expiry < 30
                else "green"
            )
        )
        expiry_text = f"{cert.valid_to.strftime('%Y-%m-%d %H:%M:%S')}"
        if cert.days_until_expiry is not None:
            if cert.is_expired:
                expiry_text += f" [bold red](EXPIRED)[/bold red]"
            else:
                expiry_text += f" [{expiry_style}]({cert.days_until_expiry} days left)[/{expiry_style}]"
        table.add_row("Valid To", expiry_text)

    table.add_row(
        "Serial Number",
        cert.serial_number[:40] + "..."
        if cert.serial_number and len(cert.serial_number) > 40
        else cert.serial_number or "N/A",
    )
    table.add_row("Signature Algorithm", cert.signature_algo or "N/A")

    key_info = (
        f"{cert.public_key_type} {cert.public_key_size} bits"
        if cert.public_key_type
        else "N/A"
    )
    key_style = (
        "green" if cert.public_key_size and cert.public_key_size >= 2048 else "red"
    )
    table.add_row("Public Key", f"[{key_style}]{key_info}[/{key_style}]")

    if cert.is_self_signed:
        table.add_row("Self-Signed", "[yellow]Yes[/yellow]")

    if cert.san_list:
        sans_display = ", ".join(cert.san_list[:5])
        if len(cert.san_list) > 5:
            sans_display += f" (+{len(cert.san_list) - 5} more)"
        table.add_row("SANs", sans_display)

    return Panel(table, title="Certificate Details", border_style="blue")


def display_tls_config(tls: TLSConfigData) -> Panel:
    """Display TLS configuration in a formatted panel."""
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Protocol", style="cyan")
    table.add_column("Status", style="white")

    def status_indicator(supported: bool, is_good: bool) -> str:
        if supported:
            color = "green" if is_good else "red"
            icon = "" if is_good else ""
            return f"[{color}]{icon} Supported[/{color}]"
        else:
            color = "green" if not is_good else "dim"
            return f"[{color}]Not Supported[/{color}]"

    table.add_row("TLS 1.0", status_indicator(tls.tls_1_0, False))
    table.add_row("TLS 1.1", status_indicator(tls.tls_1_1, False))
    table.add_row("TLS 1.2", status_indicator(tls.tls_1_2, True))
    table.add_row("TLS 1.3", status_indicator(tls.tls_1_3, True))

    if tls.preferred_proto:
        table.add_row("Preferred Version", f"[cyan]{tls.preferred_proto}[/cyan]")

    if tls.insecure_reneg:
        table.add_row("Insecure Renegotiation", "[bold red]Vulnerable[/bold red]")
    else:
        table.add_row("Insecure Renegotiation", "[green]Not Vulnerable[/green]")

    return Panel(table, title="TLS Configuration", border_style="blue")


def display_cipher_suites(ciphers: list[CipherSuiteData]) -> Panel:
    """Display cipher suites in a formatted table."""
    table = Table(box=box.ROUNDED, show_lines=False)
    table.add_column("Cipher Suite", style="white", max_width=50)
    table.add_column("Protocol", style="cyan")
    table.add_column("Key Exchange", style="magenta")
    table.add_column("Strength", justify="center")
    table.add_column("Status", justify="center")

    # Sort: show dangerous first, then by strength
    sorted_ciphers = sorted(
        ciphers, key=lambda c: (not c.is_dangerous, c.bits or 0), reverse=True
    )

    for cipher in sorted_ciphers[:15]:  # Limit to 15 for readability
        strength_color = (
            "green"
            if cipher.bits and cipher.bits >= 256
            else ("yellow" if cipher.bits and cipher.bits >= 128 else "red")
        )
        strength_text = (
            f"[{strength_color}]{cipher.bits or '?'} bits[/{strength_color}]"
        )

        status = (
            "[bold red]DANGEROUS[/bold red]"
            if cipher.is_dangerous
            else "[green]OK[/green]"
        )

        table.add_row(
            cipher.cipher_name[:50],
            cipher.protocol or "Unknown",
            cipher.key_exchange or "N/A",
            strength_text,
            status,
        )

    if len(ciphers) > 15:
        table.add_row(
            f"[dim]... and {len(ciphers) - 15} more cipher suites[/dim]", "", "", "", ""
        )

    return Panel(
        table, title=f"Cipher Suites ({len(ciphers)} total)", border_style="blue"
    )


def display_chain_info(chain) -> Panel:
    """Display certificate chain information."""
    if not chain:
        return Panel(
            "[yellow]Chain information not available[/yellow]",
            title="Certificate Chain",
            border_style="blue",
        )

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Chain Depth", str(chain.chain_depth))
    table.add_row(
        "Chain Valid",
        "[green]Yes[/green]" if chain.chain_valid else "[bold red]Invalid[/bold red]",
    )
    table.add_row(
        "Broken Chain",
        "[bold red]Yes[/bold red]" if chain.has_broken_chain else "[green]No[/green]",
    )

    if chain.has_expired_intermediate:
        table.add_row("Intermediate Status", "[bold red]Expired[/bold red]")
    else:
        table.add_row("Intermediate Status", "[green]Valid[/green]")

    # Show chain certificates if available
    if chain.chain_certs:
        for i, cert in enumerate(chain.chain_certs):
            prefix = (
                "" if i == 0 else "  ├─ " if i < len(chain.chain_certs) - 1 else "  └─ "
            )
            cert_info = f"{prefix}{cert.subject}"
            if cert.is_root:
                cert_info += " [dim](Root)[/dim]"
            table.add_row(f"Cert {i + 1}", cert_info)

    return Panel(table, title="Certificate Chain", border_style="blue")


def display_revocation_info(revocation) -> Panel:
    """Display revocation status information."""
    if not revocation:
        return Panel(
            "[yellow]Revocation information not available[/yellow]",
            title="Revocation Status",
            border_style="blue",
        )

    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    ocsp_status = revocation.ocsp_status or "Unknown"
    ocsp_color = (
        "green"
        if ocsp_status == "Good"
        else ("red" if ocsp_status == "Revoked" else "yellow")
    )
    table.add_row("OCSP Status", f"[{ocsp_color}]{ocsp_status}[/{ocsp_color}]")

    if revocation.ocsp_url:
        table.add_row(
            "OCSP URL",
            revocation.ocsp_url[:60] + "..."
            if len(revocation.ocsp_url) > 60
            else revocation.ocsp_url,
        )

    table.add_row(
        "CRL Present",
        "[green]Yes[/green]" if revocation.crl_present else "[yellow]No[/yellow]",
    )

    return Panel(table, title="Revocation Status", border_style="blue")


def display_recommendations(recommendations: list[dict]) -> Panel:
    """Display security recommendations."""
    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Issue", style="white")
    table.add_column("Recommendation", style="dim")

    # Sort by severity
    severity_order = {
        "Critical": 0,
        "High": 1,
        "Warning": 2,
        "Medium": 3,
        "Low": 4,
        "Info": 5,
    }
    sorted_recs = sorted(
        recommendations, key=lambda r: severity_order.get(r.get("severity", "Info"), 6)
    )

    for rec in sorted_recs:
        severity = rec.get("severity", "Info")
        severity_color = get_severity_color(severity)

        table.add_row(
            f"[{severity_color}]{severity}[/{severity_color}]",
            rec.get("title", ""),
            rec.get("fix_suggestion", "")[:80],
        )

    return Panel(table, title="Security Recommendations", border_style="yellow")


def display_vulnerabilities(vulns: VulnerabilityScanResult) -> Panel:
    """Display vulnerability scan results."""
    table = Table(box=box.ROUNDED, show_lines=False)
    table.add_column("Vulnerability", style="white")
    table.add_column("CVE", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Status", justify="center")

    for vuln in vulns.vulnerabilities:
        severity_color = get_severity_color(vuln.severity.value)

        if vuln.vulnerable:
            status = "[bold red]VULNERABLE[/bold red]"
        elif vuln.error:
            status = "[yellow]ERROR[/yellow]"
        else:
            status = "[green]OK[/green]"

        table.add_row(
            vuln.name,
            vuln.cve,
            f"[{severity_color}]{vuln.severity.value}[/{severity_color}]",
            status,
        )

    # Summary row
    summary = f"Score: {vulns.vulnerability_score}/100 | Grade: {vulns.grade}"
    if vulns.total_vulnerabilities > 0:
        summary += f" | [red]{vulns.total_vulnerabilities} issue(s) found[/red]"

    return Panel(
        table,
        title=f"Vulnerability Scan (completed in {vulns.scan_time_seconds:.1f}s)",
        subtitle=summary,
        border_style="red" if vulns.total_vulnerabilities > 0 else "green",
    )


def run_scan_with_progress(
    hostname: str, port: int, include_vulns: bool = True
) -> ScanResult:
    """Run the scan with a progress display."""
    orchestrator = ScanOrchestrator(
        include_vulnerability_scan=False
    )  # We'll run vulns separately
    vuln_orchestrator = VulnerabilityOrchestrator(timeout=10) if include_vulns else None

    scan_steps = [
        ("Analyzing certificate", "certificate"),
        ("Checking TLS configuration", "tls_config"),
        ("Auditing cipher suites", "cipher_suites"),
        ("Validating certificate chain", "chain"),
        ("Checking revocation status", "revocation"),
        ("Calculating security score", "score"),
    ]

    if include_vulns:
        scan_steps.append(("Scanning for vulnerabilities", "vulnerabilities"))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {hostname}:{port}...", total=len(scan_steps)
        )

        result = ScanResult(hostname=hostname, port=port)

        try:
            # Step 1: Certificate analysis
            progress.update(task, description="[cyan]Analyzing certificate...")
            result.certificate = orchestrator.cert_analyzer.analyze(hostname, port)
            progress.advance(task)

            # Step 2: TLS configuration
            progress.update(task, description="[cyan]Checking TLS configuration...")
            result.tls_config = orchestrator.tls_analyzer.analyze(hostname, port)
            progress.advance(task)

            # Step 3: Cipher suites
            progress.update(task, description="[cyan]Auditing cipher suites...")
            result.cipher_suites = orchestrator.cipher_auditor.analyze(hostname, port)
            progress.advance(task)

            # Step 4: Certificate chain
            progress.update(task, description="[cyan]Validating certificate chain...")
            result.chain = orchestrator.chain_validator.validate(hostname, port)
            progress.advance(task)

            # Step 5: Revocation check
            progress.update(task, description="[cyan]Checking revocation status...")
            from scanner.revocation import RevocationData

            issuer_cert = None
            if result.chain and len(result.chain.raw_certs) > 1:
                issuer_cert = result.chain.raw_certs[1]
            if result.certificate and result.certificate.cert_obj:
                result.revocation = orchestrator.revocation_checker.check(
                    result.certificate.cert_obj, issuer_cert
                )
            else:
                result.revocation = RevocationData()
            progress.advance(task)

            # Step 6: Calculate score
            progress.update(task, description="[cyan]Calculating security score...")
            result.score = orchestrator.scorer.calculate(
                cert=result.certificate,
                tls=result.tls_config,
                ciphers=result.cipher_suites,
                revocation=result.revocation,
                chain=result.chain,
            )
            progress.advance(task)

            # Step 7: Vulnerability scan (optional)
            if include_vulns and vuln_orchestrator:
                progress.update(
                    task, description="[cyan]Scanning for vulnerabilities..."
                )
                result.vulnerabilities = vuln_orchestrator.scan(hostname, port)
                progress.advance(task)

            # Generate recommendations (after vulns are done)
            result.recommendations = orchestrator._generate_recommendations(result)

        except Exception as e:
            result.error = str(e)

    return result


def export_json(result: ScanResult, filepath: str):
    """Export scan results to JSON."""
    data = {
        "hostname": result.hostname,
        "port": result.port,
        "scan_time": datetime.now().isoformat(),
        "score": result.score.score if result.score else None,
        "grade": result.score.grade if result.score else None,
        "certificate": {
            "subject_cn": result.certificate.subject_cn if result.certificate else None,
            "issuer_cn": result.certificate.issuer_cn if result.certificate else None,
            "valid_from": result.certificate.valid_from.isoformat()
            if result.certificate and result.certificate.valid_from
            else None,
            "valid_to": result.certificate.valid_to.isoformat()
            if result.certificate and result.certificate.valid_to
            else None,
            "days_until_expiry": result.certificate.days_until_expiry
            if result.certificate
            else None,
            "is_expired": result.certificate.is_expired if result.certificate else None,
            "is_self_signed": result.certificate.is_self_signed
            if result.certificate
            else None,
            "public_key_type": result.certificate.public_key_type
            if result.certificate
            else None,
            "public_key_size": result.certificate.public_key_size
            if result.certificate
            else None,
            "sans": result.certificate.san_list if result.certificate else [],
        }
        if result.certificate
        else None,
        "tls_config": {
            "tls_1_0": result.tls_config.tls_1_0 if result.tls_config else None,
            "tls_1_1": result.tls_config.tls_1_1 if result.tls_config else None,
            "tls_1_2": result.tls_config.tls_1_2 if result.tls_config else None,
            "tls_1_3": result.tls_config.tls_1_3 if result.tls_config else None,
            "preferred_version": result.tls_config.preferred_proto
            if result.tls_config
            else None,
            "insecure_reneg": result.tls_config.insecure_reneg
            if result.tls_config
            else None,
        }
        if result.tls_config
        else None,
        "cipher_suites": [
            {
                "name": c.cipher_name,
                "protocol": c.protocol,
                "key_exchange": c.key_exchange,
                "strength_bits": c.bits,
                "is_dangerous": c.is_dangerous,
            }
            for c in result.cipher_suites
        ],
        "chain": {
            "depth": result.chain.chain_depth if result.chain else None,
            "valid": result.chain.chain_valid if result.chain else None,
            "broken": result.chain.has_broken_chain if result.chain else None,
            "expired_intermediate": result.chain.has_expired_intermediate
            if result.chain
            else None,
        }
        if result.chain
        else None,
        "revocation": {
            "ocsp_status": result.revocation.ocsp_status if result.revocation else None,
            "ocsp_url": result.revocation.ocsp_url if result.revocation else None,
            "crl_present": result.revocation.crl_present if result.revocation else None,
        }
        if result.revocation
        else None,
        "vulnerabilities": {
            "scan_time_seconds": result.vulnerabilities.scan_time_seconds
            if result.vulnerabilities
            else None,
            "vulnerability_score": result.vulnerabilities.vulnerability_score
            if result.vulnerabilities
            else None,
            "grade": result.vulnerabilities.grade if result.vulnerabilities else None,
            "total_found": result.vulnerabilities.total_vulnerabilities
            if result.vulnerabilities
            else 0,
            "summary": {
                "critical": result.vulnerabilities.critical_count
                if result.vulnerabilities
                else 0,
                "high": result.vulnerabilities.high_count
                if result.vulnerabilities
                else 0,
                "medium": result.vulnerabilities.medium_count
                if result.vulnerabilities
                else 0,
                "low": result.vulnerabilities.low_count
                if result.vulnerabilities
                else 0,
            },
            "details": [
                {
                    "name": v.name,
                    "cve": v.cve,
                    "vulnerable": v.vulnerable,
                    "severity": v.severity.value,
                    "details": v.details,
                    "mitigation": v.mitigation,
                    "error": v.error,
                }
                for v in (
                    result.vulnerabilities.vulnerabilities
                    if result.vulnerabilities
                    else []
                )
            ],
        }
        if result.vulnerabilities
        else None,
        "recommendations": result.recommendations,
        "error": result.error,
    }

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]Results exported to {filepath}[/green]")


def main():
    parser = argparse.ArgumentParser(
        description="TLS Security Assessment CLI - Analyze SSL/TLS certificate security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s google.com                    Scan google.com on port 443
  %(prog)s example.com -p 8443           Scan on custom port
  %(prog)s example.com --json report.json Export to JSON
  %(prog)s example.com --brief           Show brief output only
  %(prog)s example.com --no-vulns        Skip vulnerability scanning
        """,
    )

    parser.add_argument("hostname", help="Domain name or IP address to scan")
    parser.add_argument(
        "-p", "--port", type=int, default=443, help="Port number (default: 443)"
    )
    parser.add_argument("--json", metavar="FILE", help="Export results to JSON file")
    parser.add_argument(
        "--brief",
        action="store_true",
        help="Show brief output (grade and key issues only)",
    )
    parser.add_argument(
        "--no-vulns",
        action="store_true",
        help="Skip vulnerability scanning (faster)",
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show verbose output"
    )

    args = parser.parse_args()

    if args.no_color:
        console.no_color = True

    # Clean hostname (remove protocol if provided)
    hostname = args.hostname.replace("https://", "").replace("http://", "").rstrip("/")

    # Print header
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]TLS Security Assessment CLI[/bold cyan]\n"
            f"[dim]Target: {hostname}:{args.port}[/dim]",
            border_style="cyan",
        )
    )
    console.print()

    # Run scan
    result = run_scan_with_progress(
        hostname, args.port, include_vulns=not args.no_vulns
    )

    if result.error:
        console.print(f"\n[bold red]Error:[/bold red] {result.error}")
        sys.exit(1)

    console.print()

    # Display results
    if result.score:
        console.print(create_grade_display(result.score.score, result.score.grade))
        console.print()

    if not args.brief:
        # Full output
        if result.certificate:
            console.print(display_certificate_info(result.certificate))
            console.print()

        if result.tls_config:
            console.print(display_tls_config(result.tls_config))
            console.print()

        if result.cipher_suites:
            console.print(display_cipher_suites(result.cipher_suites))
            console.print()

        console.print(display_chain_info(result.chain))
        console.print()

        console.print(display_revocation_info(result.revocation))
        console.print()

        # Display vulnerability results if available
        if result.vulnerabilities:
            console.print(display_vulnerabilities(result.vulnerabilities))
            console.print()

    if result.recommendations:
        console.print(display_recommendations(result.recommendations))
        console.print()

    # Export to JSON if requested
    if args.json:
        export_json(result, args.json)

    # Summary line
    if result.score:
        grade_color = get_grade_color(result.score.grade)
        critical_count = len(
            [r for r in result.recommendations if r.get("severity") == "Critical"]
        )
        high_count = len(
            [r for r in result.recommendations if r.get("severity") == "High"]
        )
        warning_count = len(
            [r for r in result.recommendations if r.get("severity") == "Warning"]
        )

        summary = f"[{grade_color}]Grade: {result.score.grade}[/{grade_color}]"
        if critical_count > 0:
            summary += f" | [bold red]{critical_count} Critical[/bold red]"
        if high_count > 0:
            summary += f" | [red]{high_count} High[/red]"
        if warning_count > 0:
            summary += f" | [yellow]{warning_count} Warnings[/yellow]"

        if result.vulnerabilities and result.vulnerabilities.total_vulnerabilities > 0:
            summary += f" | [red]{result.vulnerabilities.total_vulnerabilities} Vulnerabilities[/red]"

        console.print(Panel(summary, title="Summary", border_style="dim"))


if __name__ == "__main__":
    main()
