"""
Report Generator — Generates PDF and HTML security reports from scan data.
"""
from datetime import datetime
from typing import Any

from jinja2 import Template

from models.scan import Scan


# HTML Report Template (inline for simplicity)
REPORT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLS Security Report — {{ target_url }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0A1628; color: #E8ECF1;
            padding: 40px; line-height: 1.6;
        }
        .report-header {
            text-align: center; margin-bottom: 40px;
            border-bottom: 2px solid #00D4AA; padding-bottom: 20px;
        }
        .report-header h1 { color: #00D4AA; font-size: 28px; }
        .report-header .subtitle { color: #8B95A5; margin-top: 8px; }
        .grade-badge {
            display: inline-block; width: 80px; height: 80px;
            border-radius: 50%; font-size: 36px; font-weight: 700;
            line-height: 80px; text-align: center; margin: 20px 0;
        }
        .grade-a { background: #00B894; color: white; }
        .grade-b { background: #00D4AA; color: white; }
        .grade-c { background: #FDCB6E; color: #0A1628; }
        .grade-d { background: #FF9F43; color: white; }
        .grade-f { background: #FF6B6B; color: white; }
        .score-text { font-size: 18px; color: #8B95A5; }
        .section {
            background: rgba(15, 31, 61, 0.8); border: 1px solid #1A2A4A;
            border-radius: 12px; padding: 24px; margin-bottom: 24px;
        }
        .section h2 {
            color: #00D4AA; font-size: 20px;
            margin-bottom: 16px; border-bottom: 1px solid #1A2A4A;
            padding-bottom: 8px;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #1A2A4A; }
        th { color: #00D4AA; font-weight: 600; }
        .badge {
            display: inline-block; padding: 3px 10px; border-radius: 12px;
            font-size: 12px; font-weight: 600;
        }
        .badge-strong { background: #00B894; color: white; }
        .badge-acceptable { background: #FDCB6E; color: #0A1628; }
        .badge-weak { background: #FF6B6B; color: white; }
        .badge-critical { background: #FF6B6B; color: white; }
        .badge-warning { background: #FDCB6E; color: #0A1628; }
        .badge-info { background: #00D4AA; color: #0A1628; }
        .kv-row { display: flex; margin-bottom: 8px; }
        .kv-label { color: #8B95A5; min-width: 200px; }
        .kv-value { color: #E8ECF1; }
        .check { color: #00B894; }
        .cross { color: #FF6B6B; }
        .rec-item { margin-bottom: 16px; padding: 12px; border-radius: 8px; background: rgba(26, 42, 74, 0.5); }
        .rec-title { font-weight: 600; margin-bottom: 4px; }
        .rec-desc { color: #8B95A5; font-size: 14px; }
        .rec-fix { color: #00D4AA; font-size: 14px; margin-top: 4px; }
        .footer { text-align: center; color: #8B95A5; margin-top: 40px; font-size: 13px; }
        @media print {
            body { background: white; color: #333; }
            .section { background: #f9f9f9; border-color: #ddd; }
            .section h2 { color: #0A1628; }
            th { color: #0A1628; }
        }
    </style>
</head>
<body>
    <div class="report-header">
        <h1>🔒 TLS Security Assessment Report</h1>
        <p class="subtitle">{{ target_url }} — Port {{ port }}</p>
        <div class="grade-badge grade-{{ grade_class }}">{{ grade }}</div>
        <p class="score-text">Security Score: {{ score }}/100</p>
        <p class="subtitle">Generated: {{ scan_date }}</p>
    </div>

    <!-- Certificate Details -->
    <div class="section">
        <h2>📜 Certificate Details</h2>
        {% if certificate %}
        <div class="kv-row"><span class="kv-label">Subject CN</span><span class="kv-value">{{ certificate.subject_cn or 'N/A' }}</span></div>
        <div class="kv-row"><span class="kv-label">Issuer</span><span class="kv-value">{{ certificate.issuer_cn or 'N/A' }} ({{ certificate.issuer_org or '' }})</span></div>
        <div class="kv-row"><span class="kv-label">Valid From</span><span class="kv-value">{{ certificate.valid_from or 'N/A' }}</span></div>
        <div class="kv-row"><span class="kv-label">Valid To</span><span class="kv-value">{{ certificate.valid_to or 'N/A' }}</span></div>
        <div class="kv-row"><span class="kv-label">Days Until Expiry</span><span class="kv-value">{{ certificate.days_until_expiry }}</span></div>
        <div class="kv-row"><span class="kv-label">Expired</span><span class="kv-value">{% if certificate.is_expired %}<span class="cross">✗ Yes</span>{% else %}<span class="check">✓ No</span>{% endif %}</span></div>
        <div class="kv-row"><span class="kv-label">Self-Signed</span><span class="kv-value">{% if certificate.is_self_signed %}<span class="cross">✗ Yes</span>{% else %}<span class="check">✓ No</span>{% endif %}</span></div>
        <div class="kv-row"><span class="kv-label">Public Key</span><span class="kv-value">{{ certificate.public_key_type or 'N/A' }} {{ certificate.public_key_size or '' }} bits</span></div>
        <div class="kv-row"><span class="kv-label">Signature Algorithm</span><span class="kv-value">{{ certificate.signature_algo or 'N/A' }}</span></div>
        <div class="kv-row"><span class="kv-label">Serial Number</span><span class="kv-value" style="font-family:monospace;font-size:13px;">{{ certificate.serial_number or 'N/A' }}</span></div>
        {% if certificate.san_list %}
        <div class="kv-row"><span class="kv-label">SANs</span><span class="kv-value">{{ certificate.san_list | join(', ') }}</span></div>
        {% endif %}
        {% else %}
        <p>No certificate data available.</p>
        {% endif %}
    </div>

    <!-- TLS Configuration -->
    <div class="section">
        <h2>🔐 TLS Configuration</h2>
        {% if tls_config %}
        <table>
            <tr><th>Protocol</th><th>Supported</th></tr>
            <tr><td>TLS 1.0</td><td>{% if tls_config.tls_1_0 %}<span class="cross">✗ Yes (Insecure)</span>{% else %}<span class="check">✓ No</span>{% endif %}</td></tr>
            <tr><td>TLS 1.1</td><td>{% if tls_config.tls_1_1 %}<span class="cross">✗ Yes (Deprecated)</span>{% else %}<span class="check">✓ No</span>{% endif %}</td></tr>
            <tr><td>TLS 1.2</td><td>{% if tls_config.tls_1_2 %}<span class="check">✓ Yes</span>{% else %}<span class="cross">✗ No</span>{% endif %}</td></tr>
            <tr><td>TLS 1.3</td><td>{% if tls_config.tls_1_3 %}<span class="check">✓ Yes</span>{% else %}<span class="cross">✗ No</span>{% endif %}</td></tr>
        </table>
        <div class="kv-row" style="margin-top:12px;"><span class="kv-label">Preferred Protocol</span><span class="kv-value">{{ tls_config.preferred_proto or 'N/A' }}</span></div>
        <div class="kv-row"><span class="kv-label">Insecure Renegotiation</span><span class="kv-value">{% if tls_config.insecure_reneg %}<span class="cross">✗ Yes</span>{% else %}<span class="check">✓ No</span>{% endif %}</span></div>
        {% else %}
        <p>No TLS configuration data available.</p>
        {% endif %}
    </div>

    <!-- Cipher Suites -->
    <div class="section">
        <h2>🛡️ Cipher Suites</h2>
        {% if cipher_suites %}
        <table>
            <tr><th>Cipher Name</th><th>Protocol</th><th>Key Exchange</th><th>Bits</th><th>Strength</th></tr>
            {% for cs in cipher_suites %}
            <tr>
                <td style="font-family:monospace;font-size:13px;">{{ cs.cipher_name }}</td>
                <td>{{ cs.protocol }}</td>
                <td>{{ cs.key_exchange }}</td>
                <td>{{ cs.bits }}</td>
                <td><span class="badge badge-{{ cs.strength|lower }}">{{ cs.strength }}</span></td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No cipher suite data available.</p>
        {% endif %}
    </div>

    <!-- Revocation -->
    <div class="section">
        <h2>🔄 Revocation Status</h2>
        {% if revocation %}
        <div class="kv-row"><span class="kv-label">OCSP Status</span><span class="kv-value">{{ revocation.ocsp_status }}</span></div>
        <div class="kv-row"><span class="kv-label">OCSP URL</span><span class="kv-value">{{ revocation.ocsp_url or 'N/A' }}</span></div>
        <div class="kv-row"><span class="kv-label">CRL Present</span><span class="kv-value">{% if revocation.crl_present %}<span class="check">✓ Yes</span>{% else %}<span class="cross">✗ No</span>{% endif %}</span></div>
        <div class="kv-row"><span class="kv-label">CRL URL</span><span class="kv-value">{{ revocation.crl_url or 'N/A' }}</span></div>
        {% else %}
        <p>No revocation data available.</p>
        {% endif %}
    </div>

    <!-- Certificate Chain -->
    <div class="section">
        <h2>🔗 Certificate Chain</h2>
        {% if chain %}
        <div class="kv-row"><span class="kv-label">Chain Depth</span><span class="kv-value">{{ chain.chain_depth }}</span></div>
        <div class="kv-row"><span class="kv-label">Chain Valid</span><span class="kv-value">{% if chain.chain_valid %}<span class="check">✓ Yes</span>{% else %}<span class="cross">✗ No</span>{% endif %}</span></div>
        {% if chain.chain_data %}
        <table style="margin-top:12px;">
            <tr><th>Subject</th><th>Issuer</th><th>Root?</th><th>Expired?</th></tr>
            {% for cert in chain.chain_data %}
            <tr>
                <td>{{ cert.subject }}</td>
                <td>{{ cert.issuer }}</td>
                <td>{% if cert.is_root %}✓{% else %}—{% endif %}</td>
                <td>{% if cert.is_expired %}<span class="cross">✗ Yes</span>{% else %}<span class="check">✓ No</span>{% endif %}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
        {% else %}
        <p>No chain data available.</p>
        {% endif %}
    </div>

    <!-- Recommendations -->
    <div class="section">
        <h2>💡 Recommendations</h2>
        {% for rec in recommendations %}
        <div class="rec-item">
            <span class="badge badge-{{ rec.severity|lower }}">{{ rec.severity }}</span>
            <p class="rec-title" style="margin-top:8px;">{{ rec.title }}</p>
            <p class="rec-desc">{{ rec.description }}</p>
            <p class="rec-fix">💡 {{ rec.fix_suggestion }}</p>
        </div>
        {% endfor %}
    </div>

    <div class="footer">
        <p>Generated by TLS Inspector • {{ scan_date }}</p>
    </div>
</body>
</html>
"""


class ReportGenerator:
    """Generates HTML and PDF security reports from scan data."""

    def build_report_data(self, scan: Scan) -> dict[str, Any]:
        """Build a dictionary of all report data from the scan model."""
        data = {
            "target_url": scan.target_url,
            "port": scan.port,
            "grade": scan.grade or "N/A",
            "score": scan.score or 0,
            "status": scan.status,
            "scan_date": scan.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.completed_at else "N/A",
            "certificate": None,
            "tls_config": None,
            "cipher_suites": [],
            "revocation": None,
            "chain": None,
            "recommendations": [],
        }

        if scan.certificate:
            data["certificate"] = {
                "subject_cn": scan.certificate.subject_cn,
                "issuer_cn": scan.certificate.issuer_cn,
                "issuer_org": scan.certificate.issuer_org,
                "valid_from": str(scan.certificate.valid_from) if scan.certificate.valid_from else None,
                "valid_to": str(scan.certificate.valid_to) if scan.certificate.valid_to else None,
                "days_until_expiry": scan.certificate.days_until_expiry,
                "is_expired": scan.certificate.is_expired,
                "is_self_signed": scan.certificate.is_self_signed,
                "serial_number": scan.certificate.serial_number,
                "signature_algo": scan.certificate.signature_algo,
                "public_key_type": scan.certificate.public_key_type,
                "public_key_size": scan.certificate.public_key_size,
                "san_list": scan.certificate.san_list or [],
            }

        if scan.tls_config:
            data["tls_config"] = {
                "tls_1_0": scan.tls_config.tls_1_0,
                "tls_1_1": scan.tls_config.tls_1_1,
                "tls_1_2": scan.tls_config.tls_1_2,
                "tls_1_3": scan.tls_config.tls_1_3,
                "insecure_reneg": scan.tls_config.insecure_reneg,
                "preferred_proto": scan.tls_config.preferred_proto,
            }

        for cs in scan.cipher_suites:
            data["cipher_suites"].append({
                "cipher_name": cs.cipher_name,
                "protocol": cs.protocol,
                "key_exchange": cs.key_exchange,
                "strength": cs.strength,
                "is_dangerous": cs.is_dangerous,
                "bits": cs.bits,
            })

        if scan.revocation:
            data["revocation"] = {
                "ocsp_status": scan.revocation.ocsp_status,
                "ocsp_url": scan.revocation.ocsp_url,
                "crl_present": scan.revocation.crl_present,
                "crl_url": scan.revocation.crl_url,
                "stapling_support": scan.revocation.stapling_support,
            }

        if scan.chain:
            data["chain"] = {
                "chain_depth": scan.chain.chain_depth,
                "chain_valid": scan.chain.chain_valid,
                "chain_data": scan.chain.chain_data or [],
                "has_broken_chain": scan.chain.has_broken_chain,
                "has_expired_intermediate": scan.chain.has_expired_intermediate,
            }

        for rec in scan.recommendations:
            data["recommendations"].append({
                "severity": rec.severity,
                "title": rec.title,
                "description": rec.description,
                "fix_suggestion": rec.fix_suggestion,
            })

        return data

    def generate_html(self, scan: Scan) -> str:
        """Generate an HTML report string."""
        data = self.build_report_data(scan)
        grade = data["grade"].replace("+", "").lower()
        grade_class = f"{grade}" if grade in ("a", "b", "c", "d", "f") else "f"
        data["grade_class"] = grade_class

        template = Template(REPORT_HTML_TEMPLATE)
        return template.render(**data)

    def generate_pdf(self, scan: Scan) -> bytes:
        """Generate a PDF report from the HTML template."""
        html_content = self.generate_html(scan)

        try:
            from weasyprint import HTML
            pdf_bytes = HTML(string=html_content).write_pdf()
            return pdf_bytes
        except ImportError:
            # Fallback: return HTML as bytes if weasyprint not available
            return html_content.encode("utf-8")
        except Exception:
            return html_content.encode("utf-8")
