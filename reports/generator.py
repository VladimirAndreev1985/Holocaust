"""Report generator — creates PDF and HTML audit reports."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Template

from core.logger import get_logger
from models.device import Device
from models.vulnerability import Vulnerability

log = get_logger("reports")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Holocaust — Network Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #111116;
            color: #b0b0b8;
            padding: 40px;
        }
        .header {
            text-align: center;
            border-bottom: 1px solid #5a7ea0;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 { color: #8ca8c4; font-size: 2em; }
        .header .meta { color: #606070; margin-top: 8px; }
        .section { margin-bottom: 30px; }
        .section h2 {
            background: #18181e;
            padding: 10px 15px;
            border-left: 3px solid #5a7ea0;
            margin-bottom: 15px;
            color: #8ca8c4;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .stat-card {
            background: #18181e;
            padding: 20px;
            border-radius: 4px;
            text-align: center;
            border: 1px solid #252530;
        }
        .stat-card .number { font-size: 2em; color: #8ca8c4; font-weight: bold; }
        .stat-card .label { color: #606070; margin-top: 5px; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #252530;
        }
        th { background: #18181e; color: #8ca8c4; }
        tr:hover { background: #18181e; }
        .severity {
            padding: 3px 10px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .severity.critical { background: #c04848; color: #fff; }
        .severity.high { background: #a05050; color: #fff; }
        .severity.medium { background: #b09040; color: #fff; }
        .severity.low { background: #4a8a5a; color: #fff; }
        .severity.info { background: #5a7ea0; color: #fff; }
        .risk-critical { color: #c04848; font-weight: bold; }
        .risk-high { color: #a05050; font-weight: bold; }
        .risk-medium { color: #b09040; }
        .risk-low { color: #4a8a5a; }
        .footer {
            text-align: center;
            color: #404050;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #252530;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Holocaust — Network Audit Report</h1>
        <div class="meta">
            Generated: {{ timestamp }}<br>
            Target: {{ target }}<br>
            Scan duration: {{ duration }}
        </div>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="number">{{ devices | length }}</div>
            <div class="label">Devices Found</div>
        </div>
        <div class="stat-card">
            <div class="number">{{ vulns | length }}</div>
            <div class="label">Vulnerabilities</div>
        </div>
        <div class="stat-card">
            <div class="number">{{ critical_count }}</div>
            <div class="label">Critical Vulns</div>
        </div>
        <div class="stat-card">
            <div class="number">{{ cameras_count }}</div>
            <div class="label">IP Cameras</div>
        </div>
    </div>

    <div class="section">
        <h2>Discovered Devices</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Type</th>
                    <th>OS</th>
                    <th>Open Ports</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                {% for d in devices %}
                <tr>
                    <td>{{ d.ip }}</td>
                    <td>{{ d.hostname or '—' }}</td>
                    <td>{{ d.device_type.value }}</td>
                    <td>{{ d.os_name or '—' }}</td>
                    <td>{{ d.open_ports[:10] | join(', ') }}{% if d.open_ports | length > 10 %}...{% endif %}</td>
                    <td class="risk-{{ d.risk_level.value }}">{{ d.risk_level.value | upper }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>CVE</th>
                    <th>Title</th>
                    <th>Host</th>
                    <th>Port</th>
                    <th>CVSS</th>
                    <th>Severity</th>
                    <th>Exploitable</th>
                </tr>
            </thead>
            <tbody>
                {% for v in vulns %}
                <tr>
                    <td>{{ v.cve_id or '—' }}</td>
                    <td>{{ v.title }}</td>
                    <td>{{ v.host_ip }}</td>
                    <td>{{ v.affected_port or '—' }}</td>
                    <td>{{ v.cvss_score }}</td>
                    <td><span class="severity {{ v.severity.value }}">{{ v.severity.value | upper }}</span></td>
                    <td>{{ 'Yes' if v.is_exploitable else 'No' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="footer">
        Holocaust Network Auditor — Report generated automatically
    </div>
</body>
</html>"""


class ReportGenerator:
    """Generates audit reports in HTML and PDF formats."""

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.output_dir = output_dir or Path("reports_output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_html(
        self,
        devices: list[Device],
        vulnerabilities: list[Vulnerability],
        target: str = "",
        duration: str = "",
    ) -> Path:
        """Generate an HTML report."""
        log.info("Generating HTML report...")

        from models.device import DeviceType
        from models.vulnerability import VulnSeverity

        template = Template(HTML_TEMPLATE)
        html = template.render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            target=target or "Local Network",
            duration=duration or "N/A",
            devices=devices,
            vulns=vulnerabilities,
            critical_count=sum(
                1 for v in vulnerabilities
                if v.severity in (VulnSeverity.CRITICAL, VulnSeverity.HIGH)
            ),
            cameras_count=sum(
                1 for d in devices if d.device_type == DeviceType.IP_CAMERA
            ),
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = self.output_dir / f"report_{timestamp}.html"
        output_path.write_text(html, encoding="utf-8")

        log.info(f"HTML report saved: {output_path}")
        return output_path

    def generate_pdf(
        self,
        devices: list[Device],
        vulnerabilities: list[Vulnerability],
        target: str = "",
        duration: str = "",
    ) -> Optional[Path]:
        """Generate a PDF report (requires xhtml2pdf)."""
        log.info("Generating PDF report...")

        # First generate HTML
        html_path = self.generate_html(devices, vulnerabilities, target, duration)

        try:
            from xhtml2pdf import pisa

            pdf_path = html_path.with_suffix(".pdf")
            html_content = html_path.read_text(encoding="utf-8")

            with open(pdf_path, "wb") as pdf_file:
                status = pisa.CreatePDF(html_content, dest=pdf_file)

            if status.err:
                log.error("PDF generation had errors")
                return None

            log.info(f"PDF report saved: {pdf_path}")
            return pdf_path

        except ImportError:
            log.error("xhtml2pdf not installed — PDF export unavailable")
            return None
        except Exception as e:
            log.error(f"PDF generation failed: {e}")
            return None
