"""Report generator — creates PDF and HTML audit reports."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Template

from core.i18n import tr, get_language
from core.logger import get_logger
from models.device import Device
from models.vulnerability import Vulnerability

log = get_logger("reports")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
    <meta charset="UTF-8">
    <title>{{ lbl_title }}</title>
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
        <h1>{{ lbl_title }}</h1>
        <div class="meta">
            {{ lbl_generated }} {{ timestamp }}<br>
            {{ lbl_target }} {{ target }}<br>
            {{ lbl_duration }} {{ duration }}
        </div>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="number">{{ devices | length }}</div>
            <div class="label">{{ lbl_devices_found }}</div>
        </div>
        <div class="stat-card">
            <div class="number">{{ vulns | length }}</div>
            <div class="label">{{ lbl_vulnerabilities }}</div>
        </div>
        <div class="stat-card">
            <div class="number">{{ critical_count }}</div>
            <div class="label">{{ lbl_critical_vulns }}</div>
        </div>
        <div class="stat-card">
            <div class="number">{{ cameras_count }}</div>
            <div class="label">{{ lbl_ip_cameras }}</div>
        </div>
    </div>

    <div class="section">
        <h2>{{ lbl_discovered_devices }}</h2>
        <table>
            <thead>
                <tr>
                    <th>{{ lbl_ip_address }}</th>
                    <th>{{ lbl_hostname }}</th>
                    <th>{{ lbl_type }}</th>
                    <th>{{ lbl_os }}</th>
                    <th>{{ lbl_open_ports }}</th>
                    <th>{{ lbl_risk }}</th>
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
        <h2>{{ lbl_vulnerabilities }}</h2>
        <table>
            <thead>
                <tr>
                    <th>{{ lbl_cve }}</th>
                    <th>{{ lbl_vtitle }}</th>
                    <th>{{ lbl_host }}</th>
                    <th>{{ lbl_port }}</th>
                    <th>{{ lbl_cvss }}</th>
                    <th>{{ lbl_severity }}</th>
                    <th>{{ lbl_exploitable }}</th>
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
                    <td>{{ lbl_yes if v.is_exploitable else lbl_no }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="footer">
        {{ lbl_footer }}
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
            lang=get_language(),
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
            # Translated labels
            lbl_title=tr("Holocaust — Network Audit Report"),
            lbl_generated=tr("Generated:"),
            lbl_target=tr("Target:"),
            lbl_duration=tr("Scan duration:"),
            lbl_devices_found=tr("Devices Found"),
            lbl_vulnerabilities=tr("Vulnerabilities"),
            lbl_critical_vulns=tr("Critical Vulns"),
            lbl_ip_cameras=tr("IP Cameras"),
            lbl_discovered_devices=tr("Discovered Devices"),
            lbl_ip_address=tr("IP Address"),
            lbl_hostname=tr("Hostname"),
            lbl_type=tr("Type"),
            lbl_os=tr("OS"),
            lbl_open_ports=tr("Open Ports"),
            lbl_risk=tr("Risk"),
            lbl_cve=tr("CVE"),
            lbl_vtitle=tr("Title"),
            lbl_host=tr("Host"),
            lbl_port=tr("Port"),
            lbl_cvss=tr("CVSS"),
            lbl_severity=tr("Severity"),
            lbl_exploitable=tr("Exploitable"),
            lbl_yes=tr("Yes"),
            lbl_no=tr("No"),
            lbl_footer=tr("Holocaust Network Auditor — Report generated automatically"),
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
