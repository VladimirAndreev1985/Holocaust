"""Detail Panel — rich host profile with Info, Services, Vulns, Actions tabs."""

from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel,
    QTableWidget, QTableWidgetItem, QTextEdit, QPushButton,
    QFrame, QHeaderView, QGridLayout, QScrollArea, QGroupBox,
    QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from models.device import Device, DeviceType
from models.vulnerability import Vulnerability
from core.i18n import tr

_NOTES_FILE = Path("data/device_notes.json")


class DetailPanel(QWidget):
    """Bottom split panel — full host profile with actionable tabs."""

    close_requested = Signal()
    exploit_requested = Signal(object, object)  # Device, Vulnerability

    # Action signals — MainWindow connects these
    rescan_requested = Signal(object, str)       # Device, depth ("quick"/"standard"/"deep")
    vuln_scan_requested = Signal(object)         # Device
    brute_force_requested = Signal(object, str, int)  # Device, service, port
    web_scan_requested = Signal(object, int)     # Device, port
    send_to_msf_requested = Signal(object)       # Device
    send_to_attack_requested = Signal(object)    # Device

    def __init__(self, parent=None):
        super().__init__(parent)
        self._device: Device | None = None
        self._vulns: list[Vulnerability] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setFixedHeight(40)
        header.setStyleSheet("background-color: #18181e; border-bottom: 1px solid #5a7ea0;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 0, 10, 0)

        self._title = QLabel(tr("Device Details"))
        self._title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self._title.setStyleSheet("color: #8ca8c4; border: none;")

        # Quick action buttons in header
        self._rescan_btn = QPushButton(tr("Rescan"))
        self._rescan_btn.setFixedHeight(26)
        self._rescan_btn.setStyleSheet(self._action_btn_style("#5a7ea0"))
        self._rescan_btn.clicked.connect(lambda: self._emit_rescan("standard"))

        self._vuln_btn = QPushButton(tr("Vuln Scan"))
        self._vuln_btn.setFixedHeight(26)
        self._vuln_btn.setStyleSheet(self._action_btn_style("#b09040"))
        self._vuln_btn.clicked.connect(self._emit_vuln_scan)

        self._msf_btn = QPushButton(tr("Metasploit"))
        self._msf_btn.setFixedHeight(26)
        self._msf_btn.setStyleSheet(self._action_btn_style("#7060a0"))
        self._msf_btn.clicked.connect(self._emit_send_to_msf)

        self._attack_btn = QPushButton(tr("Attack"))
        self._attack_btn.setFixedHeight(26)
        self._attack_btn.setStyleSheet(self._action_btn_style("#c04848"))
        self._attack_btn.clicked.connect(self._emit_send_to_attack)

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(26, 26)
        close_btn.setStyleSheet("""
            QPushButton { background: transparent; color: #666; border: none; font-size: 14px; }
            QPushButton:hover { color: #c04848; }
        """)
        close_btn.clicked.connect(self.close_requested.emit)

        header_layout.addWidget(self._title)
        header_layout.addStretch()
        header_layout.addWidget(self._rescan_btn)
        header_layout.addWidget(self._vuln_btn)
        header_layout.addWidget(self._msf_btn)
        header_layout.addWidget(self._attack_btn)
        header_layout.addWidget(close_btn)
        layout.addWidget(header)

        # Tab widget
        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # === Tab 1: Overview ===
        self._overview = QWidget()
        self._setup_overview_tab()
        self._tabs.addTab(self._overview, tr("Info"))

        # === Tab 2: Services (with action buttons) ===
        self._services_table = QTableWidget()
        self._services_table.setColumnCount(8)
        self._services_table.setHorizontalHeaderLabels([
            tr("Port"), tr("Proto"), tr("Service"), tr("Product"),
            tr("Version"), tr("Info"), tr(""), tr(""),
        ])
        h = self._services_table.horizontalHeader()
        h.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        # Fixed width for action columns
        h.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)
        h.setSectionResizeMode(7, QHeaderView.ResizeMode.Fixed)
        self._services_table.setColumnWidth(6, 90)
        self._services_table.setColumnWidth(7, 90)
        self._services_table.setAlternatingRowColors(True)
        self._services_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabs.addTab(self._services_table, tr("Services"))

        # === Tab 3: Vulnerabilities ===
        self._vulns_table = QTableWidget()
        self._vulns_table.setColumnCount(6)
        self._vulns_table.setHorizontalHeaderLabels([
            tr("CVE"), tr("Title"), tr("CVSS"), tr("Severity"),
            tr("Exploitable"), tr("Action"),
        ])
        vh = self._vulns_table.horizontalHeader()
        vh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._vulns_table.setAlternatingRowColors(True)
        self._vulns_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tabs.addTab(self._vulns_table, tr("Vulns ({count})").format(count=0))

        # === Tab 4: Notes ===
        notes_widget = QWidget()
        notes_layout = QVBoxLayout(notes_widget)
        self._notes = QTextEdit()
        self._notes.setPlaceholderText(tr("Notes about this device..."))
        notes_layout.addWidget(self._notes)

        save_notes_btn = QPushButton(tr("Save Notes"))
        save_notes_btn.setFixedWidth(120)
        save_notes_btn.setStyleSheet(self._action_btn_style("#4a8a5a"))
        save_notes_btn.clicked.connect(self._save_notes)
        notes_layout.addWidget(save_notes_btn)

        self._tabs.addTab(notes_widget, tr("Notes"))

    def _setup_overview_tab(self) -> None:
        layout = QGridLayout(self._overview)
        layout.setSpacing(8)
        layout.setContentsMargins(10, 10, 10, 10)

        fields = [
            (tr("IP Address:"), "ip"),
            (tr("MAC Address:"), "mac"),
            (tr("Hostname:"), "hostname"),
            (tr("Vendor:"), "vendor"),
            (tr("Device Type:"), "type"),
            (tr("OS:"), "os"),
            (tr("Open Ports:"), "ports"),
            (tr("Risk Level:"), "risk"),
            (tr("Vulnerabilities:"), "vuln_count"),
            (tr("Scan Depth:"), "scan_depth"),
            (tr("Camera Model:"), "camera"),
            (tr("First Seen:"), "first_seen"),
        ]

        self._overview_labels: dict[str, QLabel] = {}
        for i, (label_text, key) in enumerate(fields):
            row, col = i // 2, (i % 2) * 2
            label = QLabel(label_text)
            label.setStyleSheet("color: #606070; font-weight: bold; border: none;")
            value = QLabel("—")
            value.setStyleSheet("color: #b0b0b8; border: none;")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value.setWordWrap(True)
            layout.addWidget(label, row, col)
            layout.addWidget(value, row, col + 1)
            self._overview_labels[key] = value

        layout.setRowStretch(len(fields) // 2 + 1, 1)

    def show_device(self, device: Device, vulns: list[Vulnerability] | None = None) -> None:
        """Display device information across all tabs."""
        self._device = device
        self._vulns = vulns or []
        self._title.setText(f"{device.display_name}  ({device.ip})")

        self._fill_overview(device)
        self._fill_services(device)
        self._fill_vulns(device, self._vulns)

        # Load saved notes
        self._notes.setPlainText(self._load_notes(device.ip))

        # Update vulns tab title with count
        vuln_idx = self._tabs.indexOf(self._vulns_table)
        self._tabs.setTabText(vuln_idx, tr("Vulns ({count})").format(count=len(self._vulns)))

        self.setVisible(True)

    def _fill_overview(self, device: Device) -> None:
        self._overview_labels["ip"].setText(device.ip)
        self._overview_labels["mac"].setText(device.mac or "—")
        self._overview_labels["hostname"].setText(device.hostname or "—")
        self._overview_labels["vendor"].setText(device.vendor or "—")
        self._overview_labels["type"].setText(device.device_type.value)
        self._overview_labels["os"].setText(
            f"{device.os_name} {device.os_version}".strip() or "—"
        )
        ports_str = ", ".join(str(p) for p in device.open_ports[:20])
        if len(device.open_ports) > 20:
            ports_str += f" (+{len(device.open_ports) - 20})"
        self._overview_labels["ports"].setText(ports_str or "—")

        risk_label = self._overview_labels["risk"]
        risk_label.setText(device.risk_level.value.upper())
        risk_label.setStyleSheet(
            f"color: {device.risk_level.color}; border: none; font-weight: bold;"
        )

        self._overview_labels["vuln_count"].setText(str(len(self._vulns)))
        self._overview_labels["camera"].setText(device.camera_model or "—")

        depth_names = {0: "—", 1: "Quick", 2: "Standard", 3: "Deep"}
        self._overview_labels["scan_depth"].setText(
            depth_names.get(device.scan_depth, "—")
        )
        self._overview_labels["first_seen"].setText(
            device.first_seen.strftime("%Y-%m-%d %H:%M") if device.first_seen else "—"
        )

    def _fill_services(self, device: Device) -> None:
        self._services_table.setRowCount(len(device.services))

        # Map service names to attack types
        brute_services = {
            "ssh", "ftp", "smb", "microsoft-ds", "rdp", "ms-wbt-server",
            "telnet", "http", "https", "mysql", "postgresql", "vnc",
            "redis", "snmp",
        }
        web_services = {"http", "https", "http-proxy", "http-alt"}

        for row, svc in enumerate(device.services):
            self._services_table.setItem(row, 0, QTableWidgetItem(str(svc.port)))
            self._services_table.setItem(row, 1, QTableWidgetItem(svc.protocol))
            self._services_table.setItem(row, 2, QTableWidgetItem(svc.name))
            self._services_table.setItem(row, 3, QTableWidgetItem(svc.product))
            self._services_table.setItem(row, 4, QTableWidgetItem(svc.version))
            self._services_table.setItem(row, 5, QTableWidgetItem(svc.extra_info))

            svc_lower = svc.name.lower()

            # Brute-Force button
            if svc_lower in brute_services:
                bf_btn = QPushButton(tr("Brute"))
                bf_btn.setFixedHeight(24)
                bf_btn.setStyleSheet(self._small_btn_style("#b09040"))
                bf_btn.clicked.connect(
                    lambda _, s=svc_lower, p=svc.port: self._emit_brute(s, p)
                )
                self._services_table.setCellWidget(row, 6, bf_btn)

            # Web Scan button
            if svc_lower in web_services:
                ws_btn = QPushButton(tr("Web Scan"))
                ws_btn.setFixedHeight(24)
                ws_btn.setStyleSheet(self._small_btn_style("#5a7ea0"))
                ws_btn.clicked.connect(
                    lambda _, p=svc.port: self._emit_web_scan(p)
                )
                self._services_table.setCellWidget(row, 7, ws_btn)

    def _fill_vulns(self, device: Device, vulns: list[Vulnerability]) -> None:
        self._vulns_table.setRowCount(len(vulns))

        for row, vuln in enumerate(vulns):
            self._vulns_table.setItem(row, 0, QTableWidgetItem(vuln.cve_id or "—"))
            self._vulns_table.setItem(row, 1, QTableWidgetItem(vuln.title))

            cvss_item = QTableWidgetItem(f"{vuln.cvss_score:.1f}")
            self._vulns_table.setItem(row, 2, cvss_item)

            sev_item = QTableWidgetItem(vuln.severity.value.upper())
            sev_item.setForeground(QColor(vuln.severity.color))
            self._vulns_table.setItem(row, 3, sev_item)

            self._vulns_table.setItem(
                row, 4,
                QTableWidgetItem("✓" if vuln.is_exploitable else "—")
            )

            if vuln.has_exploit:
                btn = QPushButton(tr("Exploit"))
                btn.setFixedHeight(24)
                btn.setStyleSheet(self._small_btn_style("#c04848"))
                btn.clicked.connect(lambda _, v=vuln: self._on_exploit(v))
                self._vulns_table.setCellWidget(row, 5, btn)

    # === Signal emitters ===

    def _emit_rescan(self, depth: str) -> None:
        if self._device:
            self.rescan_requested.emit(self._device, depth)

    def _emit_vuln_scan(self) -> None:
        if self._device:
            self.vuln_scan_requested.emit(self._device)

    def _emit_send_to_msf(self) -> None:
        if self._device:
            self.send_to_msf_requested.emit(self._device)

    def _emit_send_to_attack(self) -> None:
        if self._device:
            self.send_to_attack_requested.emit(self._device)

    def _emit_brute(self, service: str, port: int) -> None:
        if self._device:
            self.brute_force_requested.emit(self._device, service, port)

    def _emit_web_scan(self, port: int) -> None:
        if self._device:
            self.web_scan_requested.emit(self._device, port)

    def _on_exploit(self, vuln: Vulnerability) -> None:
        if self._device:
            self.exploit_requested.emit(self._device, vuln)

    # === Notes persistence ===

    def _load_notes(self, ip: str) -> str:
        try:
            if _NOTES_FILE.exists():
                data = json.loads(_NOTES_FILE.read_text(encoding="utf-8"))
                return data.get(ip, "")
        except Exception:
            pass
        return ""

    def _save_notes(self) -> None:
        if not self._device:
            return
        _NOTES_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            data = {}
            if _NOTES_FILE.exists():
                data = json.loads(_NOTES_FILE.read_text(encoding="utf-8"))
            text = self._notes.toPlainText().strip()
            if text:
                data[self._device.ip] = text
            else:
                data.pop(self._device.ip, None)
            _NOTES_FILE.write_text(
                json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception:
            pass

    # === Styles ===

    @staticmethod
    def _action_btn_style(color: str) -> str:
        return f"""
            QPushButton {{
                background-color: #1c1c24;
                color: {color};
                border: 1px solid {color};
                border-radius: 3px;
                padding: 2px 10px;
                font-size: 11px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {color};
                color: white;
            }}
        """

    @staticmethod
    def _small_btn_style(color: str) -> str:
        return f"""
            QPushButton {{
                background-color: transparent;
                color: {color};
                border: 1px solid {color};
                border-radius: 2px;
                padding: 1px 6px;
                font-size: 10px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {color};
                color: white;
            }}
        """
