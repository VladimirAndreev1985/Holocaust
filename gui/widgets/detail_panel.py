"""Detail Panel — split-panel showing deep device information."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QLabel,
    QTableWidget, QTableWidgetItem, QTextEdit, QPushButton,
    QFrame, QHeaderView, QGroupBox, QGridLayout,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from models.device import Device, DeviceType
from models.vulnerability import Vulnerability


class DetailPanel(QWidget):
    """Bottom split panel showing detailed device information."""

    close_requested = Signal()
    exploit_requested = Signal(object, object)  # Device, Vulnerability

    def __init__(self, parent=None):
        super().__init__(parent)
        self._device: Device | None = None
        self._vulns: list[Vulnerability] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QFrame()
        header.setFixedHeight(36)
        header.setStyleSheet("background-color: #18181e; border-bottom: 1px solid #5a7ea0;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 0, 10, 0)

        self._title = QLabel("Device Details")
        self._title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self._title.setStyleSheet("color: #8ca8c4; border: none;")

        close_btn = QPushButton("X")
        close_btn.setFixedSize(24, 24)
        close_btn.setStyleSheet("""
            QPushButton { background: transparent; color: #888; border: none; font-weight: bold; }
            QPushButton:hover { color: #8ca8c4; }
        """)
        close_btn.clicked.connect(self.close_requested.emit)

        header_layout.addWidget(self._title)
        header_layout.addStretch()
        header_layout.addWidget(close_btn)
        layout.addWidget(header)

        # Tab widget for details
        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # Overview tab
        self._overview = QWidget()
        self._setup_overview_tab()
        self._tabs.addTab(self._overview, "Overview")

        # Services tab
        self._services_table = QTableWidget()
        self._services_table.setColumnCount(6)
        self._services_table.setHorizontalHeaderLabels(
            ["Port", "Protocol", "Service", "Product", "Version", "Info"]
        )
        self._services_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._services_table.setAlternatingRowColors(True)
        self._tabs.addTab(self._services_table, "Services")

        # Vulnerabilities tab
        self._vulns_table = QTableWidget()
        self._vulns_table.setColumnCount(6)
        self._vulns_table.setHorizontalHeaderLabels(
            ["CVE", "Title", "CVSS", "Severity", "Exploitable", "Action"]
        )
        self._vulns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._vulns_table.setAlternatingRowColors(True)
        self._tabs.addTab(self._vulns_table, "Vulnerabilities")

        # Raw/Notes tab
        self._notes = QTextEdit()
        self._notes.setPlaceholderText("Notes about this device...")
        self._tabs.addTab(self._notes, "Notes")

    def _setup_overview_tab(self) -> None:
        layout = QGridLayout(self._overview)
        layout.setSpacing(10)

        fields = [
            ("IP Address:", "ip"), ("MAC Address:", "mac"),
            ("Hostname:", "hostname"), ("Vendor:", "vendor"),
            ("Device Type:", "type"), ("OS:", "os"),
            ("Open Ports:", "ports"), ("Risk Level:", "risk"),
            ("Vulnerabilities:", "vuln_count"), ("Camera Model:", "camera"),
        ]

        self._overview_labels: dict[str, QLabel] = {}
        for i, (label_text, key) in enumerate(fields):
            row, col = i // 2, (i % 2) * 2
            label = QLabel(label_text)
            label.setStyleSheet("color: #606070; font-weight: bold; border: none;")
            value = QLabel("—")
            value.setStyleSheet("color: #b0b0b8; border: none;")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(label, row, col)
            layout.addWidget(value, row, col + 1)
            self._overview_labels[key] = value

        layout.setRowStretch(len(fields) // 2 + 1, 1)

    def show_device(self, device: Device, vulns: list[Vulnerability] | None = None) -> None:
        """Display device information."""
        self._device = device
        self._vulns = vulns or []
        self._title.setText(f"Device: {device.display_name}")

        # Overview
        self._overview_labels["ip"].setText(device.ip)
        self._overview_labels["mac"].setText(device.mac or "—")
        self._overview_labels["hostname"].setText(device.hostname or "—")
        self._overview_labels["vendor"].setText(device.vendor or "—")
        self._overview_labels["type"].setText(device.device_type.value)
        self._overview_labels["os"].setText(
            f"{device.os_name} {device.os_version}".strip() or "—"
        )
        self._overview_labels["ports"].setText(
            ", ".join(str(p) for p in device.open_ports[:20]) or "—"
        )

        risk_label = self._overview_labels["risk"]
        risk_label.setText(device.risk_level.value.upper())
        risk_label.setStyleSheet(f"color: {device.risk_level.color}; border: none; font-weight: bold;")

        self._overview_labels["vuln_count"].setText(str(len(device.vulnerabilities)))
        self._overview_labels["camera"].setText(device.camera_model or "—")

        # Services
        self._services_table.setRowCount(len(device.services))
        for row, svc in enumerate(device.services):
            self._services_table.setItem(row, 0, QTableWidgetItem(str(svc.port)))
            self._services_table.setItem(row, 1, QTableWidgetItem(svc.protocol))
            self._services_table.setItem(row, 2, QTableWidgetItem(svc.name))
            self._services_table.setItem(row, 3, QTableWidgetItem(svc.product))
            self._services_table.setItem(row, 4, QTableWidgetItem(svc.version))
            self._services_table.setItem(row, 5, QTableWidgetItem(svc.extra_info))

        # Vulnerabilities
        self._vulns_table.setRowCount(len(self._vulns))
        for row, vuln in enumerate(self._vulns):
            self._vulns_table.setItem(row, 0, QTableWidgetItem(vuln.cve_id or "—"))
            self._vulns_table.setItem(row, 1, QTableWidgetItem(vuln.title))
            self._vulns_table.setItem(row, 2, QTableWidgetItem(str(vuln.cvss_score)))

            sev_item = QTableWidgetItem(vuln.severity.value.upper())
            sev_item.setForeground(QColor(vuln.severity.color))
            self._vulns_table.setItem(row, 3, sev_item)

            self._vulns_table.setItem(row, 4,
                QTableWidgetItem("Yes" if vuln.is_exploitable else "No"))

            if vuln.has_exploit:
                btn = QPushButton("Exploit")
                btn.setObjectName("dangerButton")
                btn.setFixedHeight(26)
                btn.clicked.connect(lambda _, v=vuln: self._on_exploit(v))
                self._vulns_table.setCellWidget(row, 5, btn)

        self.setVisible(True)

    def _on_exploit(self, vuln: Vulnerability) -> None:
        if self._device:
            self.exploit_requested.emit(self._device, vuln)
