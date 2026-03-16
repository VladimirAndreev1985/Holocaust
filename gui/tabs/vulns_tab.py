"""Vulnerabilities & Metasploit Tab — CVE table and exploit launcher."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QLineEdit, QGroupBox, QTextEdit, QSplitter, QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont

from models.vulnerability import Vulnerability, VulnSeverity


class VulnsTab(QWidget):
    """Vulnerability management and exploit execution tab."""

    exploit_requested = Signal(object)  # Vulnerability

    def __init__(self, parent=None):
        super().__init__(parent)
        self._vulns: list[Vulnerability] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        header = QHBoxLayout()
        title = QLabel("Vulnerabilities & Exploits")
        title.setObjectName("titleLabel")
        header.addWidget(title)
        header.addStretch()

        self._count_label = QLabel("0 vulnerabilities")
        self._count_label.setStyleSheet("color: #8888aa;")
        header.addWidget(self._count_label)
        layout.addLayout(header)

        # Filters
        filter_layout = QHBoxLayout()

        self._severity_filter = QComboBox()
        self._severity_filter.addItem("All Severities", None)
        self._severity_filter.addItem("Critical", VulnSeverity.CRITICAL)
        self._severity_filter.addItem("High", VulnSeverity.HIGH)
        self._severity_filter.addItem("Medium", VulnSeverity.MEDIUM)
        self._severity_filter.addItem("Low", VulnSeverity.LOW)
        self._severity_filter.addItem("Info", VulnSeverity.INFO)
        self._severity_filter.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(QLabel("Severity:"))
        filter_layout.addWidget(self._severity_filter)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search CVE, title, host...")
        self._search.setMaximumWidth(300)
        self._search.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._search)

        self._exploitable_only = QPushButton("Exploitable Only")
        self._exploitable_only.setCheckable(True)
        self._exploitable_only.toggled.connect(self._apply_filters)
        filter_layout.addWidget(self._exploitable_only)

        filter_layout.addStretch()
        layout.addLayout(filter_layout)

        # Splitter: table + details
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Vulnerability table
        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels([
            "CVE", "Title", "Host", "Port", "CVSS",
            "Severity", "Exploitable", "Action"
        ])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSortingEnabled(True)
        self._table.cellClicked.connect(self._on_vuln_clicked)
        splitter.addWidget(self._table)

        # Detail panel
        detail_group = QGroupBox("Vulnerability Details")
        detail_layout = QVBoxLayout(detail_group)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setMaximumHeight(200)
        detail_layout.addWidget(self._detail_text)

        action_layout = QHBoxLayout()
        self._exploit_btn = QPushButton("Launch Best Exploit")
        self._exploit_btn.setObjectName("dangerButton")
        self._exploit_btn.setEnabled(False)
        self._exploit_btn.clicked.connect(self._on_exploit)

        self._copy_btn = QPushButton("Copy CVE")
        self._copy_btn.clicked.connect(self._on_copy_cve)

        action_layout.addWidget(self._exploit_btn)
        action_layout.addWidget(self._copy_btn)
        action_layout.addStretch()
        detail_layout.addLayout(action_layout)

        splitter.addWidget(detail_group)
        splitter.setSizes([400, 200])
        layout.addWidget(splitter, 1)

    def set_vulnerabilities(self, vulns: list[Vulnerability]) -> None:
        self._vulns = vulns
        self._apply_filters()

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        self._vulns.append(vuln)
        self._apply_filters()

    def _apply_filters(self) -> None:
        severity = self._severity_filter.currentData()
        search = self._search.text().lower()
        exploitable = self._exploitable_only.isChecked()

        filtered = []
        for v in self._vulns:
            if severity and v.severity != severity:
                continue
            if exploitable and not v.is_exploitable:
                continue
            if search:
                searchable = f"{v.cve_id} {v.title} {v.host_ip} {v.description}".lower()
                if search not in searchable:
                    continue
            filtered.append(v)

        self._populate_table(filtered)
        self._count_label.setText(f"{len(filtered)} vulnerabilities")

    def _populate_table(self, vulns: list[Vulnerability]) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(vulns))

        for row, vuln in enumerate(vulns):
            self._table.setItem(row, 0, QTableWidgetItem(vuln.cve_id or "—"))
            self._table.setItem(row, 1, QTableWidgetItem(vuln.title))
            self._table.setItem(row, 2, QTableWidgetItem(vuln.host_ip))
            self._table.setItem(row, 3, QTableWidgetItem(str(vuln.affected_port) if vuln.affected_port else "—"))
            self._table.setItem(row, 4, QTableWidgetItem(str(vuln.cvss_score)))

            sev_item = QTableWidgetItem(vuln.severity.value.upper())
            sev_item.setForeground(QColor(vuln.severity.color))
            sev_item.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            self._table.setItem(row, 5, sev_item)

            exp_item = QTableWidgetItem("YES" if vuln.is_exploitable else "No")
            if vuln.is_exploitable:
                exp_item.setForeground(QColor("#e74c3c"))
            self._table.setItem(row, 6, exp_item)

            # Store reference
            self._table.item(row, 0).setData(Qt.ItemDataRole.UserRole, vuln)

            if vuln.has_exploit:
                btn = QPushButton("Exploit")
                btn.setObjectName("dangerButton")
                btn.setFixedHeight(26)
                btn.clicked.connect(lambda _, v=vuln: self._launch_exploit(v))
                self._table.setCellWidget(row, 7, btn)

        self._table.setSortingEnabled(True)

    def _on_vuln_clicked(self, row: int, col: int) -> None:
        item = self._table.item(row, 0)
        if not item:
            return
        vuln = item.data(Qt.ItemDataRole.UserRole)
        if not vuln:
            return

        self._exploit_btn.setEnabled(vuln.has_exploit)

        details = (
            f"<b>{vuln.cve_id or 'N/A'}</b> — {vuln.title}<br><br>"
            f"<b>Host:</b> {vuln.host_ip}:{vuln.affected_port}<br>"
            f"<b>CVSS:</b> {vuln.cvss_score} ({vuln.severity.value})<br>"
            f"<b>Source:</b> {vuln.source.value}<br>"
            f"<b>Confirmed:</b> {'Yes' if vuln.is_confirmed else 'No'}<br><br>"
            f"<b>Description:</b><br>{vuln.description}<br><br>"
        )

        if vuln.exploits:
            details += "<b>Available Exploits:</b><br>"
            for exp in vuln.exploits:
                details += f"  - {exp.name} ({exp.source}) [{exp.reliability}]<br>"
                if exp.module_path:
                    details += f"    Module: <code>{exp.module_path}</code><br>"

        if vuln.references:
            details += "<br><b>References:</b><br>"
            for ref in vuln.references[:5]:
                details += f"  - {ref}<br>"

        self._detail_text.setHtml(details)

    def _launch_exploit(self, vuln: Vulnerability) -> None:
        reply = QMessageBox.question(
            self, "Confirm Exploit",
            f"Launch exploit for {vuln.cve_id or vuln.title} "
            f"against {vuln.host_ip}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.exploit_requested.emit(vuln)

    def _on_exploit(self) -> None:
        row = self._table.currentRow()
        if row >= 0:
            item = self._table.item(row, 0)
            if item:
                vuln = item.data(Qt.ItemDataRole.UserRole)
                if vuln:
                    self._launch_exploit(vuln)

    def _on_copy_cve(self) -> None:
        row = self._table.currentRow()
        if row >= 0:
            item = self._table.item(row, 0)
            if item and item.text() != "—":
                from PySide6.QtWidgets import QApplication
                QApplication.clipboard().setText(item.text())
