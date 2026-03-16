"""Attack Tab — unified attack interface with sub-panels for MITM, WiFi, Web, Payloads, Brute-Force."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QTabWidget, QLineEdit, QComboBox, QSpinBox,
    QTextEdit, QCheckBox, QGroupBox, QGridLayout, QFileDialog,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
    QDoubleSpinBox, QSplitter,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from core.i18n import tr


class _OutputConsole(QTextEdit):
    """Dark console-style output widget."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 9))
        self.setStyleSheet("""
            QTextEdit {
                background-color: #0b0b0f;
                color: #b0b0b8;
                border: 1px solid #252530;
                padding: 5px;
            }
        """)
        self.setMaximumHeight(250)

    def append_line(self, text: str, color: str = "#b0b0b8") -> None:
        self.append(f'<span style="color:{color}">{text}</span>')
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())


class _StatusIndicator(QLabel):
    """Colored status dot + text."""

    def __init__(self, text: str = "Idle", parent=None):
        super().__init__(parent)
        self.set_status(text, "#606070")

    def set_status(self, text: str, color: str) -> None:
        self.setText(f"● {text}")
        self.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 12px;")


# =============================================================================
# Sub-panels
# =============================================================================

class MitmPanel(QWidget):
    """ARP Spoofing / MITM attack panel."""

    start_requested = Signal(str, str, str, bool, bool)  # iface, target, gw, two_way, capture
    stop_requested = Signal()
    dns_spoof_requested = Signal(str, str)  # domain, redirect_ip

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Header
        header = QHBoxLayout()
        title = QLabel(tr("ARP Spoofing / MITM"))
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._status = _StatusIndicator()
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self._status)
        layout.addLayout(header)

        # Config
        config = QGroupBox(tr("Configuration"))
        grid = QGridLayout(config)

        grid.addWidget(QLabel(tr("Interface:")), 0, 0)
        self._iface_input = QLineEdit()
        self._iface_input.setPlaceholderText("eth0, wlan0...")
        grid.addWidget(self._iface_input, 0, 1)

        grid.addWidget(QLabel(tr("Target IP:")), 1, 0)
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("192.168.1.100")
        grid.addWidget(self._target_input, 1, 1)

        grid.addWidget(QLabel(tr("Gateway IP:")), 2, 0)
        self._gateway_input = QLineEdit()
        self._gateway_input.setPlaceholderText("192.168.1.1")
        grid.addWidget(self._gateway_input, 2, 1)

        self._two_way = QCheckBox(tr("Two-way (full MITM)"))
        self._two_way.setChecked(True)
        grid.addWidget(self._two_way, 3, 0, 1, 2)

        self._capture = QCheckBox(tr("Capture packets (tcpdump)"))
        grid.addWidget(self._capture, 4, 0, 1, 2)

        layout.addWidget(config)

        # DNS Spoofing
        dns_group = QGroupBox(tr("DNS Spoofing (requires active MITM)"))
        dns_layout = QHBoxLayout(dns_group)
        self._dns_domain = QLineEdit()
        self._dns_domain.setPlaceholderText("example.com")
        self._dns_redirect = QLineEdit()
        self._dns_redirect.setPlaceholderText("Redirect IP")
        self._dns_btn = QPushButton(tr("Add DNS Rule"))
        self._dns_btn.clicked.connect(self._on_dns_spoof)
        dns_layout.addWidget(QLabel(tr("Domain:")))
        dns_layout.addWidget(self._dns_domain)
        dns_layout.addWidget(QLabel(tr("→")))
        dns_layout.addWidget(self._dns_redirect)
        dns_layout.addWidget(self._dns_btn)
        layout.addWidget(dns_group)

        # Buttons
        btn_layout = QHBoxLayout()
        self._start_btn = QPushButton(tr("Start MITM"))
        self._start_btn.setObjectName("primaryButton")
        self._start_btn.setMinimumWidth(150)
        self._start_btn.clicked.connect(self._on_start)

        self._stop_btn = QPushButton(tr("Stop"))
        self._stop_btn.setObjectName("dangerButton")
        self._stop_btn.setMinimumWidth(100)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._on_stop)

        btn_layout.addStretch()
        btn_layout.addWidget(self._start_btn)
        btn_layout.addWidget(self._stop_btn)
        layout.addLayout(btn_layout)

        # Output console
        self._console = _OutputConsole()
        layout.addWidget(self._console, 1)

    def set_target(self, ip: str, gateway: str = "") -> None:
        self._target_input.setText(ip)
        if gateway:
            self._gateway_input.setText(gateway)

    def set_interface(self, iface: str) -> None:
        self._iface_input.setText(iface)

    def set_running(self, running: bool) -> None:
        self._start_btn.setEnabled(not running)
        self._stop_btn.setEnabled(running)
        if running:
            self._status.set_status(tr("Active"), "#c04848")
        else:
            self._status.set_status(tr("Idle"), "#606070")

    def append_output(self, text: str, color: str = "#b0b0b8") -> None:
        self._console.append_line(text, color)

    def _on_start(self) -> None:
        iface = self._iface_input.text().strip()
        target = self._target_input.text().strip()
        gateway = self._gateway_input.text().strip()
        if not all([iface, target, gateway]):
            QMessageBox.warning(self, tr("Missing Fields"),
                                tr("Interface, target IP, and gateway IP are required."))
            return
        self.start_requested.emit(
            iface, target, gateway,
            self._two_way.isChecked(), self._capture.isChecked()
        )

    def _on_stop(self) -> None:
        self.stop_requested.emit()

    def _on_dns_spoof(self) -> None:
        domain = self._dns_domain.text().strip()
        redirect = self._dns_redirect.text().strip()
        if domain and redirect:
            self.dns_spoof_requested.emit(domain, redirect)


class WiFiAttackPanel(QWidget):
    """WiFi attack panel — deauth, handshake, WPS."""

    deauth_requested = Signal(str, str, str, int)  # iface, bssid, client, count
    deauth_stop_requested = Signal()
    handshake_requested = Signal(str, str, int, int, bool, str)  # iface, bssid, ch, timeout, auto_deauth, wordlist
    wps_requested = Signal(str, str, int, str, int)  # iface, bssid, ch, method, timeout
    wps_stop_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel(tr("WiFi Attacks"))
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._status = _StatusIndicator()
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self._status)
        layout.addLayout(header)

        # Common settings
        common = QGroupBox(tr("Target"))
        grid = QGridLayout(common)
        grid.addWidget(QLabel(tr("Monitor Interface:")), 0, 0)
        self._iface_input = QLineEdit()
        self._iface_input.setPlaceholderText("wlan0mon")
        grid.addWidget(self._iface_input, 0, 1)

        grid.addWidget(QLabel(tr("AP BSSID:")), 1, 0)
        self._bssid_input = QLineEdit()
        self._bssid_input.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        grid.addWidget(self._bssid_input, 1, 1)

        grid.addWidget(QLabel(tr("Channel:")), 2, 0)
        self._channel_spin = QSpinBox()
        self._channel_spin.setRange(1, 165)
        self._channel_spin.setValue(6)
        grid.addWidget(self._channel_spin, 2, 1)

        layout.addWidget(common)

        # Attack tabs
        attacks = QTabWidget()

        # --- Deauth tab ---
        deauth_w = QWidget()
        dl = QVBoxLayout(deauth_w)
        dg = QGridLayout()

        dg.addWidget(QLabel(tr("Client MAC (empty=broadcast):")), 0, 0)
        self._deauth_client = QLineEdit()
        self._deauth_client.setPlaceholderText(tr("Leave empty for broadcast deauth"))
        dg.addWidget(self._deauth_client, 0, 1)

        dg.addWidget(QLabel(tr("Packet count (0=continuous):")), 1, 0)
        self._deauth_count = QSpinBox()
        self._deauth_count.setRange(0, 100000)
        self._deauth_count.setValue(0)
        dg.addWidget(self._deauth_count, 1, 1)

        dl.addLayout(dg)
        btn_row = QHBoxLayout()
        self._deauth_start_btn = QPushButton(tr("Start Deauth"))
        self._deauth_start_btn.setObjectName("dangerButton")
        self._deauth_start_btn.clicked.connect(self._on_deauth_start)
        self._deauth_stop_btn = QPushButton(tr("Stop"))
        self._deauth_stop_btn.setEnabled(False)
        self._deauth_stop_btn.clicked.connect(self.deauth_stop_requested.emit)
        btn_row.addStretch()
        btn_row.addWidget(self._deauth_start_btn)
        btn_row.addWidget(self._deauth_stop_btn)
        dl.addLayout(btn_row)
        attacks.addTab(deauth_w, tr("Deauth"))

        # --- Handshake tab ---
        hs_w = QWidget()
        hl = QVBoxLayout(hs_w)
        hg = QGridLayout()

        hg.addWidget(QLabel(tr("Capture timeout (sec):")), 0, 0)
        self._hs_timeout = QSpinBox()
        self._hs_timeout.setRange(10, 600)
        self._hs_timeout.setValue(120)
        hg.addWidget(self._hs_timeout, 0, 1)

        self._hs_auto_deauth = QCheckBox(tr("Auto-deauth to force handshake"))
        self._hs_auto_deauth.setChecked(True)
        hg.addWidget(self._hs_auto_deauth, 1, 0, 1, 2)

        hg.addWidget(QLabel(tr("Wordlist (for auto-crack):")), 2, 0)
        wl_row = QHBoxLayout()
        self._hs_wordlist = QLineEdit()
        self._hs_wordlist.setPlaceholderText("/usr/share/wordlists/rockyou.txt")
        wl_browse = QPushButton(tr("Browse"))
        wl_browse.setFixedWidth(70)
        wl_browse.clicked.connect(self._browse_wordlist)
        wl_row.addWidget(self._hs_wordlist)
        wl_row.addWidget(wl_browse)
        hg.addLayout(wl_row, 2, 1)

        hl.addLayout(hg)
        hs_btn = QHBoxLayout()
        self._hs_start_btn = QPushButton(tr("Capture Handshake"))
        self._hs_start_btn.setObjectName("primaryButton")
        self._hs_start_btn.clicked.connect(self._on_handshake_start)
        hs_btn.addStretch()
        hs_btn.addWidget(self._hs_start_btn)
        hl.addLayout(hs_btn)
        attacks.addTab(hs_w, tr("Handshake"))

        # --- WPS tab ---
        wps_w = QWidget()
        wl2 = QVBoxLayout(wps_w)
        wg = QGridLayout()

        wg.addWidget(QLabel(tr("Method:")), 0, 0)
        self._wps_method = QComboBox()
        self._wps_method.addItems(["reaver", "bully"])
        wg.addWidget(self._wps_method, 0, 1)

        wg.addWidget(QLabel(tr("Timeout (sec):")), 1, 0)
        self._wps_timeout = QSpinBox()
        self._wps_timeout.setRange(60, 7200)
        self._wps_timeout.setValue(600)
        wg.addWidget(self._wps_timeout, 1, 1)

        wl2.addLayout(wg)
        wps_btn = QHBoxLayout()
        self._wps_start_btn = QPushButton(tr("Start WPS Attack"))
        self._wps_start_btn.setObjectName("dangerButton")
        self._wps_start_btn.clicked.connect(self._on_wps_start)
        self._wps_stop_btn = QPushButton(tr("Stop"))
        self._wps_stop_btn.setEnabled(False)
        self._wps_stop_btn.clicked.connect(self.wps_stop_requested.emit)
        wps_btn.addStretch()
        wps_btn.addWidget(self._wps_start_btn)
        wps_btn.addWidget(self._wps_stop_btn)
        wl2.addLayout(wps_btn)
        attacks.addTab(wps_w, tr("WPS"))

        layout.addWidget(attacks)

        # Output
        self._console = _OutputConsole()
        layout.addWidget(self._console, 1)

    def set_target(self, bssid: str = "", channel: int = 0) -> None:
        if bssid:
            self._bssid_input.setText(bssid)
        if channel:
            self._channel_spin.setValue(channel)

    def set_interface(self, iface: str) -> None:
        self._iface_input.setText(iface)

    def set_deauth_running(self, running: bool) -> None:
        self._deauth_start_btn.setEnabled(not running)
        self._deauth_stop_btn.setEnabled(running)
        if running:
            self._status.set_status(tr("Deauth Active"), "#c04848")
        else:
            self._status.set_status(tr("Idle"), "#606070")

    def set_wps_running(self, running: bool) -> None:
        self._wps_start_btn.setEnabled(not running)
        self._wps_stop_btn.setEnabled(running)

    def append_output(self, text: str, color: str = "#b0b0b8") -> None:
        self._console.append_line(text, color)

    def _on_deauth_start(self) -> None:
        iface = self._iface_input.text().strip()
        bssid = self._bssid_input.text().strip()
        if not iface or not bssid:
            QMessageBox.warning(self, tr("Missing"), tr("Interface and BSSID required."))
            return
        self.deauth_requested.emit(
            iface, bssid,
            self._deauth_client.text().strip(),
            self._deauth_count.value(),
        )

    def _on_handshake_start(self) -> None:
        iface = self._iface_input.text().strip()
        bssid = self._bssid_input.text().strip()
        if not iface or not bssid:
            QMessageBox.warning(self, tr("Missing"), tr("Interface and BSSID required."))
            return
        self.handshake_requested.emit(
            iface, bssid,
            self._channel_spin.value(),
            self._hs_timeout.value(),
            self._hs_auto_deauth.isChecked(),
            self._hs_wordlist.text().strip(),
        )

    def _on_wps_start(self) -> None:
        iface = self._iface_input.text().strip()
        bssid = self._bssid_input.text().strip()
        if not iface or not bssid:
            QMessageBox.warning(self, tr("Missing"), tr("Interface and BSSID required."))
            return
        self.wps_requested.emit(
            iface, bssid,
            self._channel_spin.value(),
            self._wps_method.currentText(),
            self._wps_timeout.value(),
        )

    def _browse_wordlist(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Select Wordlist"), "",
            tr("Text Files (*.txt);;All Files (*)")
        )
        if path:
            self._hs_wordlist.setText(path)


class WebScanPanel(QWidget):
    """Web vulnerability scan panel."""

    scan_requested = Signal(str, int, bool)   # target, port, use_ssl
    scan_stop_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel(tr("Web Vulnerability Scanner"))
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._status = _StatusIndicator()
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self._status)
        layout.addLayout(header)

        # Config
        config = QGroupBox(tr("Target"))
        grid = QGridLayout(config)

        grid.addWidget(QLabel(tr("Target IP:")), 0, 0)
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("192.168.1.100")
        grid.addWidget(self._target_input, 0, 1)

        grid.addWidget(QLabel(tr("Port:")), 1, 0)
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(80)
        grid.addWidget(self._port_spin, 1, 1)

        self._use_ssl = QCheckBox(tr("Use HTTPS"))
        grid.addWidget(self._use_ssl, 2, 0, 1, 2)

        layout.addWidget(config)

        # Buttons
        btn_row = QHBoxLayout()
        self._scan_btn = QPushButton(tr("Start Web Scan"))
        self._scan_btn.setObjectName("primaryButton")
        self._scan_btn.setMinimumWidth(150)
        self._scan_btn.clicked.connect(self._on_scan)

        self._stop_btn = QPushButton(tr("Stop"))
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self.scan_stop_requested.emit)

        btn_row.addStretch()
        btn_row.addWidget(self._scan_btn)
        btn_row.addWidget(self._stop_btn)
        layout.addLayout(btn_row)

        # Results table
        self._results_table = QTableWidget()
        self._results_table.setColumnCount(4)
        self._results_table.setHorizontalHeaderLabels(
            [tr("Severity"), tr("Title"), tr("Port"), tr("Description")]
        )
        self._results_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._results_table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.Stretch
        )
        self._results_table.setAlternatingRowColors(True)
        self._results_table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        layout.addWidget(self._results_table, 1)

    def set_target(self, ip: str, port: int = 80) -> None:
        self._target_input.setText(ip)
        self._port_spin.setValue(port)

    def set_running(self, running: bool) -> None:
        self._scan_btn.setEnabled(not running)
        self._stop_btn.setEnabled(running)
        if running:
            self._status.set_status(tr("Scanning..."), "#b09040")
        else:
            self._status.set_status(tr("Idle"), "#606070")

    def add_vulnerability(self, vuln) -> None:
        row = self._results_table.rowCount()
        self._results_table.insertRow(row)

        sev_item = QTableWidgetItem(vuln.severity.value.upper())
        sev_item.setForeground(QColor(vuln.severity.color))
        self._results_table.setItem(row, 0, sev_item)
        self._results_table.setItem(row, 1, QTableWidgetItem(vuln.title))
        self._results_table.setItem(row, 2, QTableWidgetItem(str(vuln.affected_port)))
        self._results_table.setItem(row, 3, QTableWidgetItem(vuln.description[:200]))

    def clear_results(self) -> None:
        self._results_table.setRowCount(0)

    def _on_scan(self) -> None:
        target = self._target_input.text().strip()
        if not target:
            QMessageBox.warning(self, tr("Missing"), tr("Target IP required."))
            return
        self.scan_requested.emit(target, self._port_spin.value(), self._use_ssl.isChecked())


class PayloadPanel(QWidget):
    """msfvenom payload generation panel."""

    generate_requested = Signal(str, str, int, str, str, int, str)
    # payload, lhost, lport, format, encoder, iterations, output_dir

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        title = QLabel(tr("Payload Generator (msfvenom)"))
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        layout.addWidget(title)

        # Template + Custom
        config = QGroupBox(tr("Configuration"))
        grid = QGridLayout(config)

        grid.addWidget(QLabel(tr("Template:")), 0, 0)
        self._template_combo = QComboBox()
        self._template_combo.addItem(tr("Custom..."), "")
        from modules.payload_generator import PAYLOAD_TEMPLATES
        for name in PAYLOAD_TEMPLATES:
            self._template_combo.addItem(name, name)
        self._template_combo.currentIndexChanged.connect(self._on_template_changed)
        grid.addWidget(self._template_combo, 0, 1)

        grid.addWidget(QLabel(tr("Payload:")), 1, 0)
        self._payload_input = QLineEdit()
        self._payload_input.setPlaceholderText("windows/meterpreter/reverse_tcp")
        grid.addWidget(self._payload_input, 1, 1)

        grid.addWidget(QLabel(tr("LHOST:")), 2, 0)
        self._lhost_input = QLineEdit()
        self._lhost_input.setPlaceholderText("0.0.0.0")
        grid.addWidget(self._lhost_input, 2, 1)

        grid.addWidget(QLabel(tr("LPORT:")), 3, 0)
        self._lport_spin = QSpinBox()
        self._lport_spin.setRange(1, 65535)
        self._lport_spin.setValue(4444)
        grid.addWidget(self._lport_spin, 3, 1)

        grid.addWidget(QLabel(tr("Format:")), 4, 0)
        self._format_combo = QComboBox()
        from modules.payload_generator import OUTPUT_FORMATS
        for fmt in OUTPUT_FORMATS:
            self._format_combo.addItem(fmt)
        self._format_combo.setCurrentText("exe")
        grid.addWidget(self._format_combo, 4, 1)

        grid.addWidget(QLabel(tr("Encoder:")), 5, 0)
        self._encoder_combo = QComboBox()
        self._encoder_combo.addItem(tr("None"), "")
        from modules.payload_generator import ENCODERS
        for enc in ENCODERS[1:]:
            self._encoder_combo.addItem(enc, enc)
        grid.addWidget(self._encoder_combo, 5, 1)

        grid.addWidget(QLabel(tr("Iterations:")), 6, 0)
        self._iter_spin = QSpinBox()
        self._iter_spin.setRange(1, 50)
        self._iter_spin.setValue(1)
        grid.addWidget(self._iter_spin, 6, 1)

        grid.addWidget(QLabel(tr("Output Dir:")), 7, 0)
        dir_row = QHBoxLayout()
        self._output_dir = QLineEdit()
        self._output_dir.setPlaceholderText(tr("Default: temp directory"))
        dir_browse = QPushButton(tr("Browse"))
        dir_browse.setFixedWidth(70)
        dir_browse.clicked.connect(self._browse_output_dir)
        dir_row.addWidget(self._output_dir)
        dir_row.addWidget(dir_browse)
        grid.addLayout(dir_row, 7, 1)

        layout.addWidget(config)

        # Generate button
        btn_row = QHBoxLayout()
        self._gen_btn = QPushButton(tr("Generate Payload"))
        self._gen_btn.setObjectName("dangerButton")
        self._gen_btn.setMinimumWidth(180)
        self._gen_btn.clicked.connect(self._on_generate)
        btn_row.addStretch()
        btn_row.addWidget(self._gen_btn)
        layout.addLayout(btn_row)

        # Output / results
        self._console = _OutputConsole()
        layout.addWidget(self._console, 1)

    def set_lhost(self, ip: str) -> None:
        self._lhost_input.setText(ip)

    def append_output(self, text: str, color: str = "#b0b0b8") -> None:
        self._console.append_line(text, color)

    def _on_template_changed(self, index: int) -> None:
        template_name = self._template_combo.currentData()
        if not template_name:
            return
        from modules.payload_generator import PAYLOAD_TEMPLATES
        tpl = PAYLOAD_TEMPLATES.get(template_name, {})
        if tpl:
            self._payload_input.setText(tpl["payload"])
            self._format_combo.setCurrentText(tpl["format"])

    def _on_generate(self) -> None:
        payload = self._payload_input.text().strip()
        lhost = self._lhost_input.text().strip()
        if not payload or not lhost:
            QMessageBox.warning(self, tr("Missing"), tr("Payload and LHOST are required."))
            return
        self.generate_requested.emit(
            payload, lhost, self._lport_spin.value(),
            self._format_combo.currentText(),
            self._encoder_combo.currentData() or "",
            self._iter_spin.value(),
            self._output_dir.text().strip(),
        )

    def _browse_output_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, tr("Select Output Directory"))
        if path:
            self._output_dir.setText(path)


class BruteForcePanel(QWidget):
    """Credential brute-force panel."""

    brute_requested = Signal(str, int, str, object, object, int, float, int)
    # target, port, service, usernames, passwords, timeout, delay, max_attempts
    stop_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel(tr("Credential Brute-Force"))
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self._status = _StatusIndicator()
        header.addWidget(title)
        header.addStretch()
        header.addWidget(self._status)
        layout.addLayout(header)

        # Config
        config = QGroupBox(tr("Target"))
        grid = QGridLayout(config)

        grid.addWidget(QLabel(tr("Target IP:")), 0, 0)
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("192.168.1.100")
        grid.addWidget(self._target_input, 0, 1)

        grid.addWidget(QLabel(tr("Port:")), 1, 0)
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(22)
        grid.addWidget(self._port_spin, 1, 1)

        grid.addWidget(QLabel(tr("Service:")), 2, 0)
        self._service_combo = QComboBox()
        self._service_combo.addItems([
            "ssh", "ftp", "smb", "rdp", "telnet", "http", "https",
            "mysql", "postgres", "vnc", "redis", "snmp",
        ])
        self._service_combo.currentTextChanged.connect(self._on_service_changed)
        grid.addWidget(self._service_combo, 2, 1)

        layout.addWidget(config)

        # Credentials
        creds = QGroupBox(tr("Credentials"))
        cg = QGridLayout(creds)

        cg.addWidget(QLabel(tr("Usernames (one per line):")), 0, 0)
        self._users_input = QTextEdit()
        self._users_input.setMaximumHeight(80)
        self._users_input.setPlaceholderText("admin\nroot\nuser")
        cg.addWidget(self._users_input, 0, 1)

        cg.addWidget(QLabel(tr("Passwords (one per line):")), 1, 0)
        self._pass_input = QTextEdit()
        self._pass_input.setMaximumHeight(80)
        self._pass_input.setPlaceholderText("password\n123456\nadmin")
        cg.addWidget(self._pass_input, 1, 1)

        load_row = QHBoxLayout()
        self._load_users_btn = QPushButton(tr("Load Userlist"))
        self._load_users_btn.clicked.connect(lambda: self._load_file(self._users_input))
        self._load_pass_btn = QPushButton(tr("Load Wordlist"))
        self._load_pass_btn.clicked.connect(lambda: self._load_file(self._pass_input))
        self._use_defaults = QPushButton(tr("Use Defaults"))
        self._use_defaults.clicked.connect(self._fill_defaults)
        load_row.addWidget(self._load_users_btn)
        load_row.addWidget(self._load_pass_btn)
        load_row.addWidget(self._use_defaults)
        load_row.addStretch()
        cg.addLayout(load_row, 2, 0, 1, 2)

        layout.addWidget(creds)

        # Options
        opts = QGroupBox(tr("Options"))
        og = QGridLayout(opts)

        og.addWidget(QLabel(tr("Timeout (sec):")), 0, 0)
        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(1, 60)
        self._timeout_spin.setValue(5)
        og.addWidget(self._timeout_spin, 0, 1)

        og.addWidget(QLabel(tr("Delay between attempts (sec):")), 1, 0)
        self._delay_spin = QDoubleSpinBox()
        self._delay_spin.setRange(0.0, 30.0)
        self._delay_spin.setValue(0.5)
        self._delay_spin.setSingleStep(0.1)
        og.addWidget(self._delay_spin, 1, 1)

        og.addWidget(QLabel(tr("Max attempts (0=unlimited):")), 2, 0)
        self._max_spin = QSpinBox()
        self._max_spin.setRange(0, 1000000)
        self._max_spin.setValue(0)
        og.addWidget(self._max_spin, 2, 1)

        layout.addWidget(opts)

        # Buttons
        btn_row = QHBoxLayout()
        self._start_btn = QPushButton(tr("Start Brute-Force"))
        self._start_btn.setObjectName("dangerButton")
        self._start_btn.setMinimumWidth(180)
        self._start_btn.clicked.connect(self._on_start)

        self._stop_btn = QPushButton(tr("Stop"))
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self.stop_requested.emit)

        btn_row.addStretch()
        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        layout.addLayout(btn_row)

        # Results table
        self._results_table = QTableWidget()
        self._results_table.setColumnCount(5)
        self._results_table.setHorizontalHeaderLabels(
            [tr("Service"), tr("Target"), tr("Port"), tr("Username"), tr("Password")]
        )
        self._results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._results_table.setAlternatingRowColors(True)
        layout.addWidget(self._results_table, 1)

    def set_target(self, ip: str, port: int = 0, service: str = "") -> None:
        self._target_input.setText(ip)
        if port:
            self._port_spin.setValue(port)
        if service:
            idx = self._service_combo.findText(service)
            if idx >= 0:
                self._service_combo.setCurrentIndex(idx)

    def set_running(self, running: bool) -> None:
        self._start_btn.setEnabled(not running)
        self._stop_btn.setEnabled(running)
        if running:
            self._status.set_status(tr("Running..."), "#b09040")
        else:
            self._status.set_status(tr("Idle"), "#606070")

    def add_credential(self, cred) -> None:
        row = self._results_table.rowCount()
        self._results_table.insertRow(row)
        self._results_table.setItem(row, 0, QTableWidgetItem(cred.service))
        self._results_table.setItem(row, 1, QTableWidgetItem(cred.host_ip))
        self._results_table.setItem(row, 2, QTableWidgetItem(str(cred.port)))
        self._results_table.setItem(row, 3, QTableWidgetItem(cred.username))

        pw_item = QTableWidgetItem(cred.password)
        pw_item.setForeground(QColor("#4a8a5a"))
        self._results_table.setItem(row, 4, pw_item)

    def _on_service_changed(self, service: str) -> None:
        from modules.credential_bruteforcer import SERVICE_PORTS
        port = SERVICE_PORTS.get(service, 0)
        if port:
            self._port_spin.setValue(port)

    def _on_start(self) -> None:
        target = self._target_input.text().strip()
        if not target:
            QMessageBox.warning(self, tr("Missing"), tr("Target IP required."))
            return

        usernames = [u.strip() for u in self._users_input.toPlainText().splitlines() if u.strip()] or None
        passwords = [p.strip() for p in self._pass_input.toPlainText().splitlines() if p.strip()] or None

        self.brute_requested.emit(
            target, self._port_spin.value(),
            self._service_combo.currentText(),
            usernames, passwords,
            self._timeout_spin.value(),
            self._delay_spin.value(),
            self._max_spin.value(),
        )

    def _fill_defaults(self) -> None:
        from modules.credential_bruteforcer import DEFAULT_USERNAMES, DEFAULT_PASSWORDS
        service = self._service_combo.currentText()
        users = DEFAULT_USERNAMES.get(service, ["admin", "root"])
        self._users_input.setPlainText("\n".join(users))
        self._pass_input.setPlainText("\n".join(DEFAULT_PASSWORDS[:20]))

    def _load_file(self, target_widget: QTextEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, tr("Load Wordlist"), "",
            tr("Text Files (*.txt);;All Files (*)")
        )
        if path:
            try:
                text = Path(path).read_text(encoding="utf-8", errors="ignore")
                target_widget.setPlainText(text)
            except Exception as e:
                QMessageBox.critical(self, tr("Error"), str(e))


# =============================================================================
# Main Attack Tab
# =============================================================================

class AttackTab(QWidget):
    """Main attack tab with sub-panels for all attack types."""

    # Forward signals from sub-panels
    mitm_start = Signal(str, str, str, bool, bool)
    mitm_stop = Signal()
    mitm_dns_spoof = Signal(str, str)

    deauth_start = Signal(str, str, str, int)
    deauth_stop = Signal()
    handshake_start = Signal(str, str, int, int, bool, str)
    wps_start = Signal(str, str, int, str, int)
    wps_stop = Signal()

    web_scan_start = Signal(str, int, bool)
    web_scan_stop = Signal()

    payload_generate = Signal(str, str, int, str, str, int, str)

    brute_start = Signal(str, int, str, object, object, int, float, int)
    brute_stop = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._tabs = QTabWidget()

        # Sub-panels
        self._mitm_panel = MitmPanel()
        self._wifi_panel = WiFiAttackPanel()
        self._web_panel = WebScanPanel()
        self._payload_panel = PayloadPanel()
        self._brute_panel = BruteForcePanel()

        self._tabs.addTab(self._mitm_panel, tr("MITM"))
        self._tabs.addTab(self._wifi_panel, tr("WiFi"))
        self._tabs.addTab(self._web_panel, tr("Web Scan"))
        self._tabs.addTab(self._payload_panel, tr("Payloads"))
        self._tabs.addTab(self._brute_panel, tr("Brute-Force"))

        layout.addWidget(self._tabs)

        # Wire sub-panel signals to top-level
        self._mitm_panel.start_requested.connect(self.mitm_start.emit)
        self._mitm_panel.stop_requested.connect(self.mitm_stop.emit)
        self._mitm_panel.dns_spoof_requested.connect(self.mitm_dns_spoof.emit)

        self._wifi_panel.deauth_requested.connect(self.deauth_start.emit)
        self._wifi_panel.deauth_stop_requested.connect(self.deauth_stop.emit)
        self._wifi_panel.handshake_requested.connect(self.handshake_start.emit)
        self._wifi_panel.wps_requested.connect(self.wps_start.emit)
        self._wifi_panel.wps_stop_requested.connect(self.wps_stop.emit)

        self._web_panel.scan_requested.connect(self.web_scan_start.emit)
        self._web_panel.scan_stop_requested.connect(self.web_scan_stop.emit)

        self._payload_panel.generate_requested.connect(self.payload_generate.emit)

        self._brute_panel.brute_requested.connect(self.brute_start.emit)
        self._brute_panel.stop_requested.connect(self.brute_stop.emit)

    # === Public API for MainWindow to call ===

    @property
    def mitm(self) -> MitmPanel:
        return self._mitm_panel

    @property
    def wifi(self) -> WiFiAttackPanel:
        return self._wifi_panel

    @property
    def web(self) -> WebScanPanel:
        return self._web_panel

    @property
    def payloads(self) -> PayloadPanel:
        return self._payload_panel

    @property
    def brute_force(self) -> BruteForcePanel:
        return self._brute_panel

    def set_target(self, ip: str, gateway: str = "") -> None:
        """Pre-fill target across all sub-panels."""
        self._mitm_panel.set_target(ip, gateway)
        self._web_panel.set_target(ip)
        self._brute_panel.set_target(ip)

    def set_interface(self, iface: str) -> None:
        """Pre-fill interface across panels that need it."""
        self._mitm_panel.set_interface(iface)
        self._wifi_panel.set_interface(iface)

    def switch_to_mitm(self) -> None:
        self._tabs.setCurrentWidget(self._mitm_panel)

    def switch_to_wifi(self) -> None:
        self._tabs.setCurrentWidget(self._wifi_panel)

    def switch_to_web(self) -> None:
        self._tabs.setCurrentWidget(self._web_panel)

    def switch_to_payloads(self) -> None:
        self._tabs.setCurrentWidget(self._payload_panel)

    def switch_to_brute(self) -> None:
        self._tabs.setCurrentWidget(self._brute_panel)
