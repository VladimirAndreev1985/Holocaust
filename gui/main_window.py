"""Main Window — central hub connecting all tabs, widgets, and backend modules."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QSplitter, QStatusBar,
    QProgressBar, QLabel, QVBoxLayout, QWidget, QMessageBox,
    QDockWidget, QScrollArea,
)
from PySide6.QtCore import Qt, Slot, QTimer
from PySide6.QtGui import QFont, QAction

from core.interface_manager import InterfaceManager
from core.logger import get_logger, get_emitter
from gui.tabs.dashboard_tab import DashboardTab
from gui.tabs.interfaces_tab import InterfacesTab
from gui.tabs.lan_tab import LanTab
from gui.tabs.vulns_tab import VulnsTab
from gui.tabs.metasploit_tab import MetasploitTab
from gui.tabs.reports_tab import ReportsTab
from gui.tabs.settings_tab import SettingsTab
from gui.widgets.detail_panel import DetailPanel
from gui.widgets.log_panel import LogPanel
from gui.widgets.device_card import DeviceCard
from models.device import Device, DeviceType
from models.vulnerability import Vulnerability
from modules.metasploit_bridge import MetasploitBridge
from reports.generator import ReportGenerator
from workers.scan_workers import (
    DiscoveryWorker, FullScanWorker, VulnScanWorker,
    CameraAuditWorker, PcAuditWorker, UpdateWorker,
)

log = get_logger("main_window")


class MainWindow(QMainWindow):
    """Application main window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Holocaust — Network Auditor")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        # Backend
        self._iface_manager = InterfaceManager()
        self._msf_bridge = MetasploitBridge()
        self._report_gen = ReportGenerator()
        self._devices: dict[str, Device] = {}
        self._vulns: list[Vulnerability] = []

        # Workers
        self._scan_worker: FullScanWorker | None = None
        self._vuln_worker: VulnScanWorker | None = None

        self._setup_ui()
        self._connect_signals()
        self._init_state()

    def _setup_ui(self) -> None:
        # Central widget with splitter
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Main splitter: sidebar + content + detail
        self._main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # === Left sidebar: device tree ===
        sidebar = QWidget()
        sidebar.setMinimumWidth(200)
        sidebar.setMaximumWidth(350)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(5, 5, 5, 5)

        sidebar_title = QLabel("Targets")
        sidebar_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        sidebar_title.setStyleSheet("color: #e94560; padding: 5px;")
        sidebar_layout.addWidget(sidebar_title)

        self._device_list_area = QScrollArea()
        self._device_list_area.setWidgetResizable(True)
        self._device_list_widget = QWidget()
        self._device_list_layout = QVBoxLayout(self._device_list_widget)
        self._device_list_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self._device_list_layout.setSpacing(4)
        self._device_list_area.setWidget(self._device_list_widget)
        sidebar_layout.addWidget(self._device_list_area, 1)

        self._main_splitter.addWidget(sidebar)

        # === Center: Tab widget ===
        content_splitter = QSplitter(Qt.Orientation.Vertical)

        self._tabs = QTabWidget()
        self._dashboard = DashboardTab()
        self._interfaces = InterfacesTab()
        self._lan = LanTab()
        self._vulns_tab = VulnsTab()
        self._msf_tab = MetasploitTab()
        self._reports_tab = ReportsTab()
        self._settings_tab = SettingsTab()

        self._tabs.addTab(self._dashboard, "Dashboard")
        self._tabs.addTab(self._interfaces, "Interfaces & Wi-Fi")
        self._tabs.addTab(self._lan, "LAN Scanner")
        self._tabs.addTab(self._vulns_tab, "Vulnerabilities")
        self._tabs.addTab(self._msf_tab, "Metasploit")
        self._tabs.addTab(self._reports_tab, "Reports")
        self._tabs.addTab(self._settings_tab, "Settings")
        content_splitter.addWidget(self._tabs)

        # Detail panel (bottom)
        self._detail_panel = DetailPanel()
        self._detail_panel.setVisible(False)
        content_splitter.addWidget(self._detail_panel)
        content_splitter.setSizes([600, 250])

        self._main_splitter.addWidget(content_splitter)
        self._main_splitter.setSizes([250, 1000])

        main_layout.addWidget(self._main_splitter, 1)

        # === Log panel (bottom) ===
        self._log_panel = LogPanel()
        main_layout.addWidget(self._log_panel)

        # === Status bar ===
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)

        self._progress = QProgressBar()
        self._progress.setFixedWidth(250)
        self._progress.setVisible(False)
        self._statusbar.addPermanentWidget(self._progress)

        self._status_label = QLabel("Ready")
        self._statusbar.addWidget(self._status_label)

        self._host_count_label = QLabel("Hosts: 0")
        self._statusbar.addPermanentWidget(self._host_count_label)

        self._vuln_count_label = QLabel("Vulns: 0")
        self._statusbar.addPermanentWidget(self._vuln_count_label)

        self._msf_status_label = QLabel("MSF: disconnected")
        self._msf_status_label.setStyleSheet("color: #e74c3c;")
        self._statusbar.addPermanentWidget(self._msf_status_label)

    def _connect_signals(self) -> None:
        # Connect log emitter
        emitter = get_emitter()
        if emitter:
            emitter.log_record.connect(self._log_panel.append_log)

        # Dashboard
        self._dashboard.scan_requested.connect(self._start_full_scan)
        self._dashboard.device_selected.connect(self._on_device_selected)
        self._dashboard.device_inspect.connect(self._on_device_inspect)

        # Interfaces
        self._interfaces.interface_up.connect(
            lambda n: self._iface_manager.set_up(n) or self._refresh_interfaces())
        self._interfaces.interface_down.connect(
            lambda n: self._iface_manager.set_down(n) or self._refresh_interfaces())
        self._interfaces.monitor_enable.connect(
            lambda n: self._iface_manager.enable_monitor(n) or self._refresh_interfaces())
        self._interfaces.monitor_disable.connect(
            lambda n: self._iface_manager.disable_monitor(n) or self._refresh_interfaces())
        self._interfaces.check_kill.connect(
            lambda: self._iface_manager.airmon_check_kill() or self._refresh_interfaces())

        # LAN
        self._lan.scan_requested.connect(lambda: self._start_full_scan(self._get_default_target()))
        self._lan.device_selected.connect(self._on_device_selected)
        self._lan.device_inspect.connect(self._on_device_inspect)
        self._lan.vuln_scan_requested.connect(self._start_vuln_scan)

        # Vulnerabilities
        self._vulns_tab.exploit_requested.connect(self._on_exploit_requested)

        # Metasploit
        self._msf_tab.connect_requested.connect(self._connect_metasploit)
        self._msf_tab.exploit_run.connect(self._run_metasploit_exploit)

        # Reports
        self._reports_tab.generate_html.connect(self._generate_html_report)
        self._reports_tab.generate_pdf.connect(self._generate_pdf_report)

        # Settings
        self._settings_tab.update_databases.connect(self._update_databases)

        # Detail panel
        self._detail_panel.close_requested.connect(
            lambda: self._detail_panel.setVisible(False))
        self._detail_panel.exploit_requested.connect(self._on_device_exploit)

    def _init_state(self) -> None:
        """Initialize application state on startup."""
        log.info("Holocaust Network Auditor starting...")
        self._refresh_interfaces()

    def _refresh_interfaces(self) -> None:
        interfaces = self._iface_manager.refresh()
        self._interfaces.set_interfaces(interfaces)
        self._dashboard.set_interfaces(interfaces)

    def _get_default_target(self) -> str:
        connected = self._iface_manager.get_connected()
        if connected:
            cidr = connected[0].cidr
            if cidr:
                return cidr
            ip = connected[0].ip_address
            return f"{ip.rsplit('.', 1)[0]}.0/24"
        return "192.168.1.0/24"

    # === Scan operations ===

    @Slot(str)
    def _start_full_scan(self, target: str) -> None:
        if self._scan_worker and self._scan_worker.isRunning():
            QMessageBox.warning(self, "Scan Running", "A scan is already in progress.")
            return

        log.info(f"Starting full network scan on {target}")
        self._status_label.setText(f"Scanning {target}...")
        self._progress.setVisible(True)
        self._progress.setValue(0)
        self._dashboard.set_scan_enabled(False)

        self._scan_worker = FullScanWorker(target)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.host_found.connect(self._on_host_found)
        self._scan_worker.host_updated.connect(self._on_host_updated)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.start()

    @Slot(str, int)
    def _on_scan_progress(self, message: str, percent: int) -> None:
        self._status_label.setText(message)
        self._progress.setValue(percent)

    @Slot(object)
    def _on_host_found(self, device: Device) -> None:
        self._devices[device.ip] = device
        self._dashboard.add_device(device)
        self._lan.add_device(device)
        self._add_device_card(device)
        self._host_count_label.setText(f"Hosts: {len(self._devices)}")

    @Slot(object)
    def _on_host_updated(self, device: Device) -> None:
        self._devices[device.ip] = device
        self._dashboard.update_device(device)
        self._lan.update_device(device)

    @Slot(object)
    def _on_scan_finished(self, result) -> None:
        self._status_label.setText("Scan complete")
        self._progress.setVisible(False)
        self._dashboard.set_scan_enabled(True)
        log.info(f"Scan finished: {len(self._devices)} devices found")

    @Slot(str)
    def _on_scan_error(self, error: str) -> None:
        self._status_label.setText(f"Scan error: {error}")
        self._progress.setVisible(False)
        self._dashboard.set_scan_enabled(True)
        QMessageBox.critical(self, "Scan Error", error)

    # === Vuln scan ===

    @Slot(list)
    def _start_vuln_scan(self, devices: list[Device]) -> None:
        if self._vuln_worker and self._vuln_worker.isRunning():
            QMessageBox.warning(self, "Scan Running", "A vulnerability scan is in progress.")
            return

        log.info(f"Starting vuln scan on {len(devices)} devices")
        self._progress.setVisible(True)

        self._vuln_worker = VulnScanWorker(devices)
        self._vuln_worker.progress.connect(self._on_scan_progress)
        self._vuln_worker.vuln_found.connect(self._on_vuln_found)
        self._vuln_worker.finished.connect(self._on_vuln_scan_finished)
        self._vuln_worker.error.connect(self._on_scan_error)
        self._vuln_worker.start()

    @Slot(object)
    def _on_vuln_found(self, vuln: Vulnerability) -> None:
        self._vulns.append(vuln)
        self._vulns_tab.add_vulnerability(vuln)
        self._vuln_count_label.setText(f"Vulns: {len(self._vulns)}")

    @Slot(list)
    def _on_vuln_scan_finished(self, vulns: list) -> None:
        self._status_label.setText("Vulnerability scan complete")
        self._progress.setVisible(False)

        critical = sum(1 for v in self._vulns
                       if v.severity.value in ("critical", "high"))
        self._dashboard.set_vuln_count(len(self._vulns), critical)

    # === Device interaction ===

    @Slot(object)
    def _on_device_selected(self, device: Device) -> None:
        self._status_label.setText(f"Selected: {device.display_name} ({device.ip})")

    @Slot(object)
    def _on_device_inspect(self, device: Device) -> None:
        device_vulns = [v for v in self._vulns if v.host_ip == device.ip]
        self._detail_panel.show_device(device, device_vulns)
        self._detail_panel.setVisible(True)

    def _add_device_card(self, device: Device) -> None:
        card = DeviceCard(device)
        card.clicked.connect(self._on_device_selected)
        card.double_clicked.connect(self._on_device_inspect)
        self._device_list_layout.addWidget(card)

    # === Metasploit ===

    @Slot(str, int, str)
    def _connect_metasploit(self, host: str, port: int, password: str) -> None:
        if self._msf_bridge.is_connected:
            self._msf_bridge.disconnect()
            self._msf_tab.set_connected(False)
            self._msf_status_label.setText("MSF: disconnected")
            self._msf_status_label.setStyleSheet("color: #e74c3c;")
            return

        success = self._msf_bridge.connect(host, port, password)
        self._msf_tab.set_connected(success)
        if success:
            self._msf_status_label.setText("MSF: connected")
            self._msf_status_label.setStyleSheet("color: #2ecc71;")
        else:
            QMessageBox.warning(self, "Metasploit", "Failed to connect to msfrpcd.")

    @Slot(object)
    def _on_exploit_requested(self, vuln: Vulnerability) -> None:
        if not self._msf_bridge.is_connected:
            QMessageBox.warning(self, "Metasploit",
                                "Connect to Metasploit first (Metasploit tab).")
            return

        best = vuln.best_exploit
        if best and best.is_metasploit:
            self._msf_tab.set_exploit_target(
                vuln.host_ip, vuln.affected_port, best.module_path
            )
            self._tabs.setCurrentWidget(self._msf_tab)

    @Slot(object, object)
    def _on_device_exploit(self, device: Device, vuln: Vulnerability) -> None:
        self._on_exploit_requested(vuln)

    @Slot(str, str, int, str, dict)
    def _run_metasploit_exploit(self, module: str, target: str, port: int,
                                 payload: str, options: dict) -> None:
        result = self._msf_bridge.run_exploit(module, target, port, payload, options)
        if "error" in result:
            QMessageBox.critical(self, "Exploit Failed", result["error"])
        else:
            QMessageBox.information(
                self, "Exploit Launched",
                f"Job ID: {result.get('job_id')}\nModule: {module}\nTarget: {target}"
            )

    # === Reports ===

    @Slot()
    def _generate_html_report(self) -> None:
        devices = list(self._devices.values())
        path = self._report_gen.generate_html(devices, self._vulns)
        self._reports_tab.set_report_generated(path)

    @Slot()
    def _generate_pdf_report(self) -> None:
        devices = list(self._devices.values())
        path = self._report_gen.generate_pdf(devices, self._vulns)
        if path:
            self._reports_tab.set_report_generated(path)

    # === Updates ===

    @Slot()
    def _update_databases(self) -> None:
        worker = UpdateWorker()
        worker.progress.connect(self._on_scan_progress)
        worker.finished.connect(lambda r: log.info(f"Updates: {r}"))
        worker.start()

    def closeEvent(self, event) -> None:
        # Cleanup workers
        for worker in [self._scan_worker, self._vuln_worker]:
            if worker and worker.isRunning():
                worker.abort()
                worker.wait(3000)
        if self._msf_bridge.is_connected:
            self._msf_bridge.disconnect()
        super().closeEvent(event)
