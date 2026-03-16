"""Main Window — central hub connecting all tabs, widgets, and backend modules."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QMainWindow, QTabWidget, QSplitter, QStatusBar,
    QProgressBar, QLabel, QVBoxLayout, QHBoxLayout, QWidget, QMessageBox,
    QDockWidget, QScrollArea, QPushButton, QMenu,
)
from PySide6.QtCore import Qt, Slot, QTimer
from PySide6.QtGui import QFont, QAction

from core.i18n import tr
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
from models.scan_config import ScanConfig, ScanDepth
from models.vulnerability import Vulnerability
from modules.metasploit_bridge import MetasploitBridge
from reports.generator import ReportGenerator
from workers.scan_workers import (
    DiscoveryWorker, FullScanWorker, VulnScanWorker,
    CameraAuditWorker, PcAuditWorker, UpdateWorker,
    HostScanWorker,
)

log = get_logger("main_window")


class MainWindow(QMainWindow):
    """Application main window."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(tr("Holocaust — Network Auditor"))
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)

        # Backend
        self._iface_manager = InterfaceManager()
        self._msf_bridge = MetasploitBridge()
        self._report_gen = ReportGenerator()
        self._devices: dict[str, Device] = {}
        self._vulns: list[Vulnerability] = []

        # Device cards index (ip -> card widget)
        self._device_cards: dict[str, DeviceCard] = {}
        # Selected devices for batch operations
        self._selected_devices: set[str] = set()

        # Workers
        self._scan_worker: FullScanWorker | None = None
        self._vuln_worker: VulnScanWorker | None = None
        self._host_worker: HostScanWorker | None = None
        self._host_scan_ips: list[str] = []
        self._update_worker: UpdateWorker | None = None

        self._setup_ui()
        self._connect_signals()
        self._init_state()

    def _build_scan_config(self, depth: ScanDepth | None = None) -> ScanConfig:
        """Build ScanConfig from current settings + dashboard options.

        If depth is provided, use it (for context menu actions).
        Otherwise take from dashboard combo.
        """
        settings = self._settings_tab.get_settings()
        config = ScanConfig.from_settings(settings)

        if depth:
            config.depth = depth
        else:
            try:
                config.depth = ScanDepth(self._dashboard.scan_depth)
            except ValueError:
                pass

        config.auto_vuln_scan = self._dashboard.auto_vuln_scan
        config.auto_report = self._dashboard.auto_report

        return config

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
        sidebar_layout.setSpacing(4)

        sidebar_title = QLabel(tr("Targets"))
        sidebar_title.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        sidebar_title.setStyleSheet("color: #8ca8c4; padding: 5px;")
        sidebar_layout.addWidget(sidebar_title)

        # === Action toolbar ===
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)

        self._select_all_btn = QPushButton(tr("All"))
        self._select_all_btn.setFixedHeight(26)
        self._select_all_btn.setToolTip(tr("Select / deselect all"))
        self._select_all_btn.setStyleSheet(self._toolbar_btn_style())
        self._select_all_btn.clicked.connect(self._toggle_select_all)
        toolbar.addWidget(self._select_all_btn)

        # Batch scan button with dropdown
        self._batch_scan_btn = QPushButton(tr("Scan"))
        self._batch_scan_btn.setFixedHeight(26)
        self._batch_scan_btn.setToolTip(tr("Scan selected devices"))
        self._batch_scan_btn.setStyleSheet(self._toolbar_btn_style())
        batch_scan_menu = QMenu(self._batch_scan_btn)
        batch_scan_menu.setStyleSheet(self._menu_style())
        batch_scan_menu.addAction(tr("Quick Scan"), lambda: self._batch_scan(ScanDepth.QUICK))
        batch_scan_menu.addAction(tr("Standard Scan"), lambda: self._batch_scan(ScanDepth.STANDARD))
        batch_scan_menu.addAction(tr("Deep Scan"), lambda: self._batch_scan(ScanDepth.DEEP))
        batch_scan_menu.addSeparator()
        batch_scan_menu.addAction(tr("Vulnerability Scan"), self._batch_vuln_scan)
        self._batch_scan_btn.setMenu(batch_scan_menu)
        toolbar.addWidget(self._batch_scan_btn)

        self._batch_msf_btn = QPushButton(tr("MSF"))
        self._batch_msf_btn.setFixedHeight(26)
        self._batch_msf_btn.setToolTip(tr("Send selected to Metasploit"))
        self._batch_msf_btn.setStyleSheet(self._toolbar_btn_style())
        self._batch_msf_btn.clicked.connect(self._batch_send_to_msf)
        toolbar.addWidget(self._batch_msf_btn)

        self._batch_remove_btn = QPushButton(tr("Del"))
        self._batch_remove_btn.setFixedHeight(26)
        self._batch_remove_btn.setToolTip(tr("Remove selected from results"))
        self._batch_remove_btn.setStyleSheet(self._toolbar_btn_style("#a05050"))
        self._batch_remove_btn.clicked.connect(self._batch_remove)
        toolbar.addWidget(self._batch_remove_btn)

        # Selection count label
        self._selection_label = QLabel("0")
        self._selection_label.setFixedWidth(30)
        self._selection_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._selection_label.setStyleSheet("color: #5a7ea0; font-weight: bold; font-size: 12px;")
        self._selection_label.setToolTip(tr("Selected devices"))
        toolbar.addWidget(self._selection_label)

        sidebar_layout.addLayout(toolbar)

        # === Scan progress indicator in sidebar ===
        self._sidebar_scan_widget = QWidget()
        scan_indicator_layout = QHBoxLayout(self._sidebar_scan_widget)
        scan_indicator_layout.setContentsMargins(0, 2, 0, 2)
        scan_indicator_layout.setSpacing(4)

        self._sidebar_scan_label = QLabel("")
        self._sidebar_scan_label.setStyleSheet("color: #b09040; font-size: 11px; font-weight: bold;")
        scan_indicator_layout.addWidget(self._sidebar_scan_label, 1)

        self._sidebar_progress = QProgressBar()
        self._sidebar_progress.setFixedHeight(14)
        self._sidebar_progress.setStyleSheet("""
            QProgressBar {
                background-color: #18181e;
                border: 1px solid #303040;
                border-radius: 3px;
                text-align: center;
                color: #b0b0b8;
                font-size: 10px;
            }
            QProgressBar::chunk {
                background-color: #5a7ea0;
                border-radius: 2px;
            }
        """)
        scan_indicator_layout.addWidget(self._sidebar_progress)

        self._stop_scan_btn = QPushButton(tr("Stop"))
        self._stop_scan_btn.setFixedSize(40, 20)
        self._stop_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #a05050;
                color: white;
                border: none;
                border-radius: 3px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c06060;
            }
        """)
        self._stop_scan_btn.clicked.connect(self._stop_host_scan)
        scan_indicator_layout.addWidget(self._stop_scan_btn)

        self._sidebar_scan_widget.setVisible(False)
        sidebar_layout.addWidget(self._sidebar_scan_widget)

        # Device list scroll area
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

        self._tabs.addTab(self._dashboard, tr("Dashboard"))
        self._tabs.addTab(self._interfaces, tr("Interfaces & Wi-Fi"))
        self._tabs.addTab(self._lan, tr("LAN Scanner"))
        self._tabs.addTab(self._vulns_tab, tr("Vulnerabilities"))
        self._tabs.addTab(self._msf_tab, tr("Metasploit"))
        self._tabs.addTab(self._reports_tab, tr("Reports"))
        self._tabs.addTab(self._settings_tab, tr("Settings"))
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

        self._status_label = QLabel(tr("Ready"))
        self._statusbar.addWidget(self._status_label)

        self._host_count_label = QLabel(tr("Hosts: {count}").format(count=0))
        self._statusbar.addPermanentWidget(self._host_count_label)

        self._vuln_count_label = QLabel(tr("Vulns: {count}").format(count=0))
        self._statusbar.addPermanentWidget(self._vuln_count_label)

        self._msf_status_label = QLabel(tr("MSF: disconnected"))
        self._msf_status_label.setStyleSheet("color: #a05050;")
        self._statusbar.addPermanentWidget(self._msf_status_label)

    @staticmethod
    def _toolbar_btn_style(color: str = "#5a7ea0") -> str:
        return f"""
            QPushButton {{
                background-color: #1c1c24;
                color: {color};
                border: 1px solid #303040;
                border-radius: 3px;
                padding: 2px 8px;
                font-size: 11px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #252530;
                border-color: {color};
            }}
            QPushButton::menu-indicator {{
                width: 10px;
                subcontrol-position: right center;
            }}
        """

    @staticmethod
    def _menu_style() -> str:
        return """
            QMenu {
                background-color: #1c1c24;
                border: 1px solid #303040;
                color: #b0b0b8;
                padding: 4px;
            }
            QMenu::item:selected {
                background-color: #2a2a38;
            }
            QMenu::separator {
                height: 1px;
                background: #303040;
                margin: 4px 8px;
            }
        """

    def _connect_signals(self) -> None:
        # Connect log emitter
        emitter = get_emitter()
        if emitter:
            emitter.log_record.connect(self._log_panel.append_log)

        # Dashboard
        self._dashboard.scan_requested.connect(self._start_full_scan)
        self._dashboard.scan_stop_requested.connect(self._stop_full_scan)
        self._dashboard.device_selected.connect(self._on_device_selected)
        self._dashboard.device_inspect.connect(self._on_device_inspect)
        self._dashboard.stat_filter_requested.connect(self._on_stat_filter)

        # Network graph context menu signals + selection sync
        graph = self._dashboard.network_graph
        graph.device_scan_quick.connect(lambda d: self._scan_single_host(d, ScanDepth.QUICK))
        graph.device_scan_standard.connect(lambda d: self._scan_single_host(d, ScanDepth.STANDARD))
        graph.device_scan_deep.connect(lambda d: self._scan_single_host(d, ScanDepth.DEEP))
        graph.device_vuln_scan.connect(lambda d: self._start_vuln_scan([d]))
        graph.device_send_to_msf.connect(self._send_device_to_msf)
        graph.device_remove.connect(self._remove_device)
        graph.device_selection_toggled.connect(self._on_graph_selection_toggled)

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

        # Sync target between Dashboard and LAN tabs
        self._dashboard.scan_requested.connect(self._lan.set_target)

        # LAN
        self._lan.scan_requested.connect(self._start_full_scan)
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
        self._settings_tab.settings_saved.connect(self._on_settings_saved)

        # Detail panel
        self._detail_panel.close_requested.connect(
            lambda: self._detail_panel.setVisible(False))
        self._detail_panel.exploit_requested.connect(self._on_device_exploit)

    def _init_state(self) -> None:
        """Initialize application state on startup."""
        log.info("Holocaust Network Auditor starting...")
        self._refresh_interfaces()

        # Auto-connect to Metasploit if configured
        settings = self._settings_tab.get_settings()
        if settings.get("msf_auto_connect"):
            QTimer.singleShot(1000, lambda: self._connect_metasploit(
                settings["msf_host"], settings["msf_port"], settings["msf_password"]
            ))

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

    @Slot(dict)
    def _on_settings_saved(self, settings: dict) -> None:
        """Update MSF bridge config when settings change."""
        self._msf_bridge._host = settings.get("msf_host", "127.0.0.1")
        self._msf_bridge._port = settings.get("msf_port", 55553)
        self._msf_bridge._password = settings.get("msf_password", "msf")

        # Update report directory
        report_dir = settings.get("report_dir", "reports_output")
        self._report_gen = ReportGenerator(output_dir=Path(report_dir))

    # === Scan operations ===

    @Slot(str)
    def _start_full_scan(self, target: str) -> None:
        if self._scan_worker and self._scan_worker.isRunning():
            QMessageBox.warning(self, tr("Scan Running"), tr("A scan is already in progress."))
            return

        config = self._build_scan_config()
        depth_label = config.depth.value.upper()

        log.info(f"Starting {depth_label} network scan on {target} "
                 f"(timeout={config.host_timeout}s, ports={config.port_range}, "
                 f"speed={config.speed_flag}, auto_vuln={config.auto_vuln_scan})")

        self._status_label.setText(tr("Scanning {target}...").format(target=target))
        self._progress.setVisible(True)
        self._progress.setValue(0)
        self._dashboard.set_scan_enabled(False)

        self._scan_worker = FullScanWorker(target, config)
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.host_found.connect(self._on_host_found)
        self._scan_worker.host_updated.connect(self._on_host_updated)
        self._scan_worker.vuln_found.connect(self._on_vuln_found)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.start()

    def _stop_full_scan(self) -> None:
        """Stop the running full network scan."""
        if self._scan_worker and self._scan_worker.isRunning():
            log.info("Aborting full network scan...")
            self._scan_worker.abort()
            self._status_label.setText(tr("Scan aborted"))
            self._progress.setVisible(False)
            self._dashboard.set_scan_enabled(True)

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
        self._host_count_label.setText(tr("Hosts: {count}").format(count=len(self._devices)))

    @Slot(object)
    def _on_host_updated(self, device: Device) -> None:
        self._devices[device.ip] = device
        self._dashboard.update_device(device)
        self._lan.update_device(device)
        # Update card in sidebar
        if device.ip in self._device_cards:
            self._device_cards[device.ip].update_device(device)

    @Slot(object)
    def _on_scan_finished(self, result) -> None:
        config = self._build_scan_config()
        self._status_label.setText(tr("Scan complete"))
        self._progress.setVisible(False)
        self._dashboard.set_scan_enabled(True)
        log.info(tr("Scan finished: {count} devices found").format(count=len(self._devices)))

        # Update vuln stats
        critical = sum(1 for v in self._vulns
                       if v.severity.value in ("critical", "high"))
        self._dashboard.set_vuln_count(len(self._vulns), critical)

        # Auto-generate report if enabled
        if config.auto_report and self._devices:
            log.info("Auto-generating HTML report...")
            self._generate_html_report()

    @Slot(str)
    def _on_scan_error(self, error: str) -> None:
        self._status_label.setText(tr("Scan error: {error}").format(error=error))
        self._progress.setVisible(False)
        self._dashboard.set_scan_enabled(True)
        QMessageBox.critical(self, tr("Scan Error"), error)

    # === Single host / batch host scan ===

    def _scan_single_host(self, device: Device, depth: ScanDepth) -> None:
        """Rescan a single device at a specific depth."""
        self._scan_hosts([device], depth)

    def _scan_hosts(self, devices: list[Device], depth: ScanDepth,
                    vuln_scan: bool = False) -> None:
        """Scan a list of hosts at a specific depth."""
        if self._host_worker and self._host_worker.isRunning():
            QMessageBox.warning(self, tr("Scan Running"), tr("A host scan is already in progress."))
            return

        config = self._build_scan_config(depth)
        ips = ", ".join(d.ip for d in devices[:3])
        if len(devices) > 3:
            ips += f" (+{len(devices) - 3})"
        log.info(f"Rescanning {len(devices)} host(s) at {depth.value}: {ips}")

        # Remember which hosts we're scanning for post-scan actions
        self._host_scan_ips = [d.ip for d in devices]

        self._progress.setVisible(True)
        self._progress.setValue(0)
        self._status_label.setText(
            tr("Scanning {count} host(s)...").format(count=len(devices))
        )

        # Show sidebar scan indicator + disable toolbar
        self._set_host_scan_ui(True, len(devices))

        self._host_worker = HostScanWorker(devices, config, vuln_scan=vuln_scan)
        self._host_worker.progress.connect(self._on_scan_progress)
        self._host_worker.progress.connect(self._on_sidebar_progress)
        self._host_worker.host_updated.connect(self._on_host_scanned)
        self._host_worker.vuln_found.connect(self._on_vuln_found)
        self._host_worker.finished.connect(self._on_host_scan_finished)
        self._host_worker.error.connect(self._on_scan_error)
        self._host_worker.start()

    @Slot(object)
    def _on_host_scanned(self, device: Device) -> None:
        """Called when a single host finishes rescanning — update + flash + log summary."""
        self._devices[device.ip] = device
        self._dashboard.update_device(device)
        self._lan.update_device(device)

        # Flash the sidebar card green to show it was updated
        card = self._device_cards.get(device.ip)
        if card:
            card.update_device(device, flash=True)

        # Log a summary of what was found
        ports_str = ", ".join(str(p) for p in device.open_ports[:10])
        if len(device.open_ports) > 10:
            ports_str += f" (+{len(device.open_ports) - 10})"
        os_str = f"{device.os_name} {device.os_version}".strip() or "unknown"
        log.info(
            f"Scan result: {device.ip} — "
            f"type={device.device_type.value}, "
            f"OS={os_str}, "
            f"ports=[{ports_str}], "
            f"services={len(device.services)}"
        )

    def _set_host_scan_ui(self, scanning: bool, count: int = 0) -> None:
        """Show/hide sidebar scan indicator and enable/disable toolbar buttons."""
        self._sidebar_scan_widget.setVisible(scanning)
        if scanning:
            self._sidebar_scan_label.setText(
                tr("Scanning {count}...").format(count=count)
            )
            self._sidebar_progress.setValue(0)
        # Disable/enable toolbar batch buttons during scan
        self._batch_scan_btn.setEnabled(not scanning)
        self._batch_msf_btn.setEnabled(not scanning)
        self._batch_remove_btn.setEnabled(not scanning)

    @Slot(str, int)
    def _on_sidebar_progress(self, message: str, percent: int) -> None:
        """Update sidebar progress bar."""
        self._sidebar_progress.setValue(percent)
        # Show short message (just the IP part)
        self._sidebar_scan_label.setText(message[:40])

    def _stop_host_scan(self) -> None:
        """Abort the current host scan."""
        if self._host_worker and self._host_worker.isRunning():
            self._host_worker.abort()
            log.info("Host scan aborted by user")
            self._status_label.setText(tr("Scan aborted"))
            self._progress.setVisible(False)
            self._set_host_scan_ui(False)
            self._host_scan_ips = []

    @Slot()
    def _on_host_scan_finished(self) -> None:
        self._status_label.setText(tr("Host scan complete"))
        self._progress.setVisible(False)
        self._set_host_scan_ui(False)

        critical = sum(1 for v in self._vulns
                       if v.severity.value in ("critical", "high"))
        self._dashboard.set_vuln_count(len(self._vulns), critical)

        # Auto-open detail panel for scanned host(s)
        scanned_ips = getattr(self, "_host_scan_ips", [])
        if len(scanned_ips) == 1:
            # Single host — open its details automatically
            device = self._devices.get(scanned_ips[0])
            if device:
                self._on_device_inspect(device)
        elif scanned_ips:
            # Multiple hosts — open details for the last one
            device = self._devices.get(scanned_ips[-1])
            if device:
                self._on_device_inspect(device)

        # Log overall summary
        total_ports = sum(len(self._devices[ip].open_ports) for ip in scanned_ips if ip in self._devices)
        total_services = sum(len(self._devices[ip].services) for ip in scanned_ips if ip in self._devices)
        log.info(
            f"Host scan complete: {len(scanned_ips)} host(s), "
            f"{total_ports} open ports, {total_services} services detected"
        )
        self._host_scan_ips = []

    # === Vuln scan ===

    @Slot(list)
    def _start_vuln_scan(self, devices: list[Device]) -> None:
        if self._vuln_worker and self._vuln_worker.isRunning():
            QMessageBox.warning(self, tr("Scan Running"), tr("A vulnerability scan is in progress."))
            return

        config = self._build_scan_config()
        log.info(f"Starting vuln scan on {len(devices)} devices "
                 f"(timeout={config.host_timeout}s)")
        self._progress.setVisible(True)

        self._vuln_worker = VulnScanWorker(devices, config)
        self._vuln_worker.progress.connect(self._on_scan_progress)
        self._vuln_worker.vuln_found.connect(self._on_vuln_found)
        self._vuln_worker.finished.connect(self._on_vuln_scan_finished)
        self._vuln_worker.error.connect(self._on_scan_error)
        self._vuln_worker.start()

    @Slot(object)
    def _on_vuln_found(self, vuln: Vulnerability) -> None:
        self._vulns.append(vuln)
        self._vulns_tab.add_vulnerability(vuln)
        self._vuln_count_label.setText(tr("Vulns: {count}").format(count=len(self._vulns)))

    @Slot(list)
    def _on_vuln_scan_finished(self, vulns: list) -> None:
        self._status_label.setText(tr("Vulnerability scan complete"))
        self._progress.setVisible(False)

        critical = sum(1 for v in self._vulns
                       if v.severity.value in ("critical", "high"))
        self._dashboard.set_vuln_count(len(self._vulns), critical)

    # === Device interaction ===

    @Slot(object)
    def _on_device_selected(self, device: Device) -> None:
        self._status_label.setText(tr("Selected: {name} ({ip})").format(name=device.display_name, ip=device.ip))

    @Slot(object)
    def _on_device_inspect(self, device: Device) -> None:
        device_vulns = [v for v in self._vulns if v.host_ip == device.ip]
        self._detail_panel.show_device(device, device_vulns)
        self._detail_panel.setVisible(True)

    def _add_device_card(self, device: Device) -> None:
        card = DeviceCard(device)
        card.clicked.connect(self._on_device_selected)
        card.double_clicked.connect(self._on_device_inspect)

        # Context menu signals from card
        card.scan_quick.connect(lambda d: self._scan_single_host(d, ScanDepth.QUICK))
        card.scan_standard.connect(lambda d: self._scan_single_host(d, ScanDepth.STANDARD))
        card.scan_deep.connect(lambda d: self._scan_single_host(d, ScanDepth.DEEP))
        card.vuln_scan.connect(lambda d: self._start_vuln_scan([d]))
        card.send_to_msf.connect(self._send_device_to_msf)
        card.remove_device.connect(self._remove_device)
        card.selection_changed.connect(self._on_card_selection_changed)

        self._device_cards[device.ip] = card
        self._device_list_layout.addWidget(card)

    def _send_device_to_msf(self, device: Device) -> None:
        """Switch to Metasploit tab with device IP pre-filled."""
        self._msf_tab.set_exploit_target(device.ip)
        self._tabs.setCurrentWidget(self._msf_tab)
        log.info(f"Sent {device.ip} to Metasploit tab")

    def _remove_device(self, device: Device) -> None:
        """Remove a device from all views and internal storage."""
        ip = device.ip

        # Remove from storage
        self._devices.pop(ip, None)
        self._selected_devices.discard(ip)

        # Remove from sidebar
        card = self._device_cards.pop(ip, None)
        if card:
            self._device_list_layout.removeWidget(card)
            card.deleteLater()

        # Remove from graph
        self._dashboard.network_graph.remove_device(ip)

        # Update stats
        self._host_count_label.setText(tr("Hosts: {count}").format(count=len(self._devices)))
        self._update_selection_label()

        log.info(f"Removed device {ip} from results")

    # === Multi-select / batch operations ===

    def _on_card_selection_changed(self, device: Device, selected: bool) -> None:
        """Card checkbox/click changed — sync to graph and update set."""
        if selected:
            self._selected_devices.add(device.ip)
        else:
            self._selected_devices.discard(device.ip)
        # Sync to graph node
        self._dashboard.network_graph.set_node_checked(device.ip, selected)
        self._update_selection_label()

    def _on_graph_selection_toggled(self, ip: str, selected: bool) -> None:
        """Graph node clicked — sync to sidebar card and update set."""
        if selected:
            self._selected_devices.add(ip)
        else:
            self._selected_devices.discard(ip)
        # Sync to sidebar card (emit=False to avoid loop)
        card = self._device_cards.get(ip)
        if card:
            card.set_selected(selected, emit=False)
        self._update_selection_label()

    def _update_selection_label(self) -> None:
        count = len(self._selected_devices)
        self._selection_label.setText(str(count))
        self._selection_label.setToolTip(
            tr("{count} device(s) selected").format(count=count)
        )

    def _toggle_select_all(self) -> None:
        """Toggle select all / deselect all."""
        graph = self._dashboard.network_graph
        if self._selected_devices:
            # Deselect all
            for card in self._device_cards.values():
                card.set_selected(False, emit=False)
            graph.set_all_checked(False)
            self._selected_devices.clear()
        else:
            # Select all
            for ip, card in self._device_cards.items():
                card.set_selected(True, emit=False)
                self._selected_devices.add(ip)
            graph.set_all_checked(True)
        self._update_selection_label()

    # --- Stat card filter ---

    _CAMERA_TYPES = {DeviceType.IP_CAMERA, DeviceType.NVR_DVR}
    _PC_TYPES = {DeviceType.PC_WINDOWS, DeviceType.PC_LINUX, DeviceType.PC_MAC,
                 DeviceType.SERVER, DeviceType.LAPTOP}

    def _on_stat_filter(self, filter_key: str) -> None:
        """Select devices matching the clicked stat card filter."""
        graph = self._dashboard.network_graph

        if not filter_key:
            # Clear filter — deselect all
            for card in self._device_cards.values():
                card.set_selected(False, emit=False)
            graph.set_all_checked(False)
            self._selected_devices.clear()
            self._update_selection_label()
            return

        # Determine which IPs match the filter
        matching_ips: set[str] = set()

        if filter_key == "all":
            matching_ips = set(self._devices.keys())

        elif filter_key == "cameras":
            matching_ips = {ip for ip, d in self._devices.items()
                           if d.device_type in self._CAMERA_TYPES}

        elif filter_key == "pcs":
            matching_ips = {ip for ip, d in self._devices.items()
                           if d.device_type in self._PC_TYPES}

        elif filter_key == "vulns":
            matching_ips = {v.host_ip for v in self._vulns
                           if v.host_ip in self._devices}

        elif filter_key == "critical":
            matching_ips = {v.host_ip for v in self._vulns
                           if v.severity.value in ("critical", "high")
                           and v.host_ip in self._devices}

        # Apply selection
        self._selected_devices = matching_ips.copy()

        for ip, card in self._device_cards.items():
            card.set_selected(ip in matching_ips, emit=False)

        for ip in self._devices:
            graph.set_node_checked(ip, ip in matching_ips)

        self._update_selection_label()

    def _get_selected_devices(self) -> list[Device]:
        """Return list of selected Device objects."""
        return [self._devices[ip] for ip in self._selected_devices if ip in self._devices]

    def _batch_scan(self, depth: ScanDepth) -> None:
        devices = self._get_selected_devices()
        if not devices:
            QMessageBox.information(self, tr("No Selection"),
                                   tr("Select devices first (checkboxes in sidebar)."))
            return
        self._scan_hosts(devices, depth)

    def _batch_vuln_scan(self) -> None:
        devices = self._get_selected_devices()
        if not devices:
            QMessageBox.information(self, tr("No Selection"),
                                   tr("Select devices first (checkboxes in sidebar)."))
            return
        self._start_vuln_scan(devices)

    def _batch_send_to_msf(self) -> None:
        devices = self._get_selected_devices()
        if not devices:
            QMessageBox.information(self, tr("No Selection"),
                                   tr("Select devices first (checkboxes in sidebar)."))
            return
        # Send first selected device, fill RHOSTS with all IPs
        ips = " ".join(d.ip for d in devices)
        self._msf_tab.set_exploit_target(ips)
        self._tabs.setCurrentWidget(self._msf_tab)

    def _batch_remove(self) -> None:
        devices = self._get_selected_devices()
        if not devices:
            return
        for device in list(devices):
            self._remove_device(device)

    # === Metasploit ===

    @Slot(str, int, str)
    def _connect_metasploit(self, host: str, port: int, password: str) -> None:
        if self._msf_bridge.is_connected:
            self._msf_bridge.disconnect()
            self._msf_tab.set_connected(False)
            self._msf_status_label.setText(tr("MSF: disconnected"))
            self._msf_status_label.setStyleSheet("color: #a05050;")
            return

        success = self._msf_bridge.connect(host, port, password)
        self._msf_tab.set_connected(success)
        if success:
            self._msf_status_label.setText(tr("MSF: connected"))
            self._msf_status_label.setStyleSheet("color: #4a8a5a;")
        else:
            QMessageBox.warning(self, tr("Metasploit"), tr("Failed to connect to msfrpcd."))

    @Slot(object)
    def _on_exploit_requested(self, vuln: Vulnerability) -> None:
        if not self._msf_bridge.is_connected:
            QMessageBox.warning(self, tr("Metasploit"),
                                tr("Connect to Metasploit first (Metasploit tab)."))
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
            QMessageBox.critical(self, tr("Exploit Failed"), result["error"])
        else:
            QMessageBox.information(
                self, tr("Exploit Launched"),
                tr("Job ID: {job_id}\nModule: {module}\nTarget: {target}").format(
                    job_id=result.get('job_id'), module=module, target=target)
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
        api_key = self._settings_tab.get_settings().get("vulners_api_key", "")
        self._update_worker = UpdateWorker(nvd_api_key=api_key)
        self._update_worker.progress.connect(self._on_scan_progress)
        self._update_worker.finished.connect(self._on_update_finished)
        self._update_worker.error.connect(self._on_scan_error)
        self._progress.setVisible(True)
        self._status_label.setText(tr("Updating databases..."))
        self._update_worker.start()

    @Slot(dict)
    def _on_update_finished(self, results: dict) -> None:
        self._progress.setVisible(False)
        successes = sum(1 for v in results.values() if v)
        total = len(results)
        self._status_label.setText(tr("Updates done: {ok}/{total} successful").format(ok=successes, total=total))
        log.info(f"Database updates: {results}")
        # Auto-refresh DB status panel in Settings
        self._settings_tab._refresh_db_status()

    def closeEvent(self, event) -> None:
        # Cleanup workers
        for worker in [self._scan_worker, self._vuln_worker,
                       self._host_worker, self._update_worker]:
            if worker and worker.isRunning():
                worker.abort()
                worker.wait(3000)
        if self._msf_bridge.is_connected:
            self._msf_bridge.disconnect()
        super().closeEvent(event)
