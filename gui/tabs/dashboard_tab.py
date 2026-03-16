"""Dashboard Tab — main overview with network graph and stats."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QGridLayout, QComboBox, QSplitter, QLineEdit,
    QCheckBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

from gui.widgets.network_graph import NetworkGraph
from models.device import Device, DeviceType
from models.scan_config import ScanDepth
from core.i18n import tr


class StatCard(QFrame):
    """Compact stat display card."""

    def __init__(self, title: str, value: str = "0", color: str = "#5a7ea0", parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet(f"""
            StatCard {{
                background-color: #18181e;
                border: 1px solid #252530;
                border-top: 2px solid {color};
                border-radius: 4px;
            }}
        """)
        self.setFixedHeight(90)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._value_label = QLabel(value)
        self._value_label.setObjectName("statNumber")
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._value_label.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold; border: none;")

        self._title_label = QLabel(title)
        self._title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title_label.setStyleSheet("color: #606070; font-size: 11px; border: none;")

        layout.addWidget(self._value_label)
        layout.addWidget(self._title_label)

    def set_value(self, value: str) -> None:
        self._value_label.setText(value)


class DashboardTab(QWidget):
    """Main dashboard with network graph and quick stats."""

    scan_requested = Signal(str)   # target CIDR
    device_selected = Signal(object)
    device_inspect = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._devices: list[Device] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Top bar: title + scan controls
        top_bar = QHBoxLayout()

        title = QLabel(tr("Network Dashboard"))
        title.setObjectName("titleLabel")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))

        self._interface_combo = QComboBox()
        self._interface_combo.setMinimumWidth(200)
        self._interface_combo.setPlaceholderText(tr("Select network interface..."))
        self._interface_combo.currentIndexChanged.connect(self._on_interface_changed)

        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText(tr("Target: 192.168.1.0/24"))
        self._target_input.setMinimumWidth(200)
        self._target_input.setMaximumWidth(250)
        self._target_input.setToolTip(tr(
            "Scan target — auto-detected from interface.\n"
            "Edit manually to scan custom range.\n"
            "Examples: 192.168.1.0/24, 10.0.0.1-50, 172.16.0.0/16"
        ))

        # Scan depth selector
        self._depth_combo = QComboBox()
        self._depth_combo.addItem(tr("Quick Scan"), ScanDepth.QUICK.value)
        self._depth_combo.addItem(tr("Standard Scan"), ScanDepth.STANDARD.value)
        self._depth_combo.addItem(tr("Deep Scan"), ScanDepth.DEEP.value)
        self._depth_combo.setCurrentIndex(1)  # Standard by default
        self._depth_combo.setMinimumWidth(150)
        self._depth_combo.setToolTip(tr(
            "Quick — top 100 ports, fast detection\n"
            "Standard — configured port range, OS detection\n"
            "Deep — all 65535 ports, aggressive audit + auto vuln scan"
        ))

        self._scan_btn = QPushButton()
        self._scan_btn.setObjectName("primaryButton")
        self._scan_btn.setMinimumWidth(250)
        self._scan_btn.clicked.connect(self._on_scan_clicked)
        self._depth_combo.currentIndexChanged.connect(self._update_scan_btn_text)
        self._update_scan_btn_text()

        top_bar.addWidget(title)
        top_bar.addStretch()
        top_bar.addWidget(self._interface_combo)
        top_bar.addWidget(self._target_input)
        top_bar.addWidget(self._depth_combo)
        top_bar.addWidget(self._scan_btn)
        layout.addLayout(top_bar)

        # Automation options row
        auto_bar = QHBoxLayout()
        auto_bar.addStretch()

        self._auto_vuln = QCheckBox(tr("Auto vuln scan after discovery"))
        self._auto_vuln.setToolTip(tr(
            "Automatically run vulnerability scan on all discovered hosts\n"
            "after the network scan completes."
        ))
        self._auto_vuln.setStyleSheet("color: #606070;")

        self._auto_report = QCheckBox(tr("Auto-generate report"))
        self._auto_report.setToolTip(tr(
            "Automatically generate HTML report after all scans complete."
        ))
        self._auto_report.setStyleSheet("color: #606070;")

        auto_bar.addWidget(self._auto_vuln)
        auto_bar.addWidget(self._auto_report)
        layout.addLayout(auto_bar)

        # Stats row
        stats_layout = QHBoxLayout()
        self._stat_hosts = StatCard(tr("Hosts Found"), "0", "#5a7ea0")
        self._stat_cameras = StatCard(tr("IP Cameras"), "0", "#a05050")
        self._stat_pcs = StatCard(tr("PCs / Servers"), "0", "#4a8a5a")
        self._stat_vulns = StatCard(tr("Vulnerabilities"), "0", "#b09040")
        self._stat_critical = StatCard(tr("Critical"), "0", "#c04848")

        for card in [self._stat_hosts, self._stat_cameras, self._stat_pcs,
                     self._stat_vulns, self._stat_critical]:
            stats_layout.addWidget(card)
        layout.addLayout(stats_layout)

        # Network graph (main area)
        self.network_graph = NetworkGraph()
        self.network_graph.device_clicked.connect(self.device_selected.emit)
        self.network_graph.device_double_clicked.connect(self.device_inspect.emit)
        layout.addWidget(self.network_graph, 1)

    # --- Public API ---

    @property
    def scan_depth(self) -> str:
        """Return selected scan depth value ('quick', 'standard', 'deep')."""
        return self._depth_combo.currentData()

    @property
    def auto_vuln_scan(self) -> bool:
        return self._auto_vuln.isChecked()

    @property
    def auto_report(self) -> bool:
        return self._auto_report.isChecked()

    def set_interfaces(self, interfaces: list) -> None:
        self._interface_combo.blockSignals(True)
        self._interface_combo.clear()
        for iface in interfaces:
            display = f"{iface.name} ({iface.ip_address})" if iface.ip_address else iface.name
            self._interface_combo.addItem(display, iface)
        self._interface_combo.blockSignals(False)
        # Auto-detect target from first connected interface
        if self._interface_combo.count() > 0:
            self._on_interface_changed(0)

    def add_device(self, device: Device) -> None:
        self._devices.append(device)
        self.network_graph.add_device(device)
        self._update_stats()

    def update_device(self, device: Device) -> None:
        self.network_graph.update_device(device)
        self._update_stats()

    def clear(self) -> None:
        self._devices.clear()
        self.network_graph.clear_graph()
        self._update_stats()

    def set_scan_enabled(self, enabled: bool) -> None:
        self._scan_btn.setEnabled(enabled)
        self._depth_combo.setEnabled(enabled)
        self._auto_vuln.setEnabled(enabled)
        self._auto_report.setEnabled(enabled)
        if enabled:
            self._update_scan_btn_text()
        else:
            self._scan_btn.setText(tr("Scanning..."))

    def set_vuln_count(self, total: int, critical: int) -> None:
        self._stat_vulns.set_value(str(total))
        self._stat_critical.set_value(str(critical))

    # --- Private ---

    _SCAN_BTN_LABELS = {
        ScanDepth.QUICK.value: "Start Quick Scan",
        ScanDepth.STANDARD.value: "Start Standard Scan",
        ScanDepth.DEEP.value: "Start Deep Scan",
    }

    def _update_scan_btn_text(self, _index: int = 0) -> None:
        depth = self._depth_combo.currentData()
        label = self._SCAN_BTN_LABELS.get(depth, "Start Scan")
        self._scan_btn.setText(tr(label))

    def _update_stats(self) -> None:
        self._stat_hosts.set_value(str(len(self._devices)))
        self._stat_cameras.set_value(str(
            sum(1 for d in self._devices if d.device_type == DeviceType.IP_CAMERA)
        ))
        self._stat_pcs.set_value(str(
            sum(1 for d in self._devices if d.device_type in (
                DeviceType.PC_WINDOWS, DeviceType.PC_LINUX, DeviceType.PC_MAC,
                DeviceType.SERVER, DeviceType.LAPTOP,
            ))
        ))

    def _on_interface_changed(self, index: int) -> None:
        """Auto-fill target range when interface is selected."""
        iface = self._interface_combo.currentData()
        if not iface:
            return
        if iface.cidr:
            self._target_input.setText(iface.cidr)
        elif iface.ip_address:
            parts = iface.ip_address.rsplit(".", 1)
            self._target_input.setText(f"{parts[0]}.0/24")

    def _on_scan_clicked(self) -> None:
        target = self._target_input.text().strip()
        if target:
            self.scan_requested.emit(target)
            return
        # Fallback: try to get from interface
        iface = self._interface_combo.currentData()
        if iface and iface.cidr:
            self._target_input.setText(iface.cidr)
            self.scan_requested.emit(iface.cidr)
        elif iface and iface.ip_address:
            parts = iface.ip_address.rsplit(".", 1)
            target = f"{parts[0]}.0/24"
            self._target_input.setText(target)
            self.scan_requested.emit(target)
