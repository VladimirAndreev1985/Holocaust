"""Dashboard Tab — main overview with network graph and stats."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QGridLayout, QComboBox, QSplitter,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

from gui.widgets.network_graph import NetworkGraph
from models.device import Device, DeviceType


class StatCard(QFrame):
    """Compact stat display card."""

    def __init__(self, title: str, value: str = "0", color: str = "#e94560", parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet(f"""
            StatCard {{
                background-color: #16213e;
                border: 1px solid #2a2a4a;
                border-top: 3px solid {color};
                border-radius: 6px;
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
        self._title_label.setStyleSheet("color: #8888aa; font-size: 11px; border: none;")

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

        title = QLabel("Network Dashboard")
        title.setObjectName("titleLabel")
        title.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))

        self._interface_combo = QComboBox()
        self._interface_combo.setMinimumWidth(200)
        self._interface_combo.setPlaceholderText("Select network interface...")

        self._scan_btn = QPushButton("Full Network Audit")
        self._scan_btn.setObjectName("primaryButton")
        self._scan_btn.setMinimumWidth(200)
        self._scan_btn.clicked.connect(self._on_scan_clicked)

        top_bar.addWidget(title)
        top_bar.addStretch()
        top_bar.addWidget(self._interface_combo)
        top_bar.addWidget(self._scan_btn)
        layout.addLayout(top_bar)

        # Stats row
        stats_layout = QHBoxLayout()
        self._stat_hosts = StatCard("Hosts Found", "0", "#3498db")
        self._stat_cameras = StatCard("IP Cameras", "0", "#e74c3c")
        self._stat_pcs = StatCard("PCs / Servers", "0", "#2ecc71")
        self._stat_vulns = StatCard("Vulnerabilities", "0", "#f39c12")
        self._stat_critical = StatCard("Critical", "0", "#9b59b6")

        for card in [self._stat_hosts, self._stat_cameras, self._stat_pcs,
                     self._stat_vulns, self._stat_critical]:
            stats_layout.addWidget(card)
        layout.addLayout(stats_layout)

        # Network graph (main area)
        self.network_graph = NetworkGraph()
        self.network_graph.device_clicked.connect(self.device_selected.emit)
        self.network_graph.device_double_clicked.connect(self.device_inspect.emit)
        layout.addWidget(self.network_graph, 1)

    def set_interfaces(self, interfaces: list) -> None:
        self._interface_combo.clear()
        for iface in interfaces:
            display = f"{iface.name} ({iface.ip_address})" if iface.ip_address else iface.name
            self._interface_combo.addItem(display, iface)

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
        self._scan_btn.setText("Full Network Audit" if enabled else "Scanning...")

    def set_vuln_count(self, total: int, critical: int) -> None:
        self._stat_vulns.set_value(str(total))
        self._stat_critical.set_value(str(critical))

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

    def _on_scan_clicked(self) -> None:
        iface = self._interface_combo.currentData()
        if iface and iface.cidr:
            self.scan_requested.emit(iface.cidr)
        elif iface and iface.ip_address:
            # Fallback: use /24
            parts = iface.ip_address.rsplit(".", 1)
            self.scan_requested.emit(f"{parts[0]}.0/24")
