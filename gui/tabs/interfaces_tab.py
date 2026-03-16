"""Interfaces & Wi-Fi Tab — manage network adapters and scan Wi-Fi."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QGroupBox,
    QSplitter, QLineEdit, QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from models.network_interface import NetworkInterface, WiFiNetwork
from core.i18n import tr


class InterfacesTab(QWidget):
    """Network interface management and Wi-Fi scanning."""

    interface_up = Signal(str)
    interface_down = Signal(str)
    monitor_enable = Signal(str)
    monitor_disable = Signal(str)
    check_kill = Signal()
    wifi_scan = Signal(str)              # interface name
    wifi_connect = Signal(str, str, str) # interface, ssid, password

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title = QLabel(tr("Network Interfaces & Wi-Fi"))
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # === Interfaces section ===
        iface_group = QGroupBox(tr("Network Adapters"))
        iface_layout = QVBoxLayout(iface_group)

        # Buttons
        btn_layout = QHBoxLayout()
        self._refresh_btn = QPushButton(tr("Refresh"))
        self._up_btn = QPushButton(tr("Up"))
        self._up_btn.setObjectName("successButton")
        self._down_btn = QPushButton(tr("Down"))
        self._down_btn.setObjectName("dangerButton")
        self._monitor_btn = QPushButton(tr("Monitor Mode"))
        self._managed_btn = QPushButton(tr("Managed Mode"))
        self._kill_btn = QPushButton(tr("Check Kill"))

        for btn in [self._refresh_btn, self._up_btn, self._down_btn,
                     self._monitor_btn, self._managed_btn, self._kill_btn]:
            btn_layout.addWidget(btn)
        btn_layout.addStretch()
        iface_layout.addLayout(btn_layout)

        # Interface table
        self._iface_table = QTableWidget()
        self._iface_table.setColumnCount(8)
        self._iface_table.setHorizontalHeaderLabels([
            tr("Name"), tr("Type"), tr("Status"), tr("Mode"), tr("IP Address"), tr("MAC"), tr("SSID"), tr("Gateway")
        ])
        self._iface_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._iface_table.setAlternatingRowColors(True)
        self._iface_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        iface_layout.addWidget(self._iface_table)

        splitter.addWidget(iface_group)

        # === Wi-Fi section ===
        wifi_group = QGroupBox(tr("Wi-Fi Networks"))
        wifi_layout = QVBoxLayout(wifi_group)

        wifi_btn_layout = QHBoxLayout()
        self._wifi_scan_btn = QPushButton(tr("Scan Wi-Fi"))
        self._wifi_scan_btn.setObjectName("primaryButton")
        self._wifi_connect_btn = QPushButton(tr("Connect"))
        self._wifi_connect_btn.setObjectName("successButton")

        self._wifi_password = QLineEdit()
        self._wifi_password.setPlaceholderText(tr("Password (leave empty for open)"))
        self._wifi_password.setEchoMode(QLineEdit.EchoMode.Password)
        self._wifi_password.setMaximumWidth(250)

        wifi_btn_layout.addWidget(self._wifi_scan_btn)
        wifi_btn_layout.addWidget(self._wifi_password)
        wifi_btn_layout.addWidget(self._wifi_connect_btn)
        wifi_btn_layout.addStretch()
        wifi_layout.addLayout(wifi_btn_layout)

        # Wi-Fi table
        self._wifi_table = QTableWidget()
        self._wifi_table.setColumnCount(7)
        self._wifi_table.setHorizontalHeaderLabels([
            tr("SSID"), tr("BSSID"), tr("Channel"), tr("Signal"), tr("Encryption"), tr("Cipher"), tr("Clients")
        ])
        self._wifi_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._wifi_table.setAlternatingRowColors(True)
        self._wifi_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        wifi_layout.addWidget(self._wifi_table)

        splitter.addWidget(wifi_group)
        layout.addWidget(splitter, 1)

        # Connect signals
        self._up_btn.clicked.connect(self._on_up)
        self._down_btn.clicked.connect(self._on_down)
        self._monitor_btn.clicked.connect(self._on_monitor)
        self._managed_btn.clicked.connect(self._on_managed)
        self._kill_btn.clicked.connect(self.check_kill.emit)
        self._wifi_scan_btn.clicked.connect(self._on_wifi_scan)
        self._wifi_connect_btn.clicked.connect(self._on_wifi_connect)

    def set_interfaces(self, interfaces: list[NetworkInterface]) -> None:
        self._iface_table.setRowCount(len(interfaces))
        for row, iface in enumerate(interfaces):
            self._iface_table.setItem(row, 0, QTableWidgetItem(iface.name))
            self._iface_table.setItem(row, 1, QTableWidgetItem(iface.iface_type.value))

            status_item = QTableWidgetItem(iface.display_status)
            if iface.is_up:
                status_item.setForeground(QColor("#4a8a5a"))
            else:
                status_item.setForeground(QColor("#a05050"))
            self._iface_table.setItem(row, 2, status_item)

            self._iface_table.setItem(row, 3, QTableWidgetItem(iface.mode.value))
            self._iface_table.setItem(row, 4, QTableWidgetItem(iface.ip_address))
            self._iface_table.setItem(row, 5, QTableWidgetItem(iface.mac_address))
            self._iface_table.setItem(row, 6, QTableWidgetItem(iface.ssid))
            self._iface_table.setItem(row, 7, QTableWidgetItem(iface.gateway))

    def set_wifi_networks(self, networks: list[WiFiNetwork]) -> None:
        self._wifi_table.setRowCount(len(networks))
        for row, net in enumerate(networks):
            self._wifi_table.setItem(row, 0, QTableWidgetItem(net.ssid or tr("<hidden>")))
            self._wifi_table.setItem(row, 1, QTableWidgetItem(net.bssid))
            self._wifi_table.setItem(row, 2, QTableWidgetItem(str(net.channel)))

            signal_item = QTableWidgetItem(f"{net.signal_strength} dBm ({net.signal_quality})")
            if net.signal_strength >= -50:
                signal_item.setForeground(QColor("#4a8a5a"))
            elif net.signal_strength >= -70:
                signal_item.setForeground(QColor("#b09040"))
            else:
                signal_item.setForeground(QColor("#a05050"))
            self._wifi_table.setItem(row, 3, signal_item)

            enc_item = QTableWidgetItem(net.encryption)
            if net.is_open:
                enc_item.setForeground(QColor("#a05050"))
                enc_item.setText(tr("OPEN"))
            self._wifi_table.setItem(row, 4, enc_item)

            self._wifi_table.setItem(row, 5, QTableWidgetItem(net.cipher))
            self._wifi_table.setItem(row, 6, QTableWidgetItem(str(net.clients)))

    def _get_selected_iface(self) -> str:
        row = self._iface_table.currentRow()
        if row < 0:
            return ""
        item = self._iface_table.item(row, 0)
        return item.text() if item else ""

    def _on_up(self) -> None:
        name = self._get_selected_iface()
        if name:
            self.interface_up.emit(name)

    def _on_down(self) -> None:
        name = self._get_selected_iface()
        if name:
            self.interface_down.emit(name)

    def _on_monitor(self) -> None:
        name = self._get_selected_iface()
        if name:
            self.monitor_enable.emit(name)

    def _on_managed(self) -> None:
        name = self._get_selected_iface()
        if name:
            self.monitor_disable.emit(name)

    def _on_wifi_scan(self) -> None:
        name = self._get_selected_iface()
        if name:
            self.wifi_scan.emit(name)

    def _on_wifi_connect(self) -> None:
        name = self._get_selected_iface()
        wifi_row = self._wifi_table.currentRow()
        if not name or wifi_row < 0:
            return
        ssid_item = self._wifi_table.item(wifi_row, 0)
        if ssid_item:
            ssid = ssid_item.text()
            password = self._wifi_password.text()
            self.wifi_connect.emit(name, ssid, password)
