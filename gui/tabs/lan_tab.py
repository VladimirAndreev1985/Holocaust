"""LAN Scanner Tab — device table with filtering and classification."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QComboBox,
    QLineEdit, QCheckBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont

from models.device import Device, DeviceType, RiskLevel
from core.i18n import tr


class LanTab(QWidget):
    """LAN scanner results with filters and device classification."""

    device_selected = Signal(object)
    device_inspect = Signal(object)
    scan_requested = Signal(str)   # target CIDR
    vuln_scan_requested = Signal(list)  # list[Device]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._devices: list[Device] = []
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        header = QHBoxLayout()
        title = QLabel(tr("LAN Scanner"))
        title.setObjectName("titleLabel")
        header.addWidget(title)
        header.addStretch()

        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText(tr("Target: 192.168.1.0/24"))
        self._target_input.setMinimumWidth(200)
        self._target_input.setMaximumWidth(250)
        self._target_input.returnPressed.connect(self._on_scan)

        self._scan_btn = QPushButton(tr("Scan Network"))
        self._scan_btn.setObjectName("primaryButton")
        self._scan_btn.clicked.connect(self._on_scan)

        self._vuln_btn = QPushButton(tr("Vuln Scan Selected"))
        self._vuln_btn.setObjectName("dangerButton")
        self._vuln_btn.clicked.connect(self._on_vuln_scan)

        header.addWidget(self._target_input)
        header.addWidget(self._scan_btn)
        header.addWidget(self._vuln_btn)
        layout.addLayout(header)

        # Filters
        filter_layout = QHBoxLayout()

        filter_layout.addWidget(QLabel(tr("Filter:")))

        self._filter_combo = QComboBox()
        self._filter_combo.addItem(tr("All Devices"), None)
        self._filter_combo.addItem(tr("Cameras"), DeviceType.IP_CAMERA)
        self._filter_combo.addItem(tr("PCs (Windows)"), DeviceType.PC_WINDOWS)
        self._filter_combo.addItem(tr("PCs (Linux)"), DeviceType.PC_LINUX)
        self._filter_combo.addItem(tr("PCs (Mac)"), DeviceType.PC_MAC)
        self._filter_combo.addItem(tr("Servers"), DeviceType.SERVER)
        self._filter_combo.addItem(tr("Phones"), "phones")
        self._filter_combo.addItem(tr("Routers"), DeviceType.ROUTER)
        self._filter_combo.addItem(tr("IoT"), DeviceType.IOT)
        self._filter_combo.addItem(tr("Printers"), DeviceType.PRINTER)
        self._filter_combo.addItem(tr("Unknown"), DeviceType.UNKNOWN)
        self._filter_combo.currentIndexChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._filter_combo)

        self._search = QLineEdit()
        self._search.setPlaceholderText(tr("Search by IP, hostname, vendor..."))
        self._search.setMaximumWidth(300)
        self._search.textChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._search)

        self._risk_only = QCheckBox(tr("High Risk Only"))
        self._risk_only.stateChanged.connect(self._apply_filters)
        filter_layout.addWidget(self._risk_only)

        filter_layout.addStretch()

        self._count_label = QLabel(tr("{count} devices").format(count=0))
        self._count_label.setStyleSheet("color: #606070;")
        filter_layout.addWidget(self._count_label)

        layout.addLayout(filter_layout)

        # Device table
        self._table = QTableWidget()
        self._table.setColumnCount(9)
        self._table.setHorizontalHeaderLabels([
            tr("IP Address"), tr("Hostname"), tr("MAC"), tr("Vendor"), tr("Type"),
            tr("OS"), tr("Ports"), tr("Vulns"), tr("Risk")
        ])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self._table.setSortingEnabled(True)
        self._table.cellClicked.connect(self._on_cell_clicked)
        self._table.cellDoubleClicked.connect(self._on_cell_double_clicked)
        layout.addWidget(self._table, 1)

    def set_devices(self, devices: list[Device]) -> None:
        self._devices = devices
        self._apply_filters()

    def add_device(self, device: Device) -> None:
        self._devices.append(device)
        self._apply_filters()

    def update_device(self, device: Device) -> None:
        for i, d in enumerate(self._devices):
            if d.ip == device.ip:
                self._devices[i] = device
                break
        self._apply_filters()

    def _apply_filters(self) -> None:
        filter_type = self._filter_combo.currentData()
        search_text = self._search.text().lower()
        risk_only = self._risk_only.isChecked()

        filtered = []
        for d in self._devices:
            # Type filter
            if filter_type is not None:
                if filter_type == "phones":
                    if d.device_type not in (DeviceType.PHONE_ANDROID, DeviceType.PHONE_IOS):
                        continue
                elif d.device_type != filter_type:
                    continue

            # Search
            if search_text:
                searchable = f"{d.ip} {d.hostname} {d.vendor} {d.mac}".lower()
                if search_text not in searchable:
                    continue

            # Risk filter
            if risk_only and d.risk_level not in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                continue

            filtered.append(d)

        self._populate_table(filtered)
        self._count_label.setText(tr("{count} devices").format(count=len(filtered)))

    def _populate_table(self, devices: list[Device]) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(devices))

        for row, device in enumerate(devices):
            self._table.setItem(row, 0, QTableWidgetItem(device.ip))
            self._table.setItem(row, 1, QTableWidgetItem(device.hostname or "—"))
            self._table.setItem(row, 2, QTableWidgetItem(device.mac))
            self._table.setItem(row, 3, QTableWidgetItem(device.vendor or "—"))

            type_item = QTableWidgetItem(device.device_type.value)
            if device.device_type == DeviceType.IP_CAMERA:
                type_item.setForeground(QColor("#a05050"))
            self._table.setItem(row, 4, type_item)

            self._table.setItem(row, 5, QTableWidgetItem(device.os_name or "—"))
            self._table.setItem(row, 6, QTableWidgetItem(str(len(device.open_ports))))
            self._table.setItem(row, 7, QTableWidgetItem(str(len(device.vulnerabilities))))

            risk_item = QTableWidgetItem(device.risk_level.value.upper())
            risk_item.setForeground(QColor(device.risk_level.color))
            risk_item.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
            self._table.setItem(row, 8, risk_item)

            # Store device reference
            self._table.item(row, 0).setData(Qt.ItemDataRole.UserRole, device)

        self._table.setSortingEnabled(True)

    def _on_cell_clicked(self, row: int, col: int) -> None:
        item = self._table.item(row, 0)
        if item:
            device = item.data(Qt.ItemDataRole.UserRole)
            if device:
                self.device_selected.emit(device)

    def _on_cell_double_clicked(self, row: int, col: int) -> None:
        item = self._table.item(row, 0)
        if item:
            device = item.data(Qt.ItemDataRole.UserRole)
            if device:
                self.device_inspect.emit(device)

    def set_target(self, target: str) -> None:
        """Set scan target from outside (e.g. synced from Dashboard)."""
        self._target_input.setText(target)

    def _on_scan(self) -> None:
        target = self._target_input.text().strip()
        if target:
            self.scan_requested.emit(target)

    def _on_vuln_scan(self) -> None:
        selected_devices = []
        for index in self._table.selectionModel().selectedRows():
            item = self._table.item(index.row(), 0)
            if item:
                device = item.data(Qt.ItemDataRole.UserRole)
                if device:
                    selected_devices.append(device)
        if selected_devices:
            self.vuln_scan_requested.emit(selected_devices)
