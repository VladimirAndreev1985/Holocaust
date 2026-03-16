"""Device Card widget — compact card showing device summary info."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont

from models.device import Device, DeviceType


DEVICE_ICONS = {
    DeviceType.ROUTER: "R",
    DeviceType.PC_WINDOWS: "W",
    DeviceType.PC_LINUX: "L",
    DeviceType.PC_MAC: "M",
    DeviceType.SERVER: "S",
    DeviceType.IP_CAMERA: "C",
    DeviceType.PHONE_ANDROID: "A",
    DeviceType.PHONE_IOS: "i",
    DeviceType.SMART_TV: "TV",
    DeviceType.PRINTER: "P",
    DeviceType.NAS: "N",
    DeviceType.IOT: "Io",
    DeviceType.UNKNOWN: "?",
}


class DeviceCard(QFrame):
    """Compact device info card for sidebar and device lists."""

    clicked = Signal(object)        # Device
    double_clicked = Signal(object) # Device
    audit_requested = Signal(object)

    def __init__(self, device: Device, parent=None):
        super().__init__(parent)
        self.device = device
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setFixedHeight(80)
        self.setStyleSheet(f"""
            DeviceCard {{
                background-color: #16213e;
                border: 1px solid #2a2a4a;
                border-left: 4px solid {device.risk_level.color};
                border-radius: 6px;
                padding: 8px;
            }}
            DeviceCard:hover {{
                background-color: #1e2a4a;
                border-color: #e94560;
            }}
        """)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(10)

        # Icon
        icon_label = QLabel(DEVICE_ICONS.get(self.device.device_type, "?"))
        icon_label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        icon_label.setFixedSize(40, 40)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet(f"""
            background-color: {self.device.risk_level.color};
            color: white;
            border-radius: 20px;
        """)
        layout.addWidget(icon_label)

        # Info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        name = QLabel(self.device.display_name)
        name.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        name.setStyleSheet("color: #e0e0e0; border: none; background: transparent;")

        details = QLabel(
            f"{self.device.ip}  |  "
            f"{self.device.device_type.value}  |  "
            f"{len(self.device.open_ports)} ports"
        )
        details.setStyleSheet("color: #8888aa; font-size: 11px; border: none; background: transparent;")

        risk_text = f"Risk: {self.device.risk_level.value.upper()}"
        if self.device.vulnerabilities:
            risk_text += f" ({len(self.device.vulnerabilities)} vulns)"
        risk_label = QLabel(risk_text)
        risk_label.setStyleSheet(f"color: {self.device.risk_level.color}; font-size: 11px; border: none; background: transparent;")

        info_layout.addWidget(name)
        info_layout.addWidget(details)
        info_layout.addWidget(risk_label)
        layout.addLayout(info_layout, 1)

    def mousePressEvent(self, event) -> None:
        self.clicked.emit(self.device)
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        self.double_clicked.emit(self.device)
        super().mouseDoubleClickEvent(event)

    def update_device(self, device: Device) -> None:
        self.device = device
        # Clear and rebuild
        while self.layout().count():
            item = self.layout().takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._setup_ui()
        self.setStyleSheet(f"""
            DeviceCard {{
                background-color: #16213e;
                border: 1px solid #2a2a4a;
                border-left: 4px solid {device.risk_level.color};
                border-radius: 6px;
                padding: 8px;
            }}
            DeviceCard:hover {{
                background-color: #1e2a4a;
                border-color: #e94560;
            }}
        """)
