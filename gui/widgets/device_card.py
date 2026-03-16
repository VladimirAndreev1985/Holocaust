"""Device Card widget — compact card showing device summary info."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QMenu, QApplication,
    QCheckBox, QLayout, QSizePolicy,
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont, QAction

from core.i18n import tr
from models.device import Device, DeviceType
from gui.widgets.network_graph import DEVICE_COLORS


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

    # Context menu action signals
    scan_quick = Signal(object)     # Device
    scan_standard = Signal(object)  # Device
    scan_deep = Signal(object)      # Device
    vuln_scan = Signal(object)      # Device
    send_to_msf = Signal(object)    # Device
    remove_device = Signal(object)  # Device

    # Selection
    selection_changed = Signal(object, bool)  # Device, is_selected

    def __init__(self, device: Device, parent=None):
        super().__init__(parent)
        self.device = device
        self._selected = False
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setFixedHeight(80)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)

        # Create layout once — never recreate
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(4, 6, 8, 6)
        self._layout.setSpacing(8)

        self._apply_style()
        self._build_content()

    @property
    def is_selected(self) -> bool:
        return self._selected

    def set_selected(self, selected: bool, emit: bool = True) -> None:
        """Set selection state. If emit=False, don't fire selection_changed signal."""
        if self._selected == selected:
            return
        self._selected = selected
        self._checkbox.blockSignals(True)
        self._checkbox.setChecked(selected)
        self._checkbox.blockSignals(False)
        self._apply_style()
        if emit:
            self.selection_changed.emit(self.device, selected)

    def _apply_style(self) -> None:
        border_color = "#5a7ea0" if self._selected else "#252530"
        bg = "#1c1c28" if self._selected else "#18181e"
        self.setStyleSheet(f"""
            DeviceCard {{
                background-color: {bg};
                border: 1px solid {border_color};
                border-left: 3px solid {self.device.risk_level.color};
                border-radius: 4px;
                padding: 8px;
            }}
            DeviceCard:hover {{
                background-color: #1c1c24;
                border-color: #5a7ea0;
            }}
        """)

    def _clear_layout(self) -> None:
        """Remove all widgets and sub-layouts from the main layout."""
        while self._layout.count():
            item = self._layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                # Recursively clear sub-layout
                sub = item.layout()
                while sub.count():
                    sub_item = sub.takeAt(0)
                    if sub_item.widget():
                        sub_item.widget().deleteLater()

    def _build_content(self) -> None:
        """Populate the existing layout with widgets. Only called once."""
        # Checkbox for multi-select
        self._checkbox = QCheckBox()
        self._checkbox.setFixedSize(18, 18)
        self._checkbox.setChecked(self._selected)
        self._checkbox.setStyleSheet("""
            QCheckBox::indicator { width: 14px; height: 14px; }
            QCheckBox::indicator:unchecked { border: 1px solid #404050; background: #18181e; border-radius: 2px; }
            QCheckBox::indicator:checked { border: 1px solid #5a7ea0; background: #5a7ea0; border-radius: 2px; }
        """)
        self._checkbox.toggled.connect(self._on_checkbox_toggled)
        self._layout.addWidget(self._checkbox)

        # Icon (colored by device type — matches graph node colors)
        type_color = DEVICE_COLORS.get(self.device.device_type, "#484850")
        self._icon_label = QLabel(DEVICE_ICONS.get(self.device.device_type, "?"))
        self._icon_label.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        self._icon_label.setFixedSize(40, 40)
        self._icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon_label.setStyleSheet(f"""
            background-color: {type_color};
            color: white;
            border-radius: 20px;
        """)
        self._layout.addWidget(self._icon_label)

        # Info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        display_name = self.device.display_name
        if len(display_name) > 30:
            display_name = display_name[:27] + "..."

        self._name_label = QLabel(display_name)
        self._name_label.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        self._name_label.setStyleSheet("color: #b0b0b8; border: none; background: transparent;")
        self._name_label.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        detail_text = (
            f"{self.device.ip}  |  "
            f"{self.device.device_type.value}  |  "
            f"{tr('{ports} ports').format(ports=len(self.device.open_ports))}"
        )
        self._details_label = QLabel(detail_text)
        self._details_label.setStyleSheet("color: #606070; font-size: 11px; border: none; background: transparent;")
        self._details_label.setWordWrap(True)

        risk_text = tr("Risk: {level}").format(level=self.device.risk_level.value.upper())
        if self.device.vulnerabilities:
            risk_text += " " + tr("({count} vulns)").format(count=len(self.device.vulnerabilities))
        self._risk_label = QLabel(risk_text)
        self._risk_label.setStyleSheet(f"color: {self.device.risk_level.color}; font-size: 11px; border: none; background: transparent;")

        info_layout.addWidget(self._name_label)
        info_layout.addWidget(self._details_label)
        info_layout.addWidget(self._risk_label)
        self._layout.addLayout(info_layout, 1)

    def _on_checkbox_toggled(self, checked: bool) -> None:
        self._selected = checked
        self._apply_style()
        self.selection_changed.emit(self.device, checked)

    def _show_context_menu(self, pos) -> None:
        menu = QMenu(self)
        menu.setStyleSheet("""
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
        """)

        # Scan submenu
        scan_menu = menu.addMenu(tr("Rescan Host"))
        scan_menu.addAction(tr("Quick Scan"), lambda: self.scan_quick.emit(self.device))
        scan_menu.addAction(tr("Standard Scan"), lambda: self.scan_standard.emit(self.device))
        scan_menu.addAction(tr("Deep Scan"), lambda: self.scan_deep.emit(self.device))

        menu.addAction(tr("Vulnerability Scan"), lambda: self.vuln_scan.emit(self.device))
        menu.addSeparator()
        menu.addAction(tr("Send to Metasploit"), lambda: self.send_to_msf.emit(self.device))
        menu.addSeparator()
        menu.addAction(tr("Copy IP"), lambda: QApplication.clipboard().setText(self.device.ip))

        if self.device.mac:
            menu.addAction(tr("Copy MAC"), lambda: QApplication.clipboard().setText(self.device.mac))

        menu.addSeparator()
        menu.addAction(tr("View Details"), lambda: self.double_clicked.emit(self.device))
        menu.addSeparator()

        remove_action = menu.addAction(tr("Remove from Results"))
        remove_action.triggered.connect(lambda: self.remove_device.emit(self.device))

        menu.exec(self.mapToGlobal(pos))

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            # Toggle selection on click anywhere on the card
            new_state = not self._selected
            self.set_selected(new_state)
            self.clicked.emit(self.device)
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event) -> None:
        self.double_clicked.emit(self.device)
        super().mouseDoubleClickEvent(event)

    def update_device(self, device: Device, flash: bool = False) -> None:
        """Update card with new device data — update labels only (no rebuild)."""
        self.device = device

        # Update icon
        type_color = DEVICE_COLORS.get(device.device_type, "#484850")
        self._icon_label.setText(DEVICE_ICONS.get(device.device_type, "?"))
        self._icon_label.setStyleSheet(f"background-color: {type_color}; color: white; border-radius: 20px;")

        # Update text labels
        display_name = device.display_name
        if len(display_name) > 30:
            display_name = display_name[:27] + "..."
        self._name_label.setText(display_name)

        self._details_label.setText(
            f"{device.ip}  |  "
            f"{device.device_type.value}  |  "
            f"{tr('{ports} ports').format(ports=len(device.open_ports))}"
        )

        risk_text = tr("Risk: {level}").format(level=device.risk_level.value.upper())
        if device.vulnerabilities:
            risk_text += " " + tr("({count} vulns)").format(count=len(device.vulnerabilities))
        self._risk_label.setText(risk_text)
        self._risk_label.setStyleSheet(f"color: {device.risk_level.color}; font-size: 11px; border: none; background: transparent;")

        self._apply_style()
        if flash:
            self._flash_highlight()

    def _flash_highlight(self) -> None:
        """Briefly flash the card border to indicate it was updated."""
        self.setStyleSheet(f"""
            DeviceCard {{
                background-color: #1e2230;
                border: 2px solid #4a9a5a;
                border-left: 3px solid #4a9a5a;
                border-radius: 4px;
                padding: 8px;
            }}
        """)
        QTimer.singleShot(1500, self._apply_style)
