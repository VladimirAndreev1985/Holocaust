"""Network Graph widget — visual network topology using QGraphicsView."""

from __future__ import annotations

import math
import random
from typing import Optional

from PySide6.QtWidgets import (
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsTextItem, QGraphicsLineItem, QGraphicsItem,
    QMenu, QApplication,
)
from PySide6.QtCore import Qt, QPointF, QRectF, Signal
from PySide6.QtGui import (
    QPen, QBrush, QColor, QFont, QPainter, QRadialGradient,
)

from core.i18n import tr
from models.device import Device, DeviceType, RiskLevel


DEVICE_COLORS = {
    DeviceType.ROUTER: "#5a7ea0",
    DeviceType.ACCESS_POINT: "#4a7090",
    DeviceType.PC_WINDOWS: "#4a8a5a",
    DeviceType.PC_LINUX: "#3a7a4a",
    DeviceType.PC_MAC: "#4a8080",
    DeviceType.LAPTOP: "#3a7070",
    DeviceType.SERVER: "#7060a0",
    DeviceType.PHONE_ANDROID: "#b09040",
    DeviceType.PHONE_IOS: "#a08030",
    DeviceType.TABLET: "#907030",
    DeviceType.IP_CAMERA: "#a05050",
    DeviceType.NVR_DVR: "#904040",
    DeviceType.SMART_TV: "#806090",
    DeviceType.PRINTER: "#707078",
    DeviceType.NAS: "#606068",
    DeviceType.IOT: "#4a8080",
    DeviceType.VOIP: "#506070",
    DeviceType.FIREWALL: "#405060",
    DeviceType.SWITCH: "#4a7090",
    DeviceType.UNKNOWN: "#484850",
}

NODE_SIZE = 40
SELECTION_COLOR = "#5a7ea0"


class DeviceNode(QGraphicsEllipseItem):
    """A graphical node representing a device on the network."""

    def __init__(self, device: Device, x: float, y: float):
        super().__init__(-NODE_SIZE/2, -NODE_SIZE/2, NODE_SIZE, NODE_SIZE)
        self.device = device
        self._is_checked = False  # our custom selection (not Qt's item selection)
        self.setPos(x, y)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, False)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAcceptHoverEvents(True)
        self.setZValue(10)

        self._base_color = QColor(DEVICE_COLORS.get(device.device_type, "#555555"))
        self._apply_fill()

        # Border based on risk (default)
        self._risk_pen_color = QColor(device.risk_level.color)
        self._apply_border()

        # Label
        self._label = QGraphicsTextItem(self)
        label_text = device.display_name
        if len(label_text) > 18:
            label_text = label_text[:15] + "..."
        self._label.setPlainText(label_text)
        self._label.setDefaultTextColor(QColor("#e0e0e0"))
        self._label.setFont(QFont("Segoe UI", 8))
        rect = self._label.boundingRect()
        self._label.setPos(-rect.width()/2, NODE_SIZE/2 + 2)

        # Type icon label (inside node)
        self._type_label = QGraphicsTextItem(self)
        self._type_label.setPlainText(self._get_type_icon())
        self._type_label.setDefaultTextColor(QColor("white"))
        self._type_label.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        tr_ = self._type_label.boundingRect()
        self._type_label.setPos(-tr_.width()/2, -tr_.height()/2)

        # Tooltip
        tooltip = (
            f"IP: {device.ip}\n"
            f"MAC: {device.mac}\n"
            f"Type: {device.device_type.value}\n"
            f"OS: {device.os_name or 'Unknown'}\n"
            f"Ports: {len(device.open_ports)}\n"
            f"Risk: {device.risk_level.value}"
        )
        self.setToolTip(tooltip)

        self._edges: list[EdgeLine] = []

    @property
    def is_checked(self) -> bool:
        return self._is_checked

    def set_checked(self, checked: bool) -> None:
        """Set custom selection state with visual feedback."""
        self._is_checked = checked
        self._apply_border()
        self._apply_fill()

    def _apply_fill(self) -> None:
        gradient = QRadialGradient(0, 0, NODE_SIZE/2)
        if self._is_checked:
            gradient.setColorAt(0, self._base_color.lighter(160))
            gradient.setColorAt(1, self._base_color.lighter(120))
        else:
            gradient.setColorAt(0, self._base_color.lighter(130))
            gradient.setColorAt(1, self._base_color)
        self.setBrush(QBrush(gradient))

    def _apply_border(self) -> None:
        if self._is_checked:
            pen = QPen(QColor(SELECTION_COLOR), 3, Qt.PenStyle.SolidLine)
        else:
            pen = QPen(self._risk_pen_color, 2)
        self.setPen(pen)

    def add_edge(self, edge: EdgeLine) -> None:
        self._edges.append(edge)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            for edge in self._edges:
                edge.update_position()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):
        self.setScale(1.2)
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self.setScale(1.0)
        super().hoverLeaveEvent(event)

    def _get_type_icon(self) -> str:
        icons = {
            DeviceType.ROUTER: "R",
            DeviceType.ACCESS_POINT: "AP",
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
        }
        return icons.get(self.device.device_type, "?")


class EdgeLine(QGraphicsLineItem):
    """A line connecting two device nodes."""

    def __init__(self, source: DeviceNode, target: DeviceNode):
        super().__init__()
        self.source = source
        self.target = target
        self.setPen(QPen(QColor("#252530"), 1.5, Qt.PenStyle.SolidLine))
        self.setZValue(1)
        self.update_position()

        source.add_edge(self)
        target.add_edge(self)

    def update_position(self) -> None:
        self.setLine(
            self.source.pos().x(), self.source.pos().y(),
            self.target.pos().x(), self.target.pos().y(),
        )


class NetworkGraph(QGraphicsView):
    """Interactive network topology graph."""

    device_clicked = Signal(object)         # Device
    device_double_clicked = Signal(object)  # Device
    # Emitted when user clicks a node to toggle selection
    device_selection_toggled = Signal(str, bool)  # ip, is_selected

    # Context menu action signals
    device_scan_quick = Signal(object)      # Device
    device_scan_standard = Signal(object)   # Device
    device_scan_deep = Signal(object)       # Device
    device_vuln_scan = Signal(object)       # Device
    device_send_to_msf = Signal(object)     # Device
    device_send_to_attack = Signal(object)  # Device
    device_web_scan = Signal(object)        # Device
    device_brute_force = Signal(object)     # Device
    device_remove = Signal(object)          # Device

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.SmartViewportUpdate)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_context_menu)

        self.setStyleSheet("background-color: #0b0b0f; border: 1px solid #252530;")

        self._nodes: dict[str, DeviceNode] = {}  # ip -> node
        self._gateway_ip: str = ""

        # Empty state placeholder
        self._empty_label = QGraphicsTextItem()
        self._empty_label.setPlainText(tr("No devices discovered yet.\nSelect an interface and start a scan."))
        self._empty_label.setDefaultTextColor(QColor("#404050"))
        self._empty_label.setFont(QFont("Segoe UI", 14))
        rect = self._empty_label.boundingRect()
        self._empty_label.setPos(-rect.width() / 2, -rect.height() / 2)
        self._scene.addItem(self._empty_label)

    def set_gateway(self, ip: str) -> None:
        self._gateway_ip = ip

    def _calc_position(self, device: Device) -> tuple[float, float]:
        """Calculate node position with subnet clustering."""
        if device.device_type == DeviceType.ROUTER or device.ip == self._gateway_ip:
            return 0.0, 0.0

        # Group by /24 subnet — each subnet gets its own ring sector
        parts = device.ip.rsplit(".", 1)
        subnet = parts[0] if len(parts) == 2 else device.ip

        # Count nodes in same subnet
        subnet_nodes = [ip for ip in self._nodes if ip.rsplit(".", 1)[0] == subnet]
        subnet_idx = len(subnet_nodes)

        # Count distinct subnets
        all_subnets = list({ip.rsplit(".", 1)[0] for ip in self._nodes if ip != self._gateway_ip})
        if subnet not in all_subnets:
            all_subnets.append(subnet)
        subnet_count = max(len(all_subnets), 1)
        my_subnet_idx = all_subnets.index(subnet) if subnet in all_subnets else 0

        # Sector for this subnet
        sector_start = (my_subnet_idx * 2 * math.pi) / subnet_count
        sector_width = (2 * math.pi) / subnet_count

        # Position within sector
        angle = sector_start + (subnet_idx + 1) * sector_width / max(subnet_idx + 3, 4)
        radius = 140 + subnet_idx * 25 + random.randint(-10, 10)

        return radius * math.cos(angle), radius * math.sin(angle)

    def add_device(self, device: Device) -> None:
        """Add a device to the graph."""
        # Remove empty state label on first device
        if self._empty_label and self._empty_label.scene():
            self._scene.removeItem(self._empty_label)
            self._empty_label = None

        if device.ip in self._nodes:
            return

        x, y = self._calc_position(device)

        node = DeviceNode(device, x, y)
        self._scene.addItem(node)
        self._nodes[device.ip] = node

        # Connect to gateway/router
        if self._gateway_ip and device.ip != self._gateway_ip:
            if self._gateway_ip in self._nodes:
                edge = EdgeLine(self._nodes[self._gateway_ip], node)
                self._scene.addItem(edge)

    def update_device(self, device: Device) -> None:
        """Update an existing device node (preserves selection state)."""
        if device.ip in self._nodes:
            old_node = self._nodes[device.ip]
            pos = old_node.pos()
            was_checked = old_node.is_checked
            self._scene.removeItem(old_node)
            del self._nodes[device.ip]

            new_node = DeviceNode(device, pos.x(), pos.y())
            new_node.set_checked(was_checked)
            self._scene.addItem(new_node)
            self._nodes[device.ip] = new_node

            # Reconnect to gateway
            if self._gateway_ip and device.ip != self._gateway_ip:
                if self._gateway_ip in self._nodes:
                    edge = EdgeLine(self._nodes[self._gateway_ip], new_node)
                    self._scene.addItem(edge)

    def remove_device(self, ip: str) -> None:
        """Remove a device node from the graph."""
        if ip in self._nodes:
            node = self._nodes.pop(ip)
            self._scene.removeItem(node)

    def set_node_checked(self, ip: str, checked: bool) -> None:
        """Set selection state of a node (called from MainWindow to sync)."""
        node = self._nodes.get(ip)
        if node:
            node.set_checked(checked)

    def set_all_checked(self, checked: bool) -> None:
        """Set selection state on all nodes."""
        for node in self._nodes.values():
            node.set_checked(checked)

    def clear_graph(self) -> None:
        self._scene.clear()
        self._nodes.clear()
        # Re-add empty state
        self._empty_label = QGraphicsTextItem()
        self._empty_label.setPlainText(tr("No devices discovered yet.\nSelect an interface and start a scan."))
        self._empty_label.setDefaultTextColor(QColor("#404050"))
        self._empty_label.setFont(QFont("Segoe UI", 14))
        rect = self._empty_label.boundingRect()
        self._empty_label.setPos(-rect.width() / 2, -rect.height() / 2)
        self._scene.addItem(self._empty_label)

    def fit_view(self) -> None:
        self.fitInView(self._scene.sceneRect().adjusted(-50, -50, 50, 50),
                       Qt.AspectRatioMode.KeepAspectRatio)

    def _get_node_at(self, pos) -> DeviceNode | None:
        """Find DeviceNode under a viewport position."""
        item = self.itemAt(pos)
        if isinstance(item, DeviceNode):
            return item
        if item and isinstance(item.parentItem(), DeviceNode):
            return item.parentItem()
        return None

    def _on_context_menu(self, pos) -> None:
        node = self._get_node_at(pos)
        if not node:
            return

        device = node.device
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

        # Header label
        header = menu.addAction(f"{device.display_name} ({device.ip})")
        header.setEnabled(False)
        menu.addSeparator()

        # Scan submenu
        scan_menu = menu.addMenu(tr("Rescan Host"))
        scan_menu.addAction(tr("Quick Scan"), lambda: self.device_scan_quick.emit(device))
        scan_menu.addAction(tr("Standard Scan"), lambda: self.device_scan_standard.emit(device))
        scan_menu.addAction(tr("Deep Scan"), lambda: self.device_scan_deep.emit(device))

        menu.addAction(tr("Vulnerability Scan"), lambda: self.device_vuln_scan.emit(device))
        menu.addSeparator()

        # Attack submenu
        attack_menu = menu.addMenu(tr("Attack"))
        attack_menu.addAction(tr("MITM (ARP Spoof)"), lambda: self.device_send_to_attack.emit(device))
        attack_menu.addAction(tr("Web Scan"), lambda: self.device_web_scan.emit(device))
        attack_menu.addAction(tr("Brute-Force"), lambda: self.device_brute_force.emit(device))

        menu.addAction(tr("Send to Metasploit"), lambda: self.device_send_to_msf.emit(device))
        menu.addSeparator()
        menu.addAction(tr("Copy IP"), lambda: QApplication.clipboard().setText(device.ip))
        if device.mac:
            menu.addAction(tr("Copy MAC"), lambda: QApplication.clipboard().setText(device.mac))
        menu.addSeparator()
        menu.addAction(tr("View Details"), lambda: self.device_double_clicked.emit(device))
        menu.addSeparator()
        menu.addAction(tr("Remove from Results"), lambda: self.device_remove.emit(device))

        menu.exec(self.mapToGlobal(pos))

    def mouseDoubleClickEvent(self, event) -> None:
        node = self._get_node_at(event.pos())
        if node:
            self.device_double_clicked.emit(node.device)
        super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            node = self._get_node_at(event.pos())
            if node:
                # Toggle selection on click
                new_state = not node.is_checked
                node.set_checked(new_state)
                self.device_selection_toggled.emit(node.device.ip, new_state)
                self.device_clicked.emit(node.device)
        super().mousePressEvent(event)

    def wheelEvent(self, event) -> None:
        factor = 1.08 if event.angleDelta().y() > 0 else 1 / 1.08
        self.scale(factor, factor)
