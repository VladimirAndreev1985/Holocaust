"""Network Graph widget — visual network topology using QGraphicsView."""

from __future__ import annotations

import math
import random
from typing import Optional

from PySide6.QtWidgets import (
    QGraphicsView, QGraphicsScene, QGraphicsEllipseItem,
    QGraphicsTextItem, QGraphicsLineItem, QGraphicsItem,
)
from PySide6.QtCore import Qt, QPointF, QRectF, Signal
from PySide6.QtGui import (
    QPen, QBrush, QColor, QFont, QPainter, QRadialGradient,
)

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


class DeviceNode(QGraphicsEllipseItem):
    """A graphical node representing a device on the network."""

    def __init__(self, device: Device, x: float, y: float):
        super().__init__(-NODE_SIZE/2, -NODE_SIZE/2, NODE_SIZE, NODE_SIZE)
        self.device = device
        self.setPos(x, y)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAcceptHoverEvents(True)
        self.setZValue(10)

        # Color based on device type
        base_color = QColor(DEVICE_COLORS.get(device.device_type, "#555555"))

        # Gradient fill
        gradient = QRadialGradient(0, 0, NODE_SIZE/2)
        gradient.setColorAt(0, base_color.lighter(130))
        gradient.setColorAt(1, base_color)
        self.setBrush(QBrush(gradient))

        # Border based on risk
        pen_color = QColor(device.risk_level.color)
        pen = QPen(pen_color, 2)
        self.setPen(pen)

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
        tr = self._type_label.boundingRect()
        self._type_label.setPos(-tr.width()/2, -tr.height()/2)

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

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QGraphicsScene(self)
        self.setScene(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.SmartViewportUpdate)

        self.setStyleSheet("background-color: #0b0b0f; border: 1px solid #252530;")

        self._nodes: dict[str, DeviceNode] = {}  # ip -> node
        self._gateway_ip: str = ""

    def set_gateway(self, ip: str) -> None:
        self._gateway_ip = ip

    def add_device(self, device: Device) -> None:
        """Add a device to the graph."""
        if device.ip in self._nodes:
            return

        # Calculate position
        if device.device_type == DeviceType.ROUTER or device.ip == self._gateway_ip:
            x, y = 0.0, 0.0
        else:
            count = len(self._nodes)
            angle = (count * 2 * math.pi) / max(count + 5, 8)
            radius = 150 + random.randint(-30, 30)
            x = radius * math.cos(angle)
            y = radius * math.sin(angle)

        node = DeviceNode(device, x, y)
        self._scene.addItem(node)
        self._nodes[device.ip] = node

        # Connect to gateway/router
        if self._gateway_ip and device.ip != self._gateway_ip:
            if self._gateway_ip in self._nodes:
                edge = EdgeLine(self._nodes[self._gateway_ip], node)
                self._scene.addItem(edge)

    def update_device(self, device: Device) -> None:
        """Update an existing device node."""
        if device.ip in self._nodes:
            old_node = self._nodes[device.ip]
            pos = old_node.pos()
            self._scene.removeItem(old_node)
            del self._nodes[device.ip]

            new_node = DeviceNode(device, pos.x(), pos.y())
            self._scene.addItem(new_node)
            self._nodes[device.ip] = new_node

            # Reconnect to gateway
            if self._gateway_ip and device.ip != self._gateway_ip:
                if self._gateway_ip in self._nodes:
                    edge = EdgeLine(self._nodes[self._gateway_ip], new_node)
                    self._scene.addItem(edge)

    def clear_graph(self) -> None:
        self._scene.clear()
        self._nodes.clear()

    def fit_view(self) -> None:
        self.fitInView(self._scene.sceneRect().adjusted(-50, -50, 50, 50),
                       Qt.AspectRatioMode.KeepAspectRatio)

    def mouseDoubleClickEvent(self, event) -> None:
        item = self.itemAt(event.pos())
        if isinstance(item, DeviceNode):
            self.device_double_clicked.emit(item.device)
        elif item and isinstance(item.parentItem(), DeviceNode):
            self.device_double_clicked.emit(item.parentItem().device)
        super().mouseDoubleClickEvent(event)

    def mousePressEvent(self, event) -> None:
        item = self.itemAt(event.pos())
        if isinstance(item, DeviceNode):
            self.device_clicked.emit(item.device)
        elif item and isinstance(item.parentItem(), DeviceNode):
            self.device_clicked.emit(item.parentItem().device)
        super().mousePressEvent(event)

    def wheelEvent(self, event) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)
