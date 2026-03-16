"""Device classifier — identifies device type based on OUI, ports, services, and OS."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Optional

from core.logger import get_logger
from models.device import Device, DeviceType

log = get_logger("classifier")

# Port-based classification rules
PORT_SIGNATURES: dict[frozenset[int], DeviceType] = {
    frozenset({554, 8000, 8080}): DeviceType.IP_CAMERA,
    frozenset({554, 80}): DeviceType.IP_CAMERA,
    frozenset({37777, 80}): DeviceType.IP_CAMERA,  # Dahua
    frozenset({34567, 80}): DeviceType.IP_CAMERA,  # XMeye
    frozenset({80, 443, 8443}): DeviceType.ROUTER,
    frozenset({631}): DeviceType.PRINTER,
    frozenset({9100}): DeviceType.PRINTER,
    frozenset({515, 9100}): DeviceType.PRINTER,
    frozenset({5060}): DeviceType.VOIP,
    frozenset({137, 139, 445}): DeviceType.PC_WINDOWS,
    frozenset({22, 111}): DeviceType.PC_LINUX,
    frozenset({548, 5900}): DeviceType.PC_MAC,
    frozenset({139, 445, 3389}): DeviceType.PC_WINDOWS,
    frozenset({8200}): DeviceType.NVR_DVR,
}

# Service/product name keywords for classification
PRODUCT_KEYWORDS: dict[str, DeviceType] = {
    "hikvision": DeviceType.IP_CAMERA,
    "dahua": DeviceType.IP_CAMERA,
    "reolink": DeviceType.IP_CAMERA,
    "axis": DeviceType.IP_CAMERA,
    "foscam": DeviceType.IP_CAMERA,
    "amcrest": DeviceType.IP_CAMERA,
    "vivotek": DeviceType.IP_CAMERA,
    "ip cam": DeviceType.IP_CAMERA,
    "network camera": DeviceType.IP_CAMERA,
    "rtsp": DeviceType.IP_CAMERA,
    "onvif": DeviceType.IP_CAMERA,
    "mikrotik": DeviceType.ROUTER,
    "routeros": DeviceType.ROUTER,
    "openwrt": DeviceType.ROUTER,
    "dd-wrt": DeviceType.ROUTER,
    "cisco ios": DeviceType.ROUTER,
    "ubiquiti": DeviceType.ACCESS_POINT,
    "unifi": DeviceType.ACCESS_POINT,
    "hp jetdirect": DeviceType.PRINTER,
    "cups": DeviceType.PRINTER,
    "brother": DeviceType.PRINTER,
    "canon printer": DeviceType.PRINTER,
    "samba": DeviceType.PC_LINUX,
    "openssh": DeviceType.PC_LINUX,
    "microsoft-ds": DeviceType.PC_WINDOWS,
    "microsoft windows": DeviceType.PC_WINDOWS,
    "apple": DeviceType.PC_MAC,
    "synology": DeviceType.NAS,
    "qnap": DeviceType.NAS,
    "samsung tv": DeviceType.SMART_TV,
    "lg webos": DeviceType.SMART_TV,
    "roku": DeviceType.SMART_TV,
    "chromecast": DeviceType.SMART_TV,
    "android": DeviceType.PHONE_ANDROID,
    "iphone": DeviceType.PHONE_IOS,
    "ipad": DeviceType.TABLET,
    "esp8266": DeviceType.IOT,
    "esp32": DeviceType.IOT,
    "tasmota": DeviceType.IOT,
    "tuya": DeviceType.IOT,
}

# OUI (first 3 bytes of MAC) to vendor mapping for cameras
CAMERA_OUI_PREFIXES: dict[str, str] = {
    "00:0e:22": "Hikvision",
    "54:c4:15": "Hikvision",
    "c0:56:e3": "Hikvision",
    "44:19:b6": "Hikvision",
    "bc:ad:28": "Hikvision",
    "a4:14:37": "Dahua",
    "3c:ef:8c": "Dahua",
    "40:f4:ec": "Dahua",
    "00:12:17": "Dahua",
    "b4:a3:82": "Reolink",
    "ec:71:db": "Reolink",
    "00:40:8c": "Axis",
    "ac:cc:8e": "Axis",
    "00:1a:07": "Foscam",
    "c4:3c:b0": "Amcrest",
}

# Known camera port patterns
CAMERA_PORTS = {80, 443, 554, 8000, 8080, 8443, 8899, 37777, 34567, 9000}


class DeviceClassifier:
    """Classifies network devices by type using multiple heuristics."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path

    def classify(self, device: Device) -> DeviceType:
        """Classify a device using all available signals. Priority order:
        1. OUI (MAC vendor) for cameras
        2. Product/service name keywords
        3. OS detection
        4. Port signature matching
        5. Heuristic fallback
        """
        candidates: list[tuple[DeviceType, int]] = []  # (type, confidence)

        # 1. OUI check (high confidence for cameras)
        oui_type = self._classify_by_oui(device)
        if oui_type:
            candidates.append((oui_type, 95))

        # 2. Product/service keywords
        product_type = self._classify_by_products(device)
        if product_type:
            candidates.append((product_type, 85))

        # 3. OS detection
        os_type = self._classify_by_os(device)
        if os_type:
            candidates.append((os_type, 80))

        # 4. Port signatures
        port_type = self._classify_by_ports(device)
        if port_type:
            candidates.append((port_type, 60))

        # 5. Vendor name heuristic
        vendor_type = self._classify_by_vendor(device)
        if vendor_type:
            candidates.append((vendor_type, 50))

        if not candidates:
            return DeviceType.UNKNOWN

        # Pick highest confidence
        candidates.sort(key=lambda x: x[1], reverse=True)
        best_type = candidates[0][0]

        device.device_type = best_type
        log.debug(f"Classified {device.ip} as {best_type.value} "
                   f"(confidence: {candidates[0][1]}%)")
        return best_type

    def classify_all(self, devices: list[Device]) -> None:
        """Classify a list of devices."""
        for device in devices:
            self.classify(device)
        log.info(f"Classified {len(devices)} devices")

    def is_camera(self, device: Device) -> bool:
        """Quick check if device is likely a camera."""
        if device.device_type == DeviceType.IP_CAMERA:
            return True
        if self._classify_by_oui(device) == DeviceType.IP_CAMERA:
            return True
        camera_ports = set(device.open_ports) & CAMERA_PORTS
        if len(camera_ports) >= 2 and 554 in camera_ports:
            return True
        return False

    def is_pc(self, device: Device) -> bool:
        """Quick check if device is likely a PC."""
        return device.device_type in (
            DeviceType.PC_WINDOWS, DeviceType.PC_LINUX, DeviceType.PC_MAC,
            DeviceType.LAPTOP, DeviceType.SERVER,
        )

    def get_camera_vendor(self, device: Device) -> str:
        """Get camera vendor from OUI database."""
        if not device.mac:
            return ""
        prefix = device.mac[:8].lower()
        return CAMERA_OUI_PREFIXES.get(prefix, "")

    # --- Private classification methods ---

    @staticmethod
    def _classify_by_oui(device: Device) -> Optional[DeviceType]:
        if not device.mac:
            return None
        prefix = device.mac[:8].lower()
        if prefix in CAMERA_OUI_PREFIXES:
            return DeviceType.IP_CAMERA
        return None

    @staticmethod
    def _classify_by_products(device: Device) -> Optional[DeviceType]:
        for service in device.services:
            text = f"{service.product} {service.extra_info} {service.name}".lower()
            for keyword, dtype in PRODUCT_KEYWORDS.items():
                if keyword in text:
                    return dtype
        return None

    @staticmethod
    def _classify_by_os(device: Device) -> Optional[DeviceType]:
        os_lower = device.os_name.lower()
        if not os_lower:
            return None
        if "windows" in os_lower:
            if "server" in os_lower:
                return DeviceType.SERVER
            return DeviceType.PC_WINDOWS
        if "linux" in os_lower:
            return DeviceType.PC_LINUX
        if "mac os" in os_lower or "macos" in os_lower or "darwin" in os_lower:
            return DeviceType.PC_MAC
        if "ios" in os_lower and "cisco" not in os_lower:
            return DeviceType.PHONE_IOS
        if "android" in os_lower:
            return DeviceType.PHONE_ANDROID
        if "router" in os_lower or "routeros" in os_lower:
            return DeviceType.ROUTER
        return None

    @staticmethod
    def _classify_by_ports(device: Device) -> Optional[DeviceType]:
        if not device.open_ports:
            return None
        port_set = set(device.open_ports)

        # Check exact matches first
        for sig_ports, dtype in PORT_SIGNATURES.items():
            if sig_ports.issubset(port_set):
                return dtype

        # Camera heuristic: RTSP + HTTP
        if 554 in port_set and (80 in port_set or 8080 in port_set):
            return DeviceType.IP_CAMERA

        # PC heuristic: SMB/RDP
        if 3389 in port_set:
            return DeviceType.PC_WINDOWS
        if 22 in port_set and 445 not in port_set:
            return DeviceType.PC_LINUX

        return None

    @staticmethod
    def _classify_by_vendor(device: Device) -> Optional[DeviceType]:
        vendor = device.vendor.lower()
        if not vendor:
            return None
        for keyword, dtype in PRODUCT_KEYWORDS.items():
            if keyword in vendor:
                return dtype
        return None
