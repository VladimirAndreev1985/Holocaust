from __future__ import annotations

import enum
from dataclasses import dataclass, field


class InterfaceMode(enum.Enum):
    MANAGED = "managed"
    MONITOR = "monitor"
    UNKNOWN = "unknown"


class InterfaceType(enum.Enum):
    WIRELESS = "wireless"
    ETHERNET = "ethernet"
    LOOPBACK = "loopback"
    VIRTUAL = "virtual"
    UNKNOWN = "unknown"


@dataclass
class NetworkInterface:
    name: str  # e.g. wlan0, eth0
    iface_type: InterfaceType = InterfaceType.UNKNOWN
    mode: InterfaceMode = InterfaceMode.UNKNOWN
    is_up: bool = False
    mac_address: str = ""
    ip_address: str = ""
    netmask: str = ""
    gateway: str = ""
    ssid: str = ""  # connected Wi-Fi network
    channel: int = 0
    frequency: str = ""
    driver: str = ""
    chipset: str = ""
    supports_monitor: bool = False

    @property
    def is_wireless(self) -> bool:
        return self.iface_type == InterfaceType.WIRELESS

    @property
    def is_connected(self) -> bool:
        return self.is_up and bool(self.ip_address)

    @property
    def cidr(self) -> str:
        if not self.ip_address or not self.netmask:
            return ""
        prefix = sum(bin(int(x)).count("1") for x in self.netmask.split("."))
        parts = self.ip_address.split(".")
        net_parts = [
            str(int(parts[i]) & int(self.netmask.split(".")[i]))
            for i in range(4)
        ]
        return f"{'.'.join(net_parts)}/{prefix}"

    @property
    def display_status(self) -> str:
        if not self.is_up:
            return "DOWN"
        if self.mode == InterfaceMode.MONITOR:
            return "MONITOR"
        if self.is_connected:
            return f"UP ({self.ip_address})"
        return "UP (no IP)"


@dataclass
class WiFiNetwork:
    bssid: str
    ssid: str
    channel: int = 0
    frequency: str = ""
    signal_strength: int = 0  # dBm
    encryption: str = ""  # WPA2, WPA3, WEP, Open
    cipher: str = ""
    auth: str = ""
    clients: int = 0
    first_seen: str = ""
    last_seen: str = ""

    @property
    def is_open(self) -> bool:
        return not self.encryption or self.encryption.lower() == "open"

    @property
    def signal_quality(self) -> str:
        if self.signal_strength >= -50:
            return "Excellent"
        if self.signal_strength >= -60:
            return "Good"
        if self.signal_strength >= -70:
            return "Fair"
        return "Weak"
