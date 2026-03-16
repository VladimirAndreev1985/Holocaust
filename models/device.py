from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class DeviceType(enum.Enum):
    UNKNOWN = "unknown"
    ROUTER = "router"
    SWITCH = "switch"
    ACCESS_POINT = "access_point"
    PC_WINDOWS = "pc_windows"
    PC_LINUX = "pc_linux"
    PC_MAC = "pc_mac"
    LAPTOP = "laptop"
    SERVER = "server"
    PHONE_ANDROID = "phone_android"
    PHONE_IOS = "phone_ios"
    TABLET = "tablet"
    IP_CAMERA = "ip_camera"
    NVR_DVR = "nvr_dvr"
    SMART_TV = "smart_tv"
    PRINTER = "printer"
    NAS = "nas"
    IOT = "iot"
    VOIP = "voip"
    FIREWALL = "firewall"


class RiskLevel(enum.Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def color(self) -> str:
        return {
            RiskLevel.UNKNOWN: "#606070",
            RiskLevel.LOW: "#4a8a5a",
            RiskLevel.MEDIUM: "#b09040",
            RiskLevel.HIGH: "#a05050",
            RiskLevel.CRITICAL: "#c04848",
        }[self]


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    banner: str = ""

    @property
    def display(self) -> str:
        parts = [f"{self.port}/{self.protocol}"]
        if self.name:
            parts.append(self.name)
        if self.product:
            ver = f" {self.version}" if self.version else ""
            parts.append(f"({self.product}{ver})")
        return " ".join(parts)


@dataclass
class Device:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    device_type: DeviceType = DeviceType.UNKNOWN
    os_name: str = ""
    os_version: str = ""
    os_accuracy: int = 0
    services: list[Service] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    vulnerabilities: list[str] = field(default_factory=list)  # CVE IDs
    notes: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    is_alive: bool = True
    scan_depth: int = 0  # 0=discovery, 1=ports, 2=services, 3=full

    # Camera-specific fields
    camera_model: str = ""
    camera_web_url: str = ""
    camera_rtsp_url: str = ""
    has_default_creds: Optional[bool] = None

    @property
    def display_name(self) -> str:
        if self.hostname:
            return self.hostname
        if self.vendor:
            return f"{self.vendor} ({self.ip})"
        return self.ip

    @property
    def risk_score(self) -> int:
        base = len(self.vulnerabilities) * 10
        if self.has_default_creds:
            base += 50
        if self.device_type == DeviceType.IP_CAMERA:
            base += 20
        return min(base, 100)

    def update_risk_level(self) -> None:
        score = self.risk_score
        if score == 0:
            self.risk_level = RiskLevel.UNKNOWN
        elif score < 20:
            self.risk_level = RiskLevel.LOW
        elif score < 50:
            self.risk_level = RiskLevel.MEDIUM
        elif score < 80:
            self.risk_level = RiskLevel.HIGH
        else:
            self.risk_level = RiskLevel.CRITICAL

    def has_service(self, name: str) -> bool:
        return any(s.name.lower() == name.lower() for s in self.services)

    def get_service(self, name: str) -> Optional[Service]:
        for s in self.services:
            if s.name.lower() == name.lower():
                return s
        return None
