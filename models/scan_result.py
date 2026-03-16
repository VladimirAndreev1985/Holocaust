from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime

from models.device import Device
from models.vulnerability import Vulnerability


class ScanStatus(enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(enum.Enum):
    DISCOVERY = "discovery"         # nmap -sn
    PORT_SCAN = "port_scan"         # nmap -sS / -sT
    SERVICE_SCAN = "service_scan"   # nmap -sV
    OS_DETECTION = "os_detection"   # nmap -O
    FULL_AUDIT = "full_audit"       # nmap -A + vuln scripts
    VULN_SCAN = "vuln_scan"         # NSE vuln scripts
    CAMERA_AUDIT = "camera_audit"
    PC_AUDIT = "pc_audit"
    WIFI_SCAN = "wifi_scan"


@dataclass
class ScanResult:
    scan_id: str
    scan_type: ScanType
    target: str  # IP, CIDR, or "network"
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: datetime | None = None
    devices: list[Device] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    raw_output: str = ""
    error_message: str = ""
    progress: float = 0.0  # 0.0 to 100.0

    @property
    def duration(self) -> float | None:
        if self.finished_at and self.started_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    @property
    def device_count(self) -> int:
        return len(self.devices)

    @property
    def vuln_count(self) -> int:
        return len(self.vulnerabilities)

    @property
    def is_running(self) -> bool:
        return self.status == ScanStatus.RUNNING

    def mark_running(self) -> None:
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now()

    def mark_completed(self) -> None:
        self.status = ScanStatus.COMPLETED
        self.finished_at = datetime.now()
        self.progress = 100.0

    def mark_failed(self, error: str) -> None:
        self.status = ScanStatus.FAILED
        self.finished_at = datetime.now()
        self.error_message = error

    def mark_cancelled(self) -> None:
        self.status = ScanStatus.CANCELLED
        self.finished_at = datetime.now()
