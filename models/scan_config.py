"""Scan configuration — profiles and settings passed to all scan modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ScanDepth(Enum):
    """Scan depth profiles."""
    QUICK = "quick"         # Discovery + top 100 ports, no OS detection
    STANDARD = "standard"   # Discovery + configured port range + services + OS
    DEEP = "deep"           # Full aggressive audit (-A) + all ports + vuln scan


# Nmap timing templates
SPEED_FLAGS = {
    0: "-T1",  # Sneaky
    1: "-T2",  # Polite
    2: "-T3",  # Normal
    3: "-T4",  # Aggressive
    4: "-T5",  # Insane
}


@dataclass
class ScanConfig:
    """Configuration object passed to all scanning modules."""

    # Depth profile
    depth: ScanDepth = ScanDepth.STANDARD

    # Scanning parameters
    timeout: int = 120          # Per-host timeout in seconds
    port_range: str = "1-10000" # Port range to scan
    speed: int = 3              # Nmap timing template (0-4)

    # Automation
    auto_vuln_scan: bool = False   # Auto-run vuln scan after discovery
    auto_report: bool = False      # Auto-generate report after scan

    # Metasploit
    msf_host: str = "127.0.0.1"
    msf_port: int = 55553
    msf_password: str = "msf"

    # Vulners
    vulners_api_key: str = ""

    @property
    def speed_flag(self) -> str:
        return SPEED_FLAGS.get(self.speed, "-T4")

    @property
    def discovery_timeout(self) -> int:
        """Timeout for host discovery phase."""
        if self.depth == ScanDepth.QUICK:
            return min(self.timeout, 30)
        return min(self.timeout, 60)

    @property
    def host_timeout(self) -> int:
        """Per-host scan timeout."""
        if self.depth == ScanDepth.QUICK:
            return min(self.timeout, 30)
        elif self.depth == ScanDepth.DEEP:
            return max(self.timeout, 300)
        return self.timeout

    @property
    def nmap_ports(self) -> str:
        """Port argument for nmap."""
        if self.depth == ScanDepth.QUICK:
            return "--top-ports 100"
        elif self.depth == ScanDepth.DEEP:
            return "-p-"  # All 65535 ports
        return f"-p {self.port_range}"

    @property
    def scan_arguments(self) -> str:
        """Build nmap arguments based on depth."""
        if self.depth == ScanDepth.QUICK:
            return f"-sS -sV --version-light {self.speed_flag} --min-rate=200"
        elif self.depth == ScanDepth.DEEP:
            return f"-A -O --osscan-guess --version-all {self.speed_flag} --min-rate=100"
        # STANDARD
        return f"-sS -sV -O --osscan-guess {self.speed_flag} --min-rate=150"

    @property
    def discovery_arguments(self) -> str:
        """Arguments for host discovery phase."""
        return f"-sn {self.speed_flag} --min-rate=100"

    @staticmethod
    def from_settings(settings: dict) -> ScanConfig:
        """Create ScanConfig from settings dict (from SettingsTab.get_settings())."""
        depth_str = settings.get("scan_depth", "standard")
        try:
            depth = ScanDepth(depth_str)
        except ValueError:
            depth = ScanDepth.STANDARD

        return ScanConfig(
            depth=depth,
            timeout=settings.get("scan_timeout", 120),
            port_range=settings.get("port_range", "1-10000"),
            speed=settings.get("scan_speed", 3),
            auto_vuln_scan=settings.get("auto_vuln_scan", False),
            auto_report=settings.get("auto_report", False),
            msf_host=settings.get("msf_host", "127.0.0.1"),
            msf_port=settings.get("msf_port", 55553),
            msf_password=settings.get("msf_password", "msf"),
            vulners_api_key=settings.get("vulners_api_key", ""),
        )
