"""LAN Scanner — network discovery and service enumeration using nmap."""

from __future__ import annotations

import uuid
from typing import Optional

import nmap

from core.logger import get_logger, get_audit_logger
from models.device import Device, Service
from models.scan_config import ScanConfig, ScanDepth
from models.scan_result import ScanResult, ScanStatus, ScanType

log = get_logger("lan_scanner")


class LanScanner:
    """Performs progressive network scanning: discovery -> ports -> services -> OS."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self._scanner = nmap.PortScanner()
        self._current_scan: Optional[ScanResult] = None
        self.config = config or ScanConfig()

    @property
    def is_scanning(self) -> bool:
        return self._current_scan is not None and self._current_scan.is_running

    def discover_hosts(self, target: str) -> ScanResult:
        """Phase 1: Quick host discovery (nmap -sn)."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(scan_id=scan_id, scan_type=ScanType.DISCOVERY, target=target)
        result.mark_running()
        self._current_scan = result

        audit = get_audit_logger()
        if audit:
            audit.log_action("host_discovery", target,
                             f"scan_id={scan_id} depth={self.config.depth.value}")

        log.info(f"[{scan_id}] Host discovery on {target} "
                 f"(depth={self.config.depth.value}, speed={self.config.speed_flag})")

        try:
            self._scanner.scan(
                hosts=target,
                arguments=self.config.discovery_arguments,
                timeout=self.config.discovery_timeout,
            )

            for host in self._scanner.all_hosts():
                device = Device(ip=host)

                host_data = self._scanner[host]
                if "mac" in host_data.get("addresses", {}):
                    device.mac = host_data["addresses"]["mac"]
                if "vendor" in host_data:
                    vendors = host_data["vendor"]
                    if vendors:
                        device.vendor = list(vendors.values())[0]

                hostnames = host_data.get("hostnames", [])
                if hostnames and hostnames[0].get("name"):
                    device.hostname = hostnames[0]["name"]

                device.is_alive = host_data.get("status", {}).get("state") == "up"
                result.devices.append(device)

            result.mark_completed()
            log.info(f"[{scan_id}] Discovery complete: {len(result.devices)} hosts found")

        except nmap.PortScannerError as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Discovery failed: {e}")
        except Exception as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Unexpected error: {e}")

        self._current_scan = None
        return result

    def scan_host(self, ip: str) -> Device:
        """Scan a single host using the configured depth profile."""
        scan_id = str(uuid.uuid4())[:8]
        depth = self.config.depth

        if depth == ScanDepth.QUICK:
            return self._scan_quick(ip, scan_id)
        elif depth == ScanDepth.DEEP:
            return self._scan_deep(ip, scan_id)
        return self._scan_standard(ip, scan_id)

    def _scan_quick(self, ip: str, scan_id: str) -> Device:
        """Quick scan: top 100 ports, version-light, no OS."""
        log.info(f"[{scan_id}] Quick scan on {ip}")
        try:
            args = (f"-sS -sV --version-light {self.config.speed_flag} "
                    f"--top-ports 100 --min-rate=200")
            self._scanner.scan(
                hosts=ip,
                arguments=args,
                timeout=self.config.host_timeout,
            )
            return self._parse_host_result(ip, scan_depth=1)
        except Exception as e:
            log.error(f"[{scan_id}] Quick scan failed for {ip}: {e}")
            return Device(ip=ip, is_alive=False)

    def _scan_standard(self, ip: str, scan_id: str) -> Device:
        """Standard scan: configured ports, service versions, OS detection."""
        log.info(f"[{scan_id}] Standard scan on {ip} "
                 f"(ports={self.config.port_range}, timeout={self.config.host_timeout}s)")
        try:
            args = (f"-sS -sV -O --osscan-guess {self.config.speed_flag} "
                    f"-p {self.config.port_range} --min-rate=150")
            self._scanner.scan(
                hosts=ip,
                arguments=args,
                timeout=self.config.host_timeout,
            )
            return self._parse_host_result(ip, scan_depth=2)
        except Exception as e:
            log.error(f"[{scan_id}] Standard scan failed for {ip}: {e}")
            return Device(ip=ip, is_alive=False)

    def _scan_deep(self, ip: str, scan_id: str) -> Device:
        """Deep scan: all ports, aggressive mode, full version detection."""
        log.info(f"[{scan_id}] Deep scan on {ip} "
                 f"(all ports, timeout={self.config.host_timeout}s)")
        try:
            args = (f"-A -O --osscan-guess --version-all {self.config.speed_flag} "
                    f"-p- --min-rate=100")
            self._scanner.scan(
                hosts=ip,
                arguments=args,
                timeout=self.config.host_timeout,
            )
            return self._parse_host_result(ip, scan_depth=3)
        except Exception as e:
            log.error(f"[{scan_id}] Deep scan failed for {ip}: {e}")
            return Device(ip=ip, is_alive=False)

    def _parse_host_result(self, ip: str, scan_depth: int = 2) -> Device:
        """Parse nmap result for a single host into a Device object."""
        device = Device(ip=ip)
        device.scan_depth = scan_depth

        if ip not in self._scanner.all_hosts():
            device.is_alive = False
            return device

        host_data = self._scanner[ip]

        # Addresses
        if "mac" in host_data.get("addresses", {}):
            device.mac = host_data["addresses"]["mac"]
        if "vendor" in host_data:
            vendors = host_data["vendor"]
            if vendors:
                device.vendor = list(vendors.values())[0]

        # Hostnames
        hostnames = host_data.get("hostnames", [])
        if hostnames and hostnames[0].get("name"):
            device.hostname = hostnames[0]["name"]

        # OS detection
        if "osmatch" in host_data:
            matches = host_data["osmatch"]
            if matches:
                best = matches[0]
                device.os_name = best.get("name", "")
                device.os_accuracy = int(best.get("accuracy", 0))
                osclasses = best.get("osclass", [])
                if osclasses:
                    device.os_version = osclasses[0].get("osgen", "")

        # Services / ports
        for proto in host_data.all_protocols():
            for port in sorted(host_data[proto].keys()):
                port_info = host_data[proto][port]
                if port_info["state"] == "open":
                    device.open_ports.append(port)
                    device.services.append(Service(
                        port=port,
                        protocol=proto,
                        name=port_info.get("name", ""),
                        product=port_info.get("product", ""),
                        version=port_info.get("version", ""),
                        extra_info=port_info.get("extrainfo", ""),
                    ))

        device.is_alive = True
        return device

    # --- Legacy methods (kept for backward compatibility) ---

    def scan_single_host(self, ip: str) -> Device:
        """Alias for scan_host — scans using configured depth."""
        return self.scan_host(ip)

    def scan_ports(self, target: str, ports: str = "", timeout: int = 0) -> ScanResult:
        """Port scan with SYN scan."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(scan_id=scan_id, scan_type=ScanType.PORT_SCAN, target=target)
        result.mark_running()
        self._current_scan = result

        actual_ports = ports or self.config.port_range
        actual_timeout = timeout or self.config.host_timeout

        log.info(f"[{scan_id}] Port scan on {target}, ports={actual_ports}")

        try:
            self._scanner.scan(
                hosts=target,
                ports=actual_ports,
                arguments=f"-sS {self.config.speed_flag} --min-rate=200",
                timeout=actual_timeout,
            )

            for host in self._scanner.all_hosts():
                device = Device(ip=host)
                for proto in self._scanner[host].all_protocols():
                    for port in sorted(self._scanner[host][proto].keys()):
                        port_info = self._scanner[host][proto][port]
                        if port_info["state"] == "open":
                            device.open_ports.append(port)
                            device.services.append(Service(
                                port=port,
                                protocol=proto,
                                name=port_info.get("name", ""),
                                product=port_info.get("product", ""),
                                version=port_info.get("version", ""),
                            ))
                result.devices.append(device)

            result.mark_completed()

        except nmap.PortScannerError as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Port scan failed: {e}")
        except Exception as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Unexpected error: {e}")

        self._current_scan = None
        return result

    def scan_services(self, target: str, ports: str = "", timeout: int = 0) -> ScanResult:
        """Service/version detection scan."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(scan_id=scan_id, scan_type=ScanType.SERVICE_SCAN, target=target)
        result.mark_running()
        self._current_scan = result

        actual_timeout = timeout or self.config.host_timeout

        log.info(f"[{scan_id}] Service scan on {target}")

        args = f"-sV -sC {self.config.speed_flag} --version-intensity 5"
        try:
            self._scanner.scan(
                hosts=target,
                ports=ports or None,
                arguments=args,
                timeout=actual_timeout,
            )

            for host in self._scanner.all_hosts():
                device = self._parse_host_result(host, scan_depth=2)
                result.devices.append(device)

            result.mark_completed()

        except nmap.PortScannerError as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Service scan failed: {e}")
        except Exception as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Unexpected error: {e}")

        self._current_scan = None
        return result

    def full_audit(self, target: str, timeout: int = 0) -> ScanResult:
        """Full audit — aggressive scan."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(scan_id=scan_id, scan_type=ScanType.FULL_AUDIT, target=target)
        result.mark_running()
        self._current_scan = result

        actual_timeout = timeout or self.config.host_timeout

        audit = get_audit_logger()
        if audit:
            audit.log_action("full_audit", target, f"scan_id={scan_id}")

        log.info(f"[{scan_id}] Full audit on {target}")

        try:
            self._scanner.scan(
                hosts=target,
                arguments=f"-A {self.config.speed_flag} --min-rate=100 -O --osscan-guess",
                timeout=actual_timeout,
            )

            for host in self._scanner.all_hosts():
                device = self._parse_host_result(host, scan_depth=3)
                result.devices.append(device)

            result.mark_completed()
            log.info(f"[{scan_id}] Full audit complete: {len(result.devices)} hosts")

        except nmap.PortScannerError as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Full audit failed: {e}")
        except Exception as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Unexpected error: {e}")

        self._current_scan = None
        return result
