"""LAN Scanner — async network discovery and service enumeration using nmap."""

from __future__ import annotations

import uuid
from typing import Optional

import nmap

from core.logger import get_logger, get_audit_logger
from models.device import Device, Service
from models.scan_result import ScanResult, ScanStatus, ScanType

log = get_logger("lan_scanner")


class LanScanner:
    """Performs progressive network scanning: discovery -> ports -> services -> OS."""

    def __init__(self) -> None:
        self._scanner = nmap.PortScanner()
        self._current_scan: Optional[ScanResult] = None

    @property
    def is_scanning(self) -> bool:
        return self._current_scan is not None and self._current_scan.is_running

    def discover_hosts(self, target: str, timeout: int = 30) -> ScanResult:
        """Phase 1: Quick host discovery (nmap -sn)."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(scan_id=scan_id, scan_type=ScanType.DISCOVERY, target=target)
        result.mark_running()
        self._current_scan = result

        audit = get_audit_logger()
        if audit:
            audit.log_action("host_discovery", target, f"scan_id={scan_id}")

        log.info(f"[{scan_id}] Starting host discovery on {target}")

        try:
            self._scanner.scan(
                hosts=target,
                arguments="-sn -T4 --min-rate=100",
                timeout=timeout,
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

    def scan_ports(self, target: str, ports: str = "1-10000", timeout: int = 120) -> ScanResult:
        """Phase 2: Port scan with SYN scan (nmap -sS)."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(scan_id=scan_id, scan_type=ScanType.PORT_SCAN, target=target)
        result.mark_running()
        self._current_scan = result

        log.info(f"[{scan_id}] Port scan on {target}, ports={ports}")

        try:
            self._scanner.scan(
                hosts=target,
                ports=ports,
                arguments="-sS -T4 --min-rate=200",
                timeout=timeout,
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
            log.info(f"[{scan_id}] Port scan complete")

        except nmap.PortScannerError as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Port scan failed: {e}")
        except Exception as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Unexpected error: {e}")

        self._current_scan = None
        return result

    def scan_services(self, target: str, ports: str = "", timeout: int = 180) -> ScanResult:
        """Phase 3: Service/version detection (nmap -sV)."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(scan_id=scan_id, scan_type=ScanType.SERVICE_SCAN, target=target)
        result.mark_running()
        self._current_scan = result

        log.info(f"[{scan_id}] Service scan on {target}")

        args = "-sV -sC -T4 --version-intensity 5"
        try:
            self._scanner.scan(
                hosts=target,
                ports=ports or None,
                arguments=args,
                timeout=timeout,
            )

            for host in self._scanner.all_hosts():
                device = Device(ip=host)
                host_data = self._scanner[host]

                if "mac" in host_data.get("addresses", {}):
                    device.mac = host_data["addresses"]["mac"]

                hostnames = host_data.get("hostnames", [])
                if hostnames and hostnames[0].get("name"):
                    device.hostname = hostnames[0]["name"]

                # OS detection from -sC scripts
                if "osmatch" in host_data:
                    matches = host_data["osmatch"]
                    if matches:
                        best = matches[0]
                        device.os_name = best.get("name", "")
                        device.os_accuracy = int(best.get("accuracy", 0))

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

                device.scan_depth = 2
                result.devices.append(device)

            result.mark_completed()
            log.info(f"[{scan_id}] Service scan complete")

        except nmap.PortScannerError as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Service scan failed: {e}")
        except Exception as e:
            result.mark_failed(str(e))
            log.error(f"[{scan_id}] Unexpected error: {e}")

        self._current_scan = None
        return result

    def full_audit(self, target: str, timeout: int = 300) -> ScanResult:
        """Phase 4: Full audit — aggressive scan (nmap -A)."""
        scan_id = str(uuid.uuid4())[:8]
        result = ScanResult(scan_id=scan_id, scan_type=ScanType.FULL_AUDIT, target=target)
        result.mark_running()
        self._current_scan = result

        audit = get_audit_logger()
        if audit:
            audit.log_action("full_audit", target, f"scan_id={scan_id}")

        log.info(f"[{scan_id}] Full audit on {target}")

        try:
            self._scanner.scan(
                hosts=target,
                arguments="-A -T4 --min-rate=100 -O --osscan-guess",
                timeout=timeout,
            )

            for host in self._scanner.all_hosts():
                device = Device(ip=host)
                host_data = self._scanner[host]

                # Addresses
                if "mac" in host_data.get("addresses", {}):
                    device.mac = host_data["addresses"]["mac"]
                if "vendor" in host_data:
                    vendors = host_data["vendor"]
                    if vendors:
                        device.vendor = list(vendors.values())[0]

                hostnames = host_data.get("hostnames", [])
                if hostnames and hostnames[0].get("name"):
                    device.hostname = hostnames[0]["name"]

                # OS
                if "osmatch" in host_data:
                    matches = host_data["osmatch"]
                    if matches:
                        best = matches[0]
                        device.os_name = best.get("name", "")
                        device.os_accuracy = int(best.get("accuracy", 0))
                        # Extract OS version
                        osclasses = best.get("osclass", [])
                        if osclasses:
                            device.os_version = osclasses[0].get("osgen", "")

                # Services
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

                device.scan_depth = 3
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

    def scan_single_host(self, ip: str) -> Device:
        """Quick comprehensive scan of a single host."""
        result = self.full_audit(ip, timeout=120)
        if result.devices:
            return result.devices[0]
        return Device(ip=ip, is_alive=False)
