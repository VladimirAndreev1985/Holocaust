"""Nmap output parser — converts raw nmap XML/dict to our models."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from core.logger import get_logger
from models.device import Device, Service

log = get_logger("nmap_parser")


class NmapParser:
    """Parses nmap scan results from XML files or python-nmap dict output."""

    @staticmethod
    def parse_xml_file(path: Path) -> list[Device]:
        """Parse an nmap XML output file into Device objects."""
        devices = []

        try:
            tree = ET.parse(path)
            root = tree.getroot()

            for host_elem in root.findall("host"):
                device = NmapParser._parse_host_element(host_elem)
                if device:
                    devices.append(device)

            log.info(f"Parsed {len(devices)} hosts from {path}")
        except ET.ParseError as e:
            log.error(f"XML parse error: {e}")
        except FileNotFoundError:
            log.error(f"File not found: {path}")

        return devices

    @staticmethod
    def parse_xml_string(xml_string: str) -> list[Device]:
        """Parse nmap XML output from string."""
        devices = []
        try:
            root = ET.fromstring(xml_string)
            for host_elem in root.findall("host"):
                device = NmapParser._parse_host_element(host_elem)
                if device:
                    devices.append(device)
        except ET.ParseError as e:
            log.error(f"XML parse error: {e}")
        return devices

    @staticmethod
    def parse_python_nmap(scanner_result: dict) -> list[Device]:
        """Parse python-nmap PortScanner result dict into Device objects."""
        devices = []

        for host, data in scanner_result.get("scan", {}).items():
            device = Device(ip=host)

            # Addresses
            addresses = data.get("addresses", {})
            device.mac = addresses.get("mac", "")

            # Vendor
            vendor = data.get("vendor", {})
            if vendor:
                device.vendor = list(vendor.values())[0]

            # Hostnames
            hostnames = data.get("hostnames", [])
            if hostnames and hostnames[0].get("name"):
                device.hostname = hostnames[0]["name"]

            # Status
            status = data.get("status", {})
            device.is_alive = status.get("state") == "up"

            # OS matches
            os_matches = data.get("osmatch", [])
            if os_matches:
                best = os_matches[0]
                device.os_name = best.get("name", "")
                device.os_accuracy = int(best.get("accuracy", 0))
                os_classes = best.get("osclass", [])
                if os_classes:
                    device.os_version = os_classes[0].get("osgen", "")

            # Services
            for proto in ("tcp", "udp"):
                ports_data = data.get(proto, {})
                for port_num, port_info in ports_data.items():
                    if port_info.get("state") == "open":
                        port = int(port_num)
                        device.open_ports.append(port)
                        device.services.append(Service(
                            port=port,
                            protocol=proto,
                            name=port_info.get("name", ""),
                            product=port_info.get("product", ""),
                            version=port_info.get("version", ""),
                            extra_info=port_info.get("extrainfo", ""),
                        ))

            devices.append(device)

        return devices

    @staticmethod
    def _parse_host_element(host_elem: ET.Element) -> Optional[Device]:
        """Parse a single <host> XML element."""
        # Status
        status_elem = host_elem.find("status")
        if status_elem is not None and status_elem.get("state") != "up":
            return None

        device = Device(ip="")

        # Addresses
        for addr in host_elem.findall("address"):
            addr_type = addr.get("addrtype", "")
            if addr_type == "ipv4":
                device.ip = addr.get("addr", "")
            elif addr_type == "mac":
                device.mac = addr.get("addr", "")
                device.vendor = addr.get("vendor", "")

        if not device.ip:
            return None

        # Hostnames
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hostname = hostnames_elem.find("hostname")
            if hostname is not None:
                device.hostname = hostname.get("name", "")

        # OS
        os_elem = host_elem.find("os")
        if os_elem is not None:
            os_match = os_elem.find("osmatch")
            if os_match is not None:
                device.os_name = os_match.get("name", "")
                device.os_accuracy = int(os_match.get("accuracy", 0))

        # Ports
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port = int(port_elem.get("portid", 0))
                proto = port_elem.get("protocol", "tcp")
                device.open_ports.append(port)

                service_elem = port_elem.find("service")
                if service_elem is not None:
                    device.services.append(Service(
                        port=port,
                        protocol=proto,
                        name=service_elem.get("name", ""),
                        product=service_elem.get("product", ""),
                        version=service_elem.get("version", ""),
                        extra_info=service_elem.get("extrainfo", ""),
                    ))
                else:
                    device.services.append(Service(port=port, protocol=proto))

        device.is_alive = True
        return device
