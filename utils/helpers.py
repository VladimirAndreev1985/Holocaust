"""General utility helpers."""

from __future__ import annotations

import ipaddress
import re
import socket
from datetime import datetime
from typing import Optional


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_mac(mac: str) -> bool:
    return bool(re.match(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", mac))


def ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


def get_network_range(ip: str, netmask: str) -> str:
    """Convert IP + netmask to CIDR notation."""
    try:
        prefix = sum(bin(int(x)).count("1") for x in netmask.split("."))
        network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return str(network)
    except ValueError:
        return f"{ip}/24"


def resolve_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return ""


def format_mac(mac: str) -> str:
    """Normalize MAC address to AA:BB:CC:DD:EE:FF format."""
    mac = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(mac) != 12:
        return mac
    return ":".join(mac[i:i+2].upper() for i in range(0, 12, 2))


def format_timestamp(dt: Optional[datetime] = None) -> str:
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m"


def severity_to_color(severity: str) -> str:
    colors = {
        "info": "#5a7ea0",
        "low": "#4a8a5a",
        "medium": "#b09040",
        "high": "#a05050",
        "critical": "#c04848",
    }
    return colors.get(severity.lower(), "#888888")


def truncate(text: str, max_length: int = 80) -> str:
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def port_list_to_string(ports: list[int]) -> str:
    """Convert port list to nmap-style range string: [22,23,24,80] -> '22-24,80'."""
    if not ports:
        return ""
    ports = sorted(set(ports))
    ranges = []
    start = ports[0]
    end = ports[0]

    for p in ports[1:]:
        if p == end + 1:
            end = p
        else:
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")
            start = end = p

    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")

    return ",".join(ranges)
