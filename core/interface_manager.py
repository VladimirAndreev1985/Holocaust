"""Network interface management — detection, up/down, monitor mode."""

from __future__ import annotations

import re
import subprocess
from typing import Optional

import psutil

from core.logger import get_logger, get_audit_logger
from models.network_interface import InterfaceMode, InterfaceType, NetworkInterface

log = get_logger("interfaces")


class InterfaceManager:

    def __init__(self) -> None:
        self._interfaces: dict[str, NetworkInterface] = {}

    def refresh(self) -> list[NetworkInterface]:
        """Detect and return all network interfaces."""
        self._interfaces.clear()
        ifaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, addrs in ifaces.items():
            if name == "lo":
                continue

            iface = NetworkInterface(name=name)

            # Stats
            if name in stats:
                iface.is_up = stats[name].isup

            # Addresses
            for addr in addrs:
                if addr.family.name == "AF_INET":
                    iface.ip_address = addr.address
                    iface.netmask = addr.netmask or ""
                elif addr.family.name == "AF_PACKET" or addr.family.name == "AF_LINK":
                    iface.mac_address = addr.address

            # Determine type
            iface.iface_type = self._detect_type(name)

            # Wireless-specific info
            if iface.is_wireless:
                self._fill_wireless_info(iface)

            # Gateway
            gws = psutil.net_if_stats()
            iface.gateway = self._get_gateway(name)

            self._interfaces[name] = iface

        log.info(f"Found {len(self._interfaces)} interfaces")
        return list(self._interfaces.values())

    def get(self, name: str) -> Optional[NetworkInterface]:
        if name not in self._interfaces:
            self.refresh()
        return self._interfaces.get(name)

    def get_all(self) -> list[NetworkInterface]:
        if not self._interfaces:
            self.refresh()
        return list(self._interfaces.values())

    def get_wireless(self) -> list[NetworkInterface]:
        return [i for i in self.get_all() if i.is_wireless]

    def get_connected(self) -> list[NetworkInterface]:
        return [i for i in self.get_all() if i.is_connected]

    def set_up(self, name: str) -> bool:
        log.info(f"Bringing up interface {name}")
        audit = get_audit_logger()
        if audit:
            audit.log_action("interface_up", name)
        return self._run_ip(["link", "set", name, "up"])

    def set_down(self, name: str) -> bool:
        log.info(f"Bringing down interface {name}")
        audit = get_audit_logger()
        if audit:
            audit.log_action("interface_down", name)
        return self._run_ip(["link", "set", name, "down"])

    def enable_monitor(self, name: str) -> Optional[str]:
        """Enable monitor mode. Returns the monitor interface name (e.g. wlan0mon)."""
        log.info(f"Enabling monitor mode on {name}")
        audit = get_audit_logger()
        if audit:
            audit.log_action("enable_monitor", name)

        # Kill interfering processes
        self._airmon_check_kill()

        try:
            result = subprocess.run(
                ["sudo", "airmon-ng", "start", name],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + result.stderr

            # Parse monitor interface name from output
            match = re.search(r"monitor mode.*?enabled.*?(\w+mon\w*)", output, re.IGNORECASE)
            if match:
                mon_name = match.group(1)
            else:
                mon_name = f"{name}mon"

            self.refresh()
            log.info(f"Monitor mode enabled: {mon_name}")
            return mon_name

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log.error(f"Failed to enable monitor mode on {name}: {e}")
            return None

    def disable_monitor(self, name: str) -> bool:
        """Disable monitor mode."""
        log.info(f"Disabling monitor mode on {name}")
        audit = get_audit_logger()
        if audit:
            audit.log_action("disable_monitor", name)

        try:
            subprocess.run(
                ["sudo", "airmon-ng", "stop", name],
                capture_output=True, text=True, timeout=30, check=True,
            )
            self.refresh()
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log.error(f"Failed to disable monitor mode: {e}")
            return False

    def airmon_check_kill(self) -> bool:
        """Kill interfering processes (NetworkManager, wpa_supplicant, etc.)."""
        return self._airmon_check_kill()

    # --- Private ---

    @staticmethod
    def _detect_type(name: str) -> InterfaceType:
        if name.startswith(("wlan", "wlp", "ath", "ra")):
            return InterfaceType.WIRELESS
        if name.startswith(("eth", "enp", "eno", "ens")):
            return InterfaceType.ETHERNET
        if name == "lo":
            return InterfaceType.LOOPBACK
        if name.startswith(("veth", "docker", "br-", "virbr", "tun", "tap")):
            return InterfaceType.VIRTUAL
        return InterfaceType.UNKNOWN

    @staticmethod
    def _fill_wireless_info(iface: NetworkInterface) -> None:
        try:
            result = subprocess.run(
                ["iwconfig", iface.name],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout

            # SSID
            match = re.search(r'ESSID:"([^"]*)"', output)
            if match:
                iface.ssid = match.group(1)

            # Mode
            match = re.search(r"Mode:(\w+)", output)
            if match:
                mode = match.group(1).lower()
                if mode == "monitor":
                    iface.mode = InterfaceMode.MONITOR
                else:
                    iface.mode = InterfaceMode.MANAGED

            # Channel / Frequency
            match = re.search(r"Frequency[=:](\S+)", output)
            if match:
                iface.frequency = match.group(1)

            # Check monitor mode support
            result2 = subprocess.run(
                ["iw", "phy"],
                capture_output=True, text=True, timeout=5,
            )
            if "monitor" in result2.stdout.lower():
                iface.supports_monitor = True

        except Exception:
            pass

    @staticmethod
    def _get_gateway(iface_name: str) -> str:
        try:
            result = subprocess.run(
                ["ip", "route", "show", "dev", iface_name],
                capture_output=True, text=True, timeout=5,
            )
            match = re.search(r"default via (\S+)", result.stdout)
            return match.group(1) if match else ""
        except Exception:
            return ""

    @staticmethod
    def _run_ip(args: list[str]) -> bool:
        try:
            subprocess.run(
                ["sudo", "ip", *args],
                capture_output=True, timeout=10, check=True,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log.error(f"ip command failed: {e}")
            return False

    @staticmethod
    def _airmon_check_kill() -> bool:
        try:
            subprocess.run(
                ["sudo", "airmon-ng", "check", "kill"],
                capture_output=True, timeout=15, check=True,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log.error(f"airmon-ng check kill failed: {e}")
            return False
