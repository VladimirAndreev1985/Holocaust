"""QThread workers for attack operations — runs attacks in background threads."""

from __future__ import annotations

import copy
import threading
from typing import Optional

from PySide6.QtCore import QThread, Signal

from core.logger import get_logger
from models.device import Device
from models.credential import Credential
from models.vulnerability import Vulnerability

log = get_logger("attack_workers")


class ArpSpoofWorker(QThread):
    """Worker for ARP spoofing / MITM attacks."""
    progress = Signal(str)          # status message
    packet_captured = Signal(str)   # captured packet line
    finished = Signal()
    error = Signal(str)

    def __init__(self, interface: str, target_ip: str, gateway_ip: str,
                 two_way: bool = True, capture: bool = False, parent=None):
        super().__init__(parent)
        self._interface = interface
        self._target_ip = target_ip
        self._gateway_ip = gateway_ip
        self._two_way = two_way
        self._capture = capture
        self._spoofer = None
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            from modules.arp_spoofer import ArpSpoofer
            self._spoofer = ArpSpoofer()

            self.progress.emit(f"Starting MITM: {self._target_ip} <-> {self._gateway_ip}")

            success = self._spoofer.start(
                interface=self._interface,
                target_ip=self._target_ip,
                gateway_ip=self._gateway_ip,
                two_way=self._two_way,
                capture=self._capture,
                on_packet=lambda line: self.packet_captured.emit(line),
            )

            if not success:
                self.error.emit("Failed to start ARP spoofing — check permissions and tools")
                return

            self.progress.emit(f"MITM active: {self._target_ip} <-> {self._gateway_ip}")

            # Keep running until aborted
            while not self._abort_event.is_set():
                self._abort_event.wait(1.0)

            self._spoofer.stop()
            self.progress.emit("MITM stopped — ARP tables restored")
            self.finished.emit()

        except Exception as e:
            log.error(f"ARP spoof worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()
        if self._spoofer:
            self._spoofer.stop()


class DeauthWorker(QThread):
    """Worker for WiFi deauthentication attacks."""
    progress = Signal(str)
    output = Signal(str)
    finished = Signal()
    error = Signal(str)

    def __init__(self, interface: str, bssid: str, client_mac: str = "",
                 count: int = 0, parent=None):
        super().__init__(parent)
        self._interface = interface
        self._bssid = bssid
        self._client_mac = client_mac
        self._count = count
        self._attacker = None
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            from modules.wifi_attacker import WiFiAttacker
            self._attacker = WiFiAttacker()

            target = self._client_mac or "broadcast"
            self.progress.emit(f"Deauth attack: AP={self._bssid}, client={target}")

            success = self._attacker.deauth(
                interface=self._interface,
                bssid=self._bssid,
                client_mac=self._client_mac,
                count=self._count,
                on_output=lambda line: self.output.emit(line),
            )

            if not success:
                self.error.emit("Deauth failed — check monitor mode and tools")
                return

            if self._count == 0:
                # Continuous — wait for abort
                while not self._abort_event.is_set():
                    self._abort_event.wait(1.0)
                self._attacker.stop_deauth()
            else:
                # Wait for process to finish
                if self._attacker._deauth_proc:
                    self._attacker._deauth_proc.wait()

            self.progress.emit("Deauth attack stopped")
            self.finished.emit()

        except Exception as e:
            log.error(f"Deauth worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()
        if self._attacker:
            self._attacker.stop_deauth()


class HandshakeWorker(QThread):
    """Worker for WPA handshake capture + crack."""
    progress = Signal(str)
    output = Signal(str)
    handshake_captured = Signal(str)  # cap file path
    password_found = Signal(str)      # cracked password
    finished = Signal()
    error = Signal(str)

    def __init__(self, interface: str, bssid: str, channel: int,
                 timeout: int = 120, auto_deauth: bool = True,
                 wordlist: str = "", parent=None):
        super().__init__(parent)
        self._interface = interface
        self._bssid = bssid
        self._channel = channel
        self._timeout = timeout
        self._auto_deauth = auto_deauth
        self._wordlist = wordlist
        self._attacker = None
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            from modules.wifi_attacker import WiFiAttacker
            self._attacker = WiFiAttacker()

            self.progress.emit(f"Capturing handshake from {self._bssid} (ch {self._channel})...")

            cap_file = self._attacker.capture_handshake(
                interface=self._interface,
                bssid=self._bssid,
                channel=self._channel,
                timeout=self._timeout,
                auto_deauth=self._auto_deauth,
                on_output=lambda line: self.output.emit(line),
            )

            if self._abort_event.is_set():
                return

            if cap_file:
                self.handshake_captured.emit(cap_file)
                self.progress.emit(f"Handshake saved: {cap_file}")

                # Auto-crack if wordlist provided
                if self._wordlist:
                    self.progress.emit(f"Cracking with wordlist: {self._wordlist}")
                    password = self._attacker.crack_handshake(
                        cap_file=cap_file,
                        bssid=self._bssid,
                        wordlist=self._wordlist,
                        on_output=lambda line: self.output.emit(line),
                    )
                    if password:
                        self.password_found.emit(password)
                        self.progress.emit(f"Password found: {password}")
                    else:
                        self.progress.emit("Password not found in wordlist")
            else:
                self.progress.emit("No handshake captured")

            self.finished.emit()

        except Exception as e:
            log.error(f"Handshake worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()
        if self._attacker:
            self._attacker.stop_all()


class WpsWorker(QThread):
    """Worker for WPS PIN brute-force."""
    progress = Signal(str)
    output = Signal(str)
    pin_found = Signal(str, str)  # pin, password
    finished = Signal()
    error = Signal(str)

    def __init__(self, interface: str, bssid: str, channel: int,
                 method: str = "reaver", timeout: int = 600, parent=None):
        super().__init__(parent)
        self._interface = interface
        self._bssid = bssid
        self._channel = channel
        self._method = method
        self._timeout = timeout
        self._attacker = None
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            from modules.wifi_attacker import WiFiAttacker
            self._attacker = WiFiAttacker()

            self.progress.emit(f"WPS attack ({self._method}): {self._bssid}")

            result = self._attacker.wps_attack(
                interface=self._interface,
                bssid=self._bssid,
                channel=self._channel,
                method=self._method,
                timeout=self._timeout,
                on_output=lambda line: self.output.emit(line),
            )

            if result:
                self.pin_found.emit(result["pin"], result.get("password", ""))
                self.progress.emit(f"WPS cracked! PIN={result['pin']}")
            else:
                self.progress.emit("WPS attack failed — PIN not found")

            self.finished.emit()

        except Exception as e:
            log.error(f"WPS worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()
        if self._attacker:
            self._attacker.stop_wps()


class WebScanWorker(QThread):
    """Worker for web vulnerability scanning."""
    progress = Signal(str, int)        # message, percent
    vuln_found = Signal(object)        # Vulnerability
    finished = Signal(list)            # list[Vulnerability]
    error = Signal(str)

    def __init__(self, targets: list[tuple[str, int, bool]],
                 timeout: int = 10, parent=None):
        """
        Args:
            targets: List of (ip, port, use_ssl) tuples
        """
        super().__init__(parent)
        self._targets = targets
        self._timeout = timeout
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            from modules.web_scanner import WebScanner
            scanner = WebScanner(timeout=self._timeout)

            all_vulns = []
            total = len(self._targets)

            for i, (ip, port, use_ssl) in enumerate(self._targets):
                if self._abort_event.is_set():
                    break

                pct = int((i / total) * 100) if total else 0
                scheme = "https" if use_ssl else "http"
                self.progress.emit(f"Web scan {scheme}://{ip}:{port} ({i+1}/{total})...", pct)

                vulns = scanner.scan_target(ip, port, use_ssl)
                for v in vulns:
                    self.vuln_found.emit(v)
                all_vulns.extend(vulns)

            self.progress.emit("Web scan complete", 100)
            self.finished.emit(all_vulns)

        except Exception as e:
            log.error(f"Web scan worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()


class PayloadGenWorker(QThread):
    """Worker for msfvenom payload generation."""
    progress = Signal(str)
    payload_ready = Signal(str)     # path to generated file
    handler_ready = Signal(str)     # path to .rc file
    finished = Signal()
    error = Signal(str)

    def __init__(self, payload: str, lhost: str, lport: int,
                 fmt: str = "exe", encoder: str = "", iterations: int = 1,
                 bad_chars: str = "", output_dir: str = "",
                 generate_handler: bool = True, parent=None):
        super().__init__(parent)
        self._payload = payload
        self._lhost = lhost
        self._lport = lport
        self._fmt = fmt
        self._encoder = encoder
        self._iterations = iterations
        self._bad_chars = bad_chars
        self._output_dir = output_dir
        self._generate_handler = generate_handler

    def run(self) -> None:
        try:
            from modules.payload_generator import PayloadGenerator
            gen = PayloadGenerator(output_dir=self._output_dir)

            self.progress.emit(f"Generating {self._payload} ({self._fmt})...")

            path = gen.generate(
                payload=self._payload,
                lhost=self._lhost,
                lport=self._lport,
                fmt=self._fmt,
                encoder=self._encoder,
                iterations=self._iterations,
                bad_chars=self._bad_chars,
            )

            if path:
                self.payload_ready.emit(path)
                self.progress.emit(f"Payload saved: {path}")

                # Generate handler RC
                if self._generate_handler:
                    rc = gen.generate_multi_handler_rc(
                        self._payload, self._lhost, self._lport
                    )
                    self.handler_ready.emit(rc)
            else:
                self.error.emit("Payload generation failed — check msfvenom installation")

            self.finished.emit()

        except Exception as e:
            log.error(f"Payload gen worker error: {e}")
            self.error.emit(str(e))


class BruteForceWorker(QThread):
    """Worker for credential brute-forcing."""
    progress = Signal(str, int)        # message, percent
    credential_found = Signal(object)  # Credential
    finished = Signal(object)          # BruteForceResult
    error = Signal(str)

    def __init__(self, target: str, port: int, service: str,
                 usernames: list[str] | None = None,
                 passwords: list[str] | None = None,
                 timeout: int = 5, threads: int = 3,
                 delay: float = 0.5, max_attempts: int = 0,
                 parent=None):
        super().__init__(parent)
        self._target = target
        self._port = port
        self._service = service
        self._usernames = usernames
        self._passwords = passwords
        self._timeout = timeout
        self._threads = threads
        self._delay = delay
        self._max_attempts = max_attempts
        self._bruteforcer = None
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            from modules.credential_bruteforcer import CredentialBruteForcer

            self._bruteforcer = CredentialBruteForcer(
                timeout=self._timeout,
                threads=self._threads,
                delay=self._delay,
                max_attempts=self._max_attempts,
            )

            def on_progress(tested, total, combo):
                pct = int((tested / total) * 100) if total else 0
                self.progress.emit(
                    f"Testing {self._service}://{self._target}:{self._port} "
                    f"[{combo}] ({tested}/{total})", pct
                )

            def on_found(cred):
                self.credential_found.emit(cred)

            result = self._bruteforcer.brute_force(
                target=self._target,
                port=self._port,
                service=self._service,
                usernames=self._usernames,
                passwords=self._passwords,
                on_progress=on_progress,
                on_found=on_found,
            )

            self.progress.emit(
                f"Brute-force complete: {len(result.valid_credentials)} valid", 100
            )
            self.finished.emit(result)

        except Exception as e:
            log.error(f"Brute-force worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()
        if self._bruteforcer:
            self._bruteforcer.abort()
