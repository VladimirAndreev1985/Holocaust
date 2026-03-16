"""QThread workers for non-blocking scan operations."""

from __future__ import annotations

import copy
import threading
from typing import Optional

from PySide6.QtCore import QThread, Signal

from core.logger import get_logger
from models.device import Device
from models.scan_config import ScanConfig, ScanDepth
from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from modules.device_classifier import DeviceClassifier
from modules.lan_scanner import LanScanner
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.camera_auditor import CameraAuditor
from modules.pc_auditor import PcAuditor

log = get_logger("workers")


class DiscoveryWorker(QThread):
    """Worker thread for host discovery."""
    progress = Signal(str, int)     # message, percent
    host_found = Signal(object)     # Device
    finished = Signal(object)       # ScanResult
    error = Signal(str)

    def __init__(self, target: str, config: ScanConfig | None = None, parent=None):
        super().__init__(parent)
        self.target = target
        self._config = config or ScanConfig()
        self._scanner = LanScanner(self._config)
        self._classifier = DeviceClassifier()
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            self.progress.emit("Starting host discovery...", 0)
            result = self._scanner.discover_hosts(self.target)

            if self._abort_event.is_set():
                return

            self.progress.emit("Classifying devices...", 70)
            self._classifier.classify_all(result.devices)

            for device in result.devices:
                # Send a copy to prevent cross-thread data races
                self.host_found.emit(copy.deepcopy(device))

            self.progress.emit("Discovery complete", 100)
            self.finished.emit(result)

        except Exception as e:
            log.error(f"Discovery worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()


class FullScanWorker(QThread):
    """Worker thread for full network audit (discovery + ports + services + classification).

    Supports 3 scan depth profiles (Quick/Standard/Deep) and optional
    automatic vulnerability scanning after host discovery.
    Supports pause/resume via threading.Event.
    """
    progress = Signal(str, int)
    host_found = Signal(object)
    host_updated = Signal(object)
    vuln_phase_started = Signal()
    vuln_found = Signal(object)        # Vulnerability
    finished = Signal(object)          # ScanResult
    error = Signal(str)

    def __init__(self, target: str, config: ScanConfig | None = None, parent=None):
        super().__init__(parent)
        self.target = target
        self._config = config or ScanConfig()
        self._scanner = LanScanner(self._config)
        self._classifier = DeviceClassifier()
        self._abort_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # start unpaused

    @property
    def is_paused(self) -> bool:
        return not self._pause_event.is_set()

    def pause(self) -> None:
        """Pause scanning. Blocks worker thread at next checkpoint."""
        self._pause_event.clear()

    def resume(self) -> None:
        """Resume scanning."""
        self._pause_event.set()

    def _wait_if_paused(self) -> bool:
        """Block until unpaused. Returns False if abort requested during pause."""
        while not self._pause_event.is_set():
            if self._abort_event.is_set():
                return False
            self._pause_event.wait(0.5)
        return not self._abort_event.is_set()

    def run(self) -> None:
        try:
            depth = self._config.depth
            depth_label = depth.value.upper()

            # === Phase 1: Host Discovery ===
            self.progress.emit(f"Phase 1/{'3' if self._config.auto_vuln_scan else '2'}: "
                               f"Host discovery ({depth_label})...", 2)
            discovery = self._scanner.discover_hosts(self.target)

            if self._abort_event.is_set():
                return

            total = len(discovery.devices)
            if total == 0:
                self.progress.emit("No hosts found", 100)
                self.finished.emit(discovery)
                return

            for device in discovery.devices:
                self.host_found.emit(copy.deepcopy(device))

            # === Phase 2: Detailed scan per host ===
            phase_count = "3" if self._config.auto_vuln_scan else "2"
            for i, device in enumerate(discovery.devices):
                if not self._wait_if_paused():
                    return

                phase2_end = 50 if self._config.auto_vuln_scan else 90
                pct = 10 + int((i / total) * (phase2_end - 10))
                self.progress.emit(
                    f"Phase 2/{phase_count}: {depth_label} scan "
                    f"{device.ip} ({i+1}/{total})...", pct
                )

                detailed = self._scanner.scan_host(device.ip)

                # Merge data from detailed scan into discovery device
                device.services = detailed.services
                device.open_ports = detailed.open_ports
                device.os_name = detailed.os_name
                device.os_version = detailed.os_version
                device.os_accuracy = detailed.os_accuracy
                device.scan_depth = detailed.scan_depth

                if detailed.mac:
                    device.mac = detailed.mac
                if detailed.vendor:
                    device.vendor = detailed.vendor
                if detailed.hostname:
                    device.hostname = detailed.hostname

                # Classify device type
                self._classifier.classify(device)
                self.host_updated.emit(copy.deepcopy(device))

            # === Phase 3 (optional): Auto vulnerability scan ===
            if self._config.auto_vuln_scan and not self._abort_event.is_set():
                self.vuln_phase_started.emit()
                self._run_vuln_phase(discovery.devices, total)

            self.progress.emit("Scan complete", 100)
            self.finished.emit(discovery)

        except Exception as e:
            log.error(f"Full scan worker error: {e}")
            self.error.emit(str(e))

    def _run_vuln_phase(self, devices: list[Device], total: int) -> None:
        """Phase 3: Automated vulnerability scanning."""
        vuln_scanner = VulnerabilityScanner(timeout=self._config.host_timeout)

        if self._config.vulners_api_key:
            vuln_scanner.init_vulners(self._config.vulners_api_key)

        for i, device in enumerate(devices):
            if self._abort_event.is_set():
                return

            pct = 55 + int((i / total) * 40)
            self.progress.emit(
                f"Phase 3/3: Vuln scan {device.ip} ({i+1}/{total})...", pct
            )

            vulns = vuln_scanner.scan_device(device)
            for v in vulns:
                self.vuln_found.emit(v)

    def abort(self) -> None:
        self._abort_event.set()


class VulnScanWorker(QThread):
    """Worker thread for vulnerability scanning."""
    progress = Signal(str, int)
    vuln_found = Signal(object)    # Vulnerability
    finished = Signal(list)        # list[Vulnerability]
    error = Signal(str)

    def __init__(self, devices: list[Device], config: ScanConfig | None = None, parent=None):
        super().__init__(parent)
        self.devices = devices
        self._config = config or ScanConfig()
        self._scanner = VulnerabilityScanner(timeout=self._config.host_timeout)
        self._abort_event = threading.Event()

        if self._config.vulners_api_key:
            self._scanner.init_vulners(self._config.vulners_api_key)

    def run(self) -> None:
        try:
            all_vulns = []
            total = len(self.devices)

            for i, device in enumerate(self.devices):
                if self._abort_event.is_set():
                    return

                pct = int((i / total) * 100)
                self.progress.emit(f"Scanning {device.ip} ({i+1}/{total})...", pct)

                vulns = self._scanner.scan_device(device)
                for v in vulns:
                    self.vuln_found.emit(v)
                all_vulns.extend(vulns)

            self.progress.emit("Vulnerability scan complete", 100)
            self.finished.emit(all_vulns)

        except Exception as e:
            log.error(f"Vuln scan worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()


class CameraAuditWorker(QThread):
    """Worker thread for camera-specific auditing."""
    progress = Signal(str, int)
    result_ready = Signal(object, dict)  # Device, audit_result
    finished = Signal()
    error = Signal(str)

    def __init__(self, devices: list[Device], config: ScanConfig | None = None, parent=None):
        super().__init__(parent)
        self.devices = devices
        self._config = config or ScanConfig()
        self._auditor = CameraAuditor(timeout=self._config.host_timeout)
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            total = len(self.devices)
            for i, device in enumerate(self.devices):
                if self._abort_event.is_set():
                    return

                pct = int((i / total) * 100)
                self.progress.emit(f"Auditing camera {device.ip} ({i+1}/{total})...", pct)

                result = self._auditor.audit_camera(device)
                self.result_ready.emit(copy.deepcopy(device), result)

            self.progress.emit("Camera audit complete", 100)
            self.finished.emit()

        except Exception as e:
            log.error(f"Camera audit worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()


class PcAuditWorker(QThread):
    """Worker thread for PC-specific auditing."""
    progress = Signal(str, int)
    result_ready = Signal(object, dict)
    finished = Signal()
    error = Signal(str)

    def __init__(self, devices: list[Device], config: ScanConfig | None = None, parent=None):
        super().__init__(parent)
        self.devices = devices
        self._config = config or ScanConfig()
        self._auditor = PcAuditor(timeout=self._config.host_timeout)
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            total = len(self.devices)
            for i, device in enumerate(self.devices):
                if self._abort_event.is_set():
                    return

                pct = int((i / total) * 100)
                self.progress.emit(f"Auditing PC {device.ip} ({i+1}/{total})...", pct)

                result = self._auditor.audit_pc(device)
                self.result_ready.emit(copy.deepcopy(device), result)

            self.progress.emit("PC audit complete", 100)
            self.finished.emit()

        except Exception as e:
            log.error(f"PC audit worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()


class HostScanWorker(QThread):
    """Worker for rescanning specific hosts (single or batch) at chosen depth.

    Unlike FullScanWorker which does discovery first, this takes already-known
    IPs and runs detailed scans + optional vuln scan on each.
    """
    progress = Signal(str, int)
    host_updated = Signal(object)       # Device (updated)
    vuln_found = Signal(object)         # Vulnerability
    finished = Signal()
    error = Signal(str)

    def __init__(self, devices: list[Device], config: ScanConfig | None = None,
                 vuln_scan: bool = False, parent=None):
        super().__init__(parent)
        self._devices = devices
        self._config = config or ScanConfig()
        self._vuln_scan = vuln_scan
        self._scanner = LanScanner(self._config)
        self._classifier = DeviceClassifier()
        self._abort_event = threading.Event()

    def run(self) -> None:
        try:
            total = len(self._devices)
            depth_label = self._config.depth.value.upper()
            vuln_total = total if self._vuln_scan else 0
            grand_total = total + vuln_total

            for i, device in enumerate(self._devices):
                if self._abort_event.is_set():
                    return

                pct = int((i / grand_total) * 100) if grand_total else 0
                self.progress.emit(
                    f"{depth_label} scan {device.ip} ({i+1}/{total})...", pct
                )

                detailed = self._scanner.scan_host(device.ip)

                # Merge data
                device.services = detailed.services
                device.open_ports = detailed.open_ports
                device.os_name = detailed.os_name
                device.os_version = detailed.os_version
                device.os_accuracy = detailed.os_accuracy
                device.scan_depth = detailed.scan_depth

                if detailed.mac:
                    device.mac = detailed.mac
                if detailed.vendor:
                    device.vendor = detailed.vendor
                if detailed.hostname:
                    device.hostname = detailed.hostname

                self._classifier.classify(device)
                device.update_risk_level()
                self.host_updated.emit(copy.deepcopy(device))

            # Optional vuln scan phase
            if self._vuln_scan and not self._abort_event.is_set():
                vuln_scanner = VulnerabilityScanner(timeout=self._config.host_timeout)
                if self._config.vulners_api_key:
                    vuln_scanner.init_vulners(self._config.vulners_api_key)

                for i, device in enumerate(self._devices):
                    if self._abort_event.is_set():
                        return

                    pct = int(((total + i) / grand_total) * 100) if grand_total else 0
                    self.progress.emit(
                        f"Vuln scan {device.ip} ({i+1}/{total})...", pct
                    )
                    vulns = vuln_scanner.scan_device(device)
                    for v in vulns:
                        self.vuln_found.emit(v)

            self.progress.emit("Scan complete", 100)
            self.finished.emit()

        except Exception as e:
            log.error(f"Host scan worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort_event.set()


class UpdateWorker(QThread):
    """Worker thread for database updates."""
    progress = Signal(str, int)
    finished = Signal(dict)  # {component: success}
    error = Signal(str)

    def __init__(self, nvd_api_key: str = "", parent=None):
        super().__init__(parent)
        self._nvd_api_key = nvd_api_key
        self._updater = None

    def run(self) -> None:
        try:
            from core.updater import Updater
            self._updater = Updater(nvd_api_key=self._nvd_api_key)
            self._updater.signals.progress.connect(self.progress.emit)

            results = self._updater.update_all()

            self.progress.emit("Updates complete", 100)
            self.finished.emit(results)

        except Exception as e:
            log.error(f"Update worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        if self._updater:
            self._updater.abort()
