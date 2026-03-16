"""QThread workers for non-blocking scan operations."""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QThread, Signal

from core.logger import get_logger
from models.device import Device
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

    def __init__(self, target: str, parent=None):
        super().__init__(parent)
        self.target = target
        self._scanner = LanScanner()
        self._classifier = DeviceClassifier()
        self._abort = False

    def run(self) -> None:
        try:
            self.progress.emit("Starting host discovery...", 0)
            result = self._scanner.discover_hosts(self.target)

            if self._abort:
                return

            self.progress.emit("Classifying devices...", 70)
            self._classifier.classify_all(result.devices)

            for device in result.devices:
                self.host_found.emit(device)

            self.progress.emit("Discovery complete", 100)
            self.finished.emit(result)

        except Exception as e:
            log.error(f"Discovery worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort = True


class FullScanWorker(QThread):
    """Worker thread for full network audit (discovery + ports + services + classification)."""
    progress = Signal(str, int)
    host_found = Signal(object)
    host_updated = Signal(object)
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, target: str, parent=None):
        super().__init__(parent)
        self.target = target
        self._scanner = LanScanner()
        self._classifier = DeviceClassifier()
        self._abort = False

    def run(self) -> None:
        try:
            # Phase 1: Discovery
            self.progress.emit("Phase 1: Host discovery...", 5)
            discovery = self._scanner.discover_hosts(self.target)

            if self._abort:
                return

            total = len(discovery.devices)
            if total == 0:
                self.progress.emit("No hosts found", 100)
                self.finished.emit(discovery)
                return

            for device in discovery.devices:
                self.host_found.emit(device)

            # Phase 2: Full scan each host
            for i, device in enumerate(discovery.devices):
                if self._abort:
                    return

                pct = 10 + int((i / total) * 80)
                self.progress.emit(
                    f"Phase 2: Scanning {device.ip} ({i+1}/{total})...", pct
                )

                detailed = self._scanner.scan_single_host(device.ip)

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

                # Classify
                self._classifier.classify(device)
                self.host_updated.emit(device)

            self.progress.emit("Scan complete", 100)
            self.finished.emit(discovery)

        except Exception as e:
            log.error(f"Full scan worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort = True


class VulnScanWorker(QThread):
    """Worker thread for vulnerability scanning."""
    progress = Signal(str, int)
    vuln_found = Signal(object)    # Vulnerability
    finished = Signal(list)        # list[Vulnerability]
    error = Signal(str)

    def __init__(self, devices: list[Device], parent=None):
        super().__init__(parent)
        self.devices = devices
        self._scanner = VulnerabilityScanner()
        self._abort = False

    def run(self) -> None:
        try:
            all_vulns = []
            total = len(self.devices)

            for i, device in enumerate(self.devices):
                if self._abort:
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
        self._abort = True


class CameraAuditWorker(QThread):
    """Worker thread for camera-specific auditing."""
    progress = Signal(str, int)
    result_ready = Signal(object, dict)  # Device, audit_result
    finished = Signal()
    error = Signal(str)

    def __init__(self, devices: list[Device], parent=None):
        super().__init__(parent)
        self.devices = devices
        self._auditor = CameraAuditor()
        self._abort = False

    def run(self) -> None:
        try:
            total = len(self.devices)
            for i, device in enumerate(self.devices):
                if self._abort:
                    return

                pct = int((i / total) * 100)
                self.progress.emit(f"Auditing camera {device.ip} ({i+1}/{total})...", pct)

                result = self._auditor.audit_camera(device)
                self.result_ready.emit(device, result)

            self.progress.emit("Camera audit complete", 100)
            self.finished.emit()

        except Exception as e:
            log.error(f"Camera audit worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort = True


class PcAuditWorker(QThread):
    """Worker thread for PC-specific auditing."""
    progress = Signal(str, int)
    result_ready = Signal(object, dict)
    finished = Signal()
    error = Signal(str)

    def __init__(self, devices: list[Device], parent=None):
        super().__init__(parent)
        self.devices = devices
        self._auditor = PcAuditor()
        self._abort = False

    def run(self) -> None:
        try:
            total = len(self.devices)
            for i, device in enumerate(self.devices):
                if self._abort:
                    return

                pct = int((i / total) * 100)
                self.progress.emit(f"Auditing PC {device.ip} ({i+1}/{total})...", pct)

                result = self._auditor.audit_pc(device)
                self.result_ready.emit(device, result)

            self.progress.emit("PC audit complete", 100)
            self.finished.emit()

        except Exception as e:
            log.error(f"PC audit worker error: {e}")
            self.error.emit(str(e))

    def abort(self) -> None:
        self._abort = True


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
