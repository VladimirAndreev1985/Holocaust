"""Checks and installs required system tools and Python packages."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from core.logger import get_logger

log = get_logger("dependencies")


@dataclass
class Dependency:
    name: str
    binary: str  # command-line binary name
    package: str  # apt package name
    is_python: bool = False
    required: bool = True
    installed: bool = False
    version: str = ""


SYSTEM_DEPENDENCIES: list[Dependency] = [
    Dependency(name="Nmap", binary="nmap", package="nmap"),
    Dependency(name="Aircrack-ng", binary="aircrack-ng", package="aircrack-ng"),
    Dependency(name="Airmon-ng", binary="airmon-ng", package="aircrack-ng"),
    Dependency(name="Airodump-ng", binary="airodump-ng", package="aircrack-ng"),
    Dependency(name="Metasploit", binary="msfconsole", package="metasploit-framework"),
    Dependency(name="Metasploit RPC", binary="msfrpcd", package="metasploit-framework"),
    Dependency(name="Wireshark CLI", binary="tshark", package="wireshark"),
    Dependency(name="iw", binary="iw", package="iw"),
    Dependency(name="wpa_supplicant", binary="wpa_supplicant", package="wpasupplicant"),
    Dependency(name="ip", binary="ip", package="iproute2"),
    Dependency(name="macchanger", binary="macchanger", package="macchanger", required=False),
]

PYTHON_DEPENDENCIES: list[str] = [
    "PySide6",
    "python-nmap",
    "scapy",
    "psutil",
    "requests",
    "vulners",
    "pymsf",
    "jinja2",
    "xhtml2pdf",
]


class DependencyManager:

    def __init__(self) -> None:
        self.dependencies = [Dependency(**d.__dict__) for d in SYSTEM_DEPENDENCIES]

    def check_all(self) -> list[Dependency]:
        """Check which system dependencies are installed."""
        for dep in self.dependencies:
            dep.installed = self._check_binary(dep.binary)
            if dep.installed:
                dep.version = self._get_version(dep.binary)
        return self.dependencies

    def get_missing(self) -> list[Dependency]:
        self.check_all()
        return [d for d in self.dependencies if not d.installed and d.required]

    def get_missing_optional(self) -> list[Dependency]:
        self.check_all()
        return [d for d in self.dependencies if not d.installed and not d.required]

    def install_missing(self, deps: list[Dependency] | None = None) -> tuple[list[str], list[str]]:
        """Install missing dependencies via apt. Returns (success_list, fail_list)."""
        if deps is None:
            deps = self.get_missing()

        packages = list({d.package for d in deps})
        if not packages:
            return [], []

        log.info(f"Installing packages: {', '.join(packages)}")

        success = []
        failed = []

        # Update apt cache first
        try:
            subprocess.run(
                ["sudo", "apt-get", "update", "-qq"],
                capture_output=True, timeout=120, check=True,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log.error(f"apt-get update failed: {e}")

        for pkg in packages:
            try:
                subprocess.run(
                    ["sudo", "apt-get", "install", "-y", "-qq", pkg],
                    capture_output=True, timeout=300, check=True,
                )
                success.append(pkg)
                log.info(f"Installed: {pkg}")
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                failed.append(pkg)
                log.error(f"Failed to install {pkg}: {e}")

        self.check_all()
        return success, failed

    def check_python_packages(self) -> list[str]:
        """Return list of missing Python packages."""
        missing = []
        for pkg in PYTHON_DEPENDENCIES:
            try:
                __import__(pkg.replace("-", "_").lower())
            except ImportError:
                missing.append(pkg)
        return missing

    def install_python_packages(self, packages: list[str] | None = None) -> bool:
        if packages is None:
            packages = self.check_python_packages()
        if not packages:
            return True

        log.info(f"Installing Python packages: {', '.join(packages)}")
        try:
            subprocess.run(
                ["pip", "install", "--break-system-packages", *packages],
                capture_output=True, timeout=300, check=True,
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            log.error(f"pip install failed: {e}")
            return False

    @staticmethod
    def _check_binary(name: str) -> bool:
        return shutil.which(name) is not None

    @staticmethod
    def _get_version(binary: str) -> str:
        try:
            result = subprocess.run(
                [binary, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout.strip() or result.stderr.strip()
            return output.split("\n")[0][:80] if output else ""
        except Exception:
            return ""
