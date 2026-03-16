#!/usr/bin/env python3
"""Holocaust — Network Auditor for Kali Linux.

Entry point: dependency check, logging init, database init, GUI launch.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)


def check_root() -> None:
    """Warn if not running as root — many features require it."""
    if os.geteuid() != 0:
        print("[WARNING] Holocaust should run as root for full functionality.")
        print("  Run: sudo python3 main.py")
        print()


def init_logging() -> object:
    from core.logger import setup_logging
    log_dir = PROJECT_ROOT / "logs"
    return setup_logging(log_dir=log_dir)


def init_databases() -> None:
    from database.db_manager import init_databases
    init_databases()


def ensure_python_packages() -> None:
    """Auto-install missing Python packages — GUI can't start without them."""
    import subprocess

    REQUIRED = [
        ("PySide6", "PySide6"),
        ("nmap", "python-nmap"),
        ("scapy", "scapy"),
        ("psutil", "psutil"),
        ("requests", "requests"),
        ("jinja2", "jinja2"),
    ]

    OPTIONAL = [
        ("vulners", "vulners"),
        ("pymsf", "pymsf"),
        ("xhtml2pdf", "xhtml2pdf"),
    ]

    missing = []
    for import_name, pip_name in REQUIRED:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)

    if missing:
        print(f"[*] Installing required packages: {', '.join(missing)}")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", *missing],
            stdout=sys.stdout, stderr=sys.stderr,
        )
        print("[+] Required packages installed")

    # Optional — install silently, don't fail if they don't work
    opt_missing = []
    for import_name, pip_name in OPTIONAL:
        try:
            __import__(import_name)
        except ImportError:
            opt_missing.append(pip_name)

    if opt_missing:
        print(f"[*] Installing optional packages: {', '.join(opt_missing)}")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--break-system-packages", *opt_missing],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            print("[+] Optional packages installed")
        except subprocess.CalledProcessError:
            print(f"[!] Some optional packages failed to install: {', '.join(opt_missing)}")
            print("    You can install them later via Settings tab.")


def check_system_tools() -> None:
    """Check system tools (nmap, aircrack, etc.) — report missing, don't auto-install."""
    from core.logger import get_logger
    log = get_logger("startup")

    from core.dependency_manager import DependencyManager
    dm = DependencyManager()

    missing = dm.get_missing()
    if missing:
        names = ", ".join(d.name for d in missing)
        log.warning(f"Missing system tools: {names}")
        log.info("Install them via: sudo apt install " + " ".join(d.package for d in missing))
        log.info("Or use the Settings tab to install with one click.")


def main() -> int:
    # Root check
    try:
        check_root()
    except AttributeError:
        # Windows doesn't have geteuid
        pass

    # Step 1: Auto-install Python packages (before any project imports)
    print("[*] Checking Python dependencies...")
    ensure_python_packages()

    # Step 2: Init logging (now PySide6 is guaranteed available)
    emitter = init_logging()

    from core.logger import get_logger
    log = get_logger("startup")
    log.info("=" * 50)
    log.info("  Holocaust Network Auditor — Starting...")
    log.info("=" * 50)

    # Step 3: Init databases
    init_databases()
    log.info("Databases initialized")

    # Step 4: Check system tools (report only, don't block)
    check_system_tools()

    # Launch GUI
    log.info("Launching GUI...")

    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QIcon

    app = QApplication(sys.argv)
    app.setApplicationName("Holocaust")
    app.setOrganizationName("Holocaust")

    # Apply dark theme
    app.setStyle("Fusion")
    style_path = PROJECT_ROOT / "assets" / "styles" / "dark_theme.qss"
    if style_path.exists():
        app.setStyleSheet(style_path.read_text(encoding="utf-8"))
        log.info("Dark theme applied")

    from gui.main_window import MainWindow
    window = MainWindow()
    window.show()

    log.info("Application ready")
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
