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


def check_dependencies() -> None:
    from core.logger import get_logger
    log = get_logger("startup")

    from core.dependency_manager import DependencyManager
    dm = DependencyManager()

    missing = dm.get_missing()
    if missing:
        names = ", ".join(d.name for d in missing)
        log.warning(f"Missing system tools: {names}")
        log.info("These will be needed for full functionality. Install via Settings tab.")

    missing_py = dm.check_python_packages()
    if missing_py:
        log.warning(f"Missing Python packages: {', '.join(missing_py)}")


def main() -> int:
    # Root check
    try:
        check_root()
    except AttributeError:
        # Windows doesn't have geteuid
        pass

    # Init logging
    emitter = init_logging()

    from core.logger import get_logger
    log = get_logger("startup")
    log.info("=" * 50)
    log.info("  Holocaust Network Auditor — Starting...")
    log.info("=" * 50)

    # Init databases
    init_databases()
    log.info("Databases initialized")

    # Check dependencies
    check_dependencies()

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
