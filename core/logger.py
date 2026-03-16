"""Centralized logging system with Qt signal support for real-time log panel."""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QObject, Signal


class LogSignalEmitter(QObject):
    """Emits Qt signals when log records are created, for the GUI log panel."""
    log_record = Signal(str, str, str)  # level, message, timestamp


class QtLogHandler(logging.Handler):
    """Custom logging handler that emits Qt signals."""

    def __init__(self, emitter: LogSignalEmitter):
        super().__init__()
        self.emitter = emitter

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            timestamp = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
            self.emitter.log_record.emit(record.levelname, msg, timestamp)
        except Exception:
            self.handleError(record)


class AuditLogger:
    """Separate logger for audit trail — logs all pentesting actions for reporting."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"audit_{timestamp}.log"

        self._logger = logging.getLogger("holocaust.audit")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        handler = logging.FileHandler(self.log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        self._logger.addHandler(handler)

    def log_action(self, action: str, target: str, details: str = "") -> None:
        self._logger.info(f"ACTION: {action} | TARGET: {target} | {details}")

    def log_finding(self, finding: str, target: str, severity: str = "") -> None:
        self._logger.info(f"FINDING: {finding} | TARGET: {target} | SEVERITY: {severity}")

    def log_exploit(self, exploit: str, target: str, result: str = "") -> None:
        self._logger.info(f"EXPLOIT: {exploit} | TARGET: {target} | RESULT: {result}")


_emitter: Optional[LogSignalEmitter] = None
_audit_logger: Optional[AuditLogger] = None


def setup_logging(
    log_dir: Path | None = None,
    level: int = logging.DEBUG,
    console: bool = True,
) -> LogSignalEmitter:
    """Initialize the logging system. Call once at startup."""
    global _emitter, _audit_logger

    _emitter = LogSignalEmitter()

    root = logging.getLogger("holocaust")
    root.setLevel(level)
    root.handlers.clear()

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # Qt handler for GUI
    qt_handler = QtLogHandler(_emitter)
    qt_handler.setFormatter(fmt)
    qt_handler.setLevel(logging.DEBUG)
    root.addHandler(qt_handler)

    # Console handler
    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(fmt)
        console_handler.setLevel(logging.DEBUG)
        root.addHandler(console_handler)

    # File handler with rotation (10 MB max, keep 5 backups)
    if log_dir:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / "holocaust.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        file_handler.setLevel(logging.DEBUG)
        root.addHandler(file_handler)

        # Audit logger
        _audit_logger = AuditLogger(log_dir)

    return _emitter


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"holocaust.{name}")


def get_emitter() -> Optional[LogSignalEmitter]:
    return _emitter


def get_audit_logger() -> Optional[AuditLogger]:
    return _audit_logger
