"""Log Panel widget — collapsible real-time log viewer."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton,
    QComboBox, QLabel, QFrame,
)
from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QTextCharFormat, QColor, QFont


LEVEL_COLORS = {
    "DEBUG": "#6c7a89",
    "INFO": "#3498db",
    "WARNING": "#f39c12",
    "ERROR": "#e74c3c",
    "CRITICAL": "#9b59b6",
}


class LogPanel(QWidget):
    """Collapsible log panel with filtering — displayed at bottom of main window."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._collapsed = False
        self._filter = "ALL"
        self._max_lines = 5000
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar
        header = QFrame()
        header.setFixedHeight(32)
        header.setStyleSheet("background-color: #16213e; border-bottom: 1px solid #2a2a4a;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 0, 10, 0)

        self._toggle_btn = QPushButton("Logs")
        self._toggle_btn.setFlat(True)
        self._toggle_btn.setStyleSheet("color: #e94560; font-weight: bold; border: none;")
        self._toggle_btn.clicked.connect(self._toggle_collapse)

        self._filter_combo = QComboBox()
        self._filter_combo.addItems(["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        self._filter_combo.setFixedWidth(100)
        self._filter_combo.currentTextChanged.connect(self._set_filter)

        self._line_count = QLabel("0 lines")
        self._line_count.setStyleSheet("color: #6c7a89;")

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setFixedWidth(60)
        self._clear_btn.clicked.connect(self._clear_logs)

        header_layout.addWidget(self._toggle_btn)
        header_layout.addStretch()
        header_layout.addWidget(self._filter_combo)
        header_layout.addWidget(self._line_count)
        header_layout.addWidget(self._clear_btn)

        layout.addWidget(header)

        # Log text area
        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setFont(QFont("Consolas", 11))
        self._text.setStyleSheet("""
            QTextEdit {
                background-color: #0a0a1a;
                border: none;
                padding: 5px;
            }
        """)
        self._text.setMinimumHeight(120)
        self._text.setMaximumHeight(300)

        layout.addWidget(self._text)

    @Slot(str, str, str)
    def append_log(self, level: str, message: str, timestamp: str) -> None:
        """Add a log entry. Connected to LogSignalEmitter.log_record."""
        if self._filter != "ALL" and level != self._filter:
            return

        color = LEVEL_COLORS.get(level, "#e0e0e0")

        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))

        cursor = self._text.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)

        # Timestamp
        ts_fmt = QTextCharFormat()
        ts_fmt.setForeground(QColor("#6c7a89"))
        cursor.insertText(f"[{timestamp}] ", ts_fmt)

        # Level
        level_fmt = QTextCharFormat()
        level_fmt.setForeground(QColor(color))
        level_fmt.setFontWeight(QFont.Weight.Bold)
        cursor.insertText(f"{level:8s} ", level_fmt)

        # Message
        msg_fmt = QTextCharFormat()
        msg_fmt.setForeground(QColor("#e0e0e0"))
        cursor.insertText(f"{message}\n", msg_fmt)

        # Auto-scroll
        self._text.setTextCursor(cursor)
        self._text.ensureCursorVisible()

        # Update line count
        lines = self._text.document().blockCount()
        self._line_count.setText(f"{lines} lines")

        # Trim if too many lines
        if lines > self._max_lines:
            cursor.movePosition(cursor.MoveOperation.Start)
            cursor.movePosition(cursor.MoveOperation.Down, cursor.MoveMode.KeepAnchor, 500)
            cursor.removeSelectedText()

    def _toggle_collapse(self) -> None:
        self._collapsed = not self._collapsed
        self._text.setVisible(not self._collapsed)
        self._toggle_btn.setText("Logs +" if self._collapsed else "Logs")

    def _set_filter(self, level: str) -> None:
        self._filter = level

    def _clear_logs(self) -> None:
        self._text.clear()
        self._line_count.setText("0 lines")
