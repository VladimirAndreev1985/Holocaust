"""Reports Tab — generate and view audit reports."""

from __future__ import annotations

from pathlib import Path

from core.i18n import tr
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTextEdit, QFileDialog, QMessageBox, QGroupBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont


class ReportsTab(QWidget):
    """Report generation and viewing tab."""

    generate_html = Signal()
    generate_pdf = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._last_report_path: Path | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        title = QLabel(tr("Reports"))
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        # Generation controls
        gen_group = QGroupBox(tr("Generate Report"))
        gen_layout = QVBoxLayout(gen_group)

        btn_layout = QHBoxLayout()

        self._html_btn = QPushButton(tr("Generate HTML Report"))
        self._html_btn.setObjectName("primaryButton")
        self._html_btn.clicked.connect(self.generate_html.emit)

        self._pdf_btn = QPushButton(tr("Generate PDF Report"))
        self._pdf_btn.setObjectName("successButton")
        self._pdf_btn.clicked.connect(self.generate_pdf.emit)

        self._open_btn = QPushButton(tr("Open Report Folder"))
        self._open_btn.clicked.connect(self._open_folder)

        btn_layout.addWidget(self._html_btn)
        btn_layout.addWidget(self._pdf_btn)
        btn_layout.addWidget(self._open_btn)
        btn_layout.addStretch()
        gen_layout.addLayout(btn_layout)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet("color: #606070;")
        gen_layout.addWidget(self._status_label)
        layout.addWidget(gen_group)

        # Preview
        preview_group = QGroupBox(tr("Report Preview"))
        preview_layout = QVBoxLayout(preview_group)

        self._preview = QTextEdit()
        self._preview.setReadOnly(True)
        preview_layout.addWidget(self._preview)
        layout.addWidget(preview_group, 1)

    def set_report_generated(self, path: Path) -> None:
        self._last_report_path = path
        self._status_label.setText(tr("Report saved: {path}").format(path=path))
        self._status_label.setStyleSheet("color: #4a8a5a;")

        # Load HTML preview
        if path.suffix == ".html":
            try:
                content = path.read_text(encoding="utf-8")
                self._preview.setHtml(content)
            except Exception:
                self._preview.setPlainText(tr("Report generated at: {path}").format(path=path))

    def _open_folder(self) -> None:
        import subprocess
        reports_dir = Path("reports_output")
        reports_dir.mkdir(exist_ok=True)
        try:
            subprocess.Popen(["xdg-open", str(reports_dir)])
        except FileNotFoundError:
            subprocess.Popen(["open", str(reports_dir)])
