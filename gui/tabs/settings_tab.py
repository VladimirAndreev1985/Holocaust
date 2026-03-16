"""Settings Tab — application configuration."""

from __future__ import annotations

import configparser
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QGroupBox, QComboBox, QSpinBox,
    QFormLayout, QMessageBox,
)
from PySide6.QtCore import Qt, Signal


class SettingsTab(QWidget):
    """Application settings and configuration."""

    settings_saved = Signal(dict)
    update_databases = Signal()

    def __init__(self, config_path: Path | None = None, parent=None):
        super().__init__(parent)
        self._config_path = config_path or Path("config/settings.ini")
        self._config = configparser.ConfigParser()
        self._setup_ui()
        self._load_settings()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        title = QLabel("Settings")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        # === General ===
        general_group = QGroupBox("General")
        general_layout = QFormLayout(general_group)

        self._log_level = QComboBox()
        self._log_level.addItems(["DEBUG", "INFO", "WARNING", "ERROR"])
        general_layout.addRow("Log Level:", self._log_level)

        self._auto_update = QCheckBox("Auto-update databases on startup")
        self._auto_update.setChecked(True)
        general_layout.addRow(self._auto_update)

        self._confirm_exploits = QCheckBox("Confirm before running exploits")
        self._confirm_exploits.setChecked(True)
        general_layout.addRow(self._confirm_exploits)

        layout.addWidget(general_group)

        # === Scanning ===
        scan_group = QGroupBox("Scanning")
        scan_layout = QFormLayout(scan_group)

        self._scan_timeout = QSpinBox()
        self._scan_timeout.setRange(30, 600)
        self._scan_timeout.setValue(120)
        self._scan_timeout.setSuffix(" sec")
        scan_layout.addRow("Scan Timeout:", self._scan_timeout)

        self._port_range = QLineEdit("1-10000")
        scan_layout.addRow("Port Range:", self._port_range)

        self._scan_speed = QComboBox()
        self._scan_speed.addItems(["T1 (Sneaky)", "T2 (Polite)", "T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"])
        self._scan_speed.setCurrentIndex(3)
        scan_layout.addRow("Scan Speed:", self._scan_speed)

        layout.addWidget(scan_group)

        # === Metasploit ===
        msf_group = QGroupBox("Metasploit")
        msf_layout = QFormLayout(msf_group)

        self._msf_host = QLineEdit("127.0.0.1")
        msf_layout.addRow("RPC Host:", self._msf_host)

        self._msf_port = QSpinBox()
        self._msf_port.setRange(1, 65535)
        self._msf_port.setValue(55553)
        msf_layout.addRow("RPC Port:", self._msf_port)

        self._msf_pass = QLineEdit("msf")
        self._msf_pass.setEchoMode(QLineEdit.EchoMode.Password)
        msf_layout.addRow("RPC Password:", self._msf_pass)

        self._auto_msf = QCheckBox("Auto-connect to Metasploit on startup")
        msf_layout.addRow(self._auto_msf)

        layout.addWidget(msf_group)

        # === Vulners ===
        vulners_group = QGroupBox("Vulners API")
        vulners_layout = QFormLayout(vulners_group)

        self._vulners_key = QLineEdit()
        self._vulners_key.setPlaceholderText("API key (optional)")
        self._vulners_key.setEchoMode(QLineEdit.EchoMode.Password)
        vulners_layout.addRow("API Key:", self._vulners_key)

        layout.addWidget(vulners_group)

        # === Paths ===
        paths_group = QGroupBox("Paths")
        paths_layout = QFormLayout(paths_group)

        self._log_dir = QLineEdit("logs")
        paths_layout.addRow("Log Directory:", self._log_dir)

        self._report_dir = QLineEdit("reports_output")
        paths_layout.addRow("Report Directory:", self._report_dir)

        layout.addWidget(paths_group)

        # Buttons
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("Save Settings")
        save_btn.setObjectName("primaryButton")
        save_btn.clicked.connect(self._save_settings)

        update_btn = QPushButton("Update All Databases")
        update_btn.setObjectName("successButton")
        update_btn.clicked.connect(self.update_databases.emit)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(update_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        layout.addStretch()

    def _load_settings(self) -> None:
        if self._config_path.exists():
            self._config.read(self._config_path)

            if "general" in self._config:
                g = self._config["general"]
                self._log_level.setCurrentText(g.get("log_level", "DEBUG"))
                self._auto_update.setChecked(g.getboolean("auto_update", True))
                self._confirm_exploits.setChecked(g.getboolean("confirm_exploits", True))

            if "scanning" in self._config:
                s = self._config["scanning"]
                self._scan_timeout.setValue(s.getint("timeout", 120))
                self._port_range.setText(s.get("port_range", "1-10000"))
                self._scan_speed.setCurrentIndex(s.getint("speed", 3))

            if "metasploit" in self._config:
                m = self._config["metasploit"]
                self._msf_host.setText(m.get("host", "127.0.0.1"))
                self._msf_port.setValue(m.getint("port", 55553))
                self._msf_pass.setText(m.get("password", "msf"))
                self._auto_msf.setChecked(m.getboolean("auto_connect", False))

            if "vulners" in self._config:
                self._vulners_key.setText(self._config["vulners"].get("api_key", ""))

            if "paths" in self._config:
                p = self._config["paths"]
                self._log_dir.setText(p.get("log_dir", "logs"))
                self._report_dir.setText(p.get("report_dir", "reports_output"))

    def _save_settings(self) -> None:
        self._config["general"] = {
            "log_level": self._log_level.currentText(),
            "auto_update": str(self._auto_update.isChecked()),
            "confirm_exploits": str(self._confirm_exploits.isChecked()),
        }
        self._config["scanning"] = {
            "timeout": str(self._scan_timeout.value()),
            "port_range": self._port_range.text(),
            "speed": str(self._scan_speed.currentIndex()),
        }
        self._config["metasploit"] = {
            "host": self._msf_host.text(),
            "port": str(self._msf_port.value()),
            "password": self._msf_pass.text(),
            "auto_connect": str(self._auto_msf.isChecked()),
        }
        self._config["vulners"] = {
            "api_key": self._vulners_key.text(),
        }
        self._config["paths"] = {
            "log_dir": self._log_dir.text(),
            "report_dir": self._report_dir.text(),
        }

        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._config_path, "w") as f:
            self._config.write(f)

        self.settings_saved.emit(self.get_settings())
        QMessageBox.information(self, "Settings", "Settings saved successfully.")

    def get_settings(self) -> dict:
        return {
            "log_level": self._log_level.currentText(),
            "auto_update": self._auto_update.isChecked(),
            "confirm_exploits": self._confirm_exploits.isChecked(),
            "scan_timeout": self._scan_timeout.value(),
            "port_range": self._port_range.text(),
            "scan_speed": self._scan_speed.currentIndex(),
            "msf_host": self._msf_host.text(),
            "msf_port": self._msf_port.value(),
            "msf_password": self._msf_pass.text(),
            "msf_auto_connect": self._auto_msf.isChecked(),
            "vulners_api_key": self._vulners_key.text(),
            "log_dir": self._log_dir.text(),
            "report_dir": self._report_dir.text(),
        }
