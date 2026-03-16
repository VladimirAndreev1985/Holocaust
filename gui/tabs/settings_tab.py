"""Settings Tab — application configuration."""

from __future__ import annotations

import configparser
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QCheckBox, QGroupBox, QComboBox, QSpinBox,
    QFormLayout, QMessageBox, QFrame, QGridLayout, QScrollArea,
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont


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
        # Auto-refresh DB status on startup (delayed so UI is ready)
        QTimer.singleShot(500, self._refresh_db_status)

    def _setup_ui(self) -> None:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSpacing(15)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        scroll.setWidget(content)

        title = QLabel("Settings")
        title.setObjectName("titleLabel")
        layout.addWidget(title)

        # === Database Status ===
        db_group = QGroupBox("Database Status")
        db_layout = QGridLayout(db_group)
        db_layout.setSpacing(8)

        headers = ["Component", "Status", "Details", "Last Updated"]
        for col, h in enumerate(headers):
            lbl = QLabel(h)
            lbl.setStyleSheet("color: #e94560; font-weight: bold; font-size: 12px;")
            db_layout.addWidget(lbl, 0, col)

        self._db_status_labels: dict[str, dict[str, QLabel]] = {}
        components = [
            ("nmap", "Nmap Scripts"),
            ("metasploit", "Metasploit DB"),
            ("cve_cache", "CVE Cache"),
            ("signatures", "Device Signatures"),
            ("vulners", "Vulners API"),
        ]
        for row, (key, name) in enumerate(components, start=1):
            name_lbl = QLabel(name)
            name_lbl.setStyleSheet("font-weight: bold;")
            status_lbl = QLabel("--")
            details_lbl = QLabel("--")
            updated_lbl = QLabel("--")
            for lbl in (status_lbl, details_lbl, updated_lbl):
                lbl.setStyleSheet("color: #8888aa;")
            db_layout.addWidget(name_lbl, row, 0)
            db_layout.addWidget(status_lbl, row, 1)
            db_layout.addWidget(details_lbl, row, 2)
            db_layout.addWidget(updated_lbl, row, 3)
            self._db_status_labels[key] = {
                "status": status_lbl,
                "details": details_lbl,
                "updated": updated_lbl,
            }

        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.clicked.connect(self._refresh_db_status)
        db_layout.addWidget(refresh_btn, len(components) + 1, 0, 1, 2)

        layout.addWidget(db_group)

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

    def _refresh_db_status(self) -> None:
        """Check and display status of all security databases."""
        db_dir = Path(__file__).parent.parent.parent / "database"

        # --- Nmap ---
        nmap_labels = self._db_status_labels["nmap"]
        nmap_path = shutil.which("nmap")
        if nmap_path:
            try:
                import subprocess
                r = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
                version = r.stdout.split("\n")[0].strip() if r.stdout else "installed"
                nmap_labels["status"].setText("Installed")
                nmap_labels["status"].setStyleSheet("color: #2ecc71; font-weight: bold;")
                nmap_labels["details"].setText(version)
                # Check script DB modification time
                nse_path = Path("/usr/share/nmap/scripts/script.db")
                if nse_path.exists():
                    mtime = datetime.fromtimestamp(nse_path.stat().st_mtime)
                    nmap_labels["updated"].setText(mtime.strftime("%Y-%m-%d %H:%M"))
                else:
                    nmap_labels["updated"].setText("N/A")
            except Exception:
                nmap_labels["status"].setText("Installed")
                nmap_labels["status"].setStyleSheet("color: #2ecc71; font-weight: bold;")
        else:
            nmap_labels["status"].setText("Not found")
            nmap_labels["status"].setStyleSheet("color: #e74c3c; font-weight: bold;")
            nmap_labels["details"].setText("sudo apt install nmap")

        # --- Metasploit ---
        msf_labels = self._db_status_labels["metasploit"]
        msf_path = shutil.which("msfconsole")
        if msf_path:
            msf_labels["status"].setText("Installed")
            msf_labels["status"].setStyleSheet("color: #2ecc71; font-weight: bold;")
            try:
                import subprocess
                r = subprocess.run(["msfconsole", "--version"], capture_output=True, text=True, timeout=10)
                msf_labels["details"].setText(r.stdout.strip()[:60] if r.stdout else "installed")
            except Exception:
                msf_labels["details"].setText("installed")
            # Check msf DB update time
            msf_db = Path("/usr/share/metasploit-framework/data/msfdb_version")
            if msf_db.exists():
                mtime = datetime.fromtimestamp(msf_db.stat().st_mtime)
                msf_labels["updated"].setText(mtime.strftime("%Y-%m-%d %H:%M"))
            elif shutil.which("msfupdate"):
                msf_labels["updated"].setText("Use 'Update All'")
            else:
                msf_labels["updated"].setText("N/A")
        else:
            msf_labels["status"].setText("Not found")
            msf_labels["status"].setStyleSheet("color: #e74c3c; font-weight: bold;")
            msf_labels["details"].setText("sudo apt install metasploit-framework")

        # --- CVE Cache ---
        cve_labels = self._db_status_labels["cve_cache"]
        cve_db_path = db_dir / "cve_cache.db"
        if cve_db_path.exists():
            try:
                conn = sqlite3.connect(cve_db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM cve_entries")
                count = cursor.fetchone()[0]
                conn.close()
                if count > 0:
                    cve_labels["status"].setText("Active")
                    cve_labels["status"].setStyleSheet("color: #2ecc71; font-weight: bold;")
                    cve_labels["details"].setText(f"{count} CVE entries cached")
                else:
                    cve_labels["status"].setText("Empty")
                    cve_labels["status"].setStyleSheet("color: #f39c12; font-weight: bold;")
                    cve_labels["details"].setText("0 entries — run Update All")
                mtime = datetime.fromtimestamp(cve_db_path.stat().st_mtime)
                cve_labels["updated"].setText(mtime.strftime("%Y-%m-%d %H:%M"))
            except Exception as e:
                cve_labels["status"].setText("Error")
                cve_labels["status"].setStyleSheet("color: #e74c3c; font-weight: bold;")
                cve_labels["details"].setText(str(e)[:50])
        else:
            cve_labels["status"].setText("Not created")
            cve_labels["status"].setStyleSheet("color: #f39c12; font-weight: bold;")
            cve_labels["details"].setText("Will be created on first run")

        # --- Device Signatures ---
        sig_labels = self._db_status_labels["signatures"]
        sig_db_path = db_dir / "device_signatures.db"
        if sig_db_path.exists():
            try:
                conn = sqlite3.connect(sig_db_path)
                cursor = conn.cursor()
                counts = {}
                for table in ["oui_vendor", "port_signature", "product_signature", "default_credentials"]:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    counts[table] = cursor.fetchone()[0]
                conn.close()
                total = sum(counts.values())
                sig_labels["status"].setText("Active" if total > 0 else "Empty")
                sig_labels["status"].setStyleSheet(
                    "color: #2ecc71; font-weight: bold;" if total > 0
                    else "color: #f39c12; font-weight: bold;"
                )
                sig_labels["details"].setText(
                    f"OUI: {counts['oui_vendor']}, Ports: {counts['port_signature']}, "
                    f"Products: {counts['product_signature']}, Creds: {counts['default_credentials']}"
                )
                mtime = datetime.fromtimestamp(sig_db_path.stat().st_mtime)
                sig_labels["updated"].setText(mtime.strftime("%Y-%m-%d %H:%M"))
            except Exception as e:
                sig_labels["status"].setText("Error")
                sig_labels["status"].setStyleSheet("color: #e74c3c; font-weight: bold;")
                sig_labels["details"].setText(str(e)[:50])
        else:
            sig_labels["status"].setText("Not created")
            sig_labels["status"].setStyleSheet("color: #f39c12; font-weight: bold;")

        # --- Vulners API ---
        vuln_labels = self._db_status_labels["vulners"]
        api_key = self._vulners_key.text().strip()
        if api_key:
            vuln_labels["status"].setText("Configured")
            vuln_labels["status"].setStyleSheet("color: #2ecc71; font-weight: bold;")
            vuln_labels["details"].setText(f"Key: {'*' * 8}...{api_key[-4:]}" if len(api_key) > 4 else "Key set")
        else:
            vuln_labels["status"].setText("No API key")
            vuln_labels["status"].setStyleSheet("color: #f39c12; font-weight: bold;")
            vuln_labels["details"].setText("Optional — works without key (limited)")
        vuln_labels["updated"].setText("N/A")

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
