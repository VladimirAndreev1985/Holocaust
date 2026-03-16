"""Metasploit Tab — module browser, exploit runner, session manager."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QLineEdit,
    QGroupBox, QTextEdit, QSplitter, QComboBox, QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont


class MetasploitTab(QWidget):
    """Metasploit framework integration tab."""

    connect_requested = Signal(str, int, str)  # host, port, password
    exploit_run = Signal(str, str, int, str, dict)  # module, target_ip, port, payload, options

    def __init__(self, parent=None):
        super().__init__(parent)
        self._connected = False
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # Header
        header = QHBoxLayout()
        title = QLabel("Metasploit Framework")
        title.setObjectName("titleLabel")
        header.addWidget(title)
        header.addStretch()

        self._status_label = QLabel("Disconnected")
        self._status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        header.addWidget(self._status_label)

        self._connect_btn = QPushButton("Connect to msfrpcd")
        self._connect_btn.setObjectName("primaryButton")
        self._connect_btn.clicked.connect(self._on_connect)
        header.addWidget(self._connect_btn)
        layout.addLayout(header)

        # Connection settings
        conn_layout = QHBoxLayout()
        conn_layout.addWidget(QLabel("Host:"))
        self._host_input = QLineEdit("127.0.0.1")
        self._host_input.setMaximumWidth(150)
        conn_layout.addWidget(self._host_input)

        conn_layout.addWidget(QLabel("Port:"))
        self._port_input = QLineEdit("55553")
        self._port_input.setMaximumWidth(80)
        conn_layout.addWidget(self._port_input)

        conn_layout.addWidget(QLabel("Password:"))
        self._pass_input = QLineEdit("msf")
        self._pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_input.setMaximumWidth(150)
        conn_layout.addWidget(self._pass_input)

        conn_layout.addStretch()
        layout.addLayout(conn_layout)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # === Module Search ===
        search_group = QGroupBox("Module Search")
        search_layout = QVBoxLayout(search_group)

        search_bar = QHBoxLayout()
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Search modules (e.g. 'eternalblue', 'CVE-2021-36260')...")
        self._search_input.returnPressed.connect(self._on_search)
        search_bar.addWidget(self._search_input)

        self._search_btn = QPushButton("Search")
        self._search_btn.clicked.connect(self._on_search)
        search_bar.addWidget(self._search_btn)
        search_layout.addLayout(search_bar)

        self._modules_table = QTableWidget()
        self._modules_table.setColumnCount(5)
        self._modules_table.setHorizontalHeaderLabels([
            "Type", "Module", "Rank", "Description", "Action"
        ])
        self._modules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._modules_table.setAlternatingRowColors(True)
        self._modules_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        search_layout.addWidget(self._modules_table)
        splitter.addWidget(search_group)

        # === Exploit Config ===
        exploit_group = QGroupBox("Exploit Configuration")
        exploit_layout = QVBoxLayout(exploit_group)

        config_layout = QHBoxLayout()
        config_layout.addWidget(QLabel("Module:"))
        self._module_input = QLineEdit()
        self._module_input.setPlaceholderText("exploit/windows/smb/ms17_010_eternalblue")
        config_layout.addWidget(self._module_input)
        exploit_layout.addLayout(config_layout)

        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("RHOSTS:"))
        self._target_input = QLineEdit()
        self._target_input.setPlaceholderText("Target IP")
        self._target_input.setMaximumWidth(200)
        target_layout.addWidget(self._target_input)

        target_layout.addWidget(QLabel("RPORT:"))
        self._rport_input = QLineEdit()
        self._rport_input.setMaximumWidth(80)
        target_layout.addWidget(self._rport_input)

        target_layout.addWidget(QLabel("Payload:"))
        self._payload_combo = QComboBox()
        self._payload_combo.setEditable(True)
        self._payload_combo.addItems([
            "windows/x64/meterpreter/reverse_tcp",
            "windows/meterpreter/reverse_tcp",
            "linux/x64/meterpreter/reverse_tcp",
            "generic/shell_reverse_tcp",
        ])
        self._payload_combo.setMinimumWidth(300)
        target_layout.addWidget(self._payload_combo)
        target_layout.addStretch()
        exploit_layout.addLayout(target_layout)

        run_layout = QHBoxLayout()
        self._run_btn = QPushButton("Run Exploit")
        self._run_btn.setObjectName("dangerButton")
        self._run_btn.clicked.connect(self._on_run_exploit)
        run_layout.addWidget(self._run_btn)
        run_layout.addStretch()
        exploit_layout.addLayout(run_layout)

        splitter.addWidget(exploit_group)

        # === Sessions ===
        sessions_group = QGroupBox("Active Sessions")
        sessions_layout = QVBoxLayout(sessions_group)

        session_btn_layout = QHBoxLayout()
        self._refresh_sessions_btn = QPushButton("Refresh Sessions")
        self._refresh_sessions_btn.clicked.connect(self._on_refresh_sessions)
        session_btn_layout.addWidget(self._refresh_sessions_btn)
        session_btn_layout.addStretch()
        sessions_layout.addLayout(session_btn_layout)

        self._sessions_table = QTableWidget()
        self._sessions_table.setColumnCount(5)
        self._sessions_table.setHorizontalHeaderLabels([
            "ID", "Type", "Target", "Platform", "Info"
        ])
        self._sessions_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._sessions_table.setAlternatingRowColors(True)
        sessions_layout.addWidget(self._sessions_table)

        splitter.addWidget(sessions_group)
        splitter.setSizes([300, 200, 200])
        layout.addWidget(splitter, 1)

    def set_connected(self, connected: bool) -> None:
        self._connected = connected
        if connected:
            self._status_label.setText("Connected")
            self._status_label.setStyleSheet("color: #2ecc71; font-weight: bold;")
            self._connect_btn.setText("Disconnect")
        else:
            self._status_label.setText("Disconnected")
            self._status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
            self._connect_btn.setText("Connect to msfrpcd")

    def set_search_results(self, results: list[dict]) -> None:
        self._modules_table.setRowCount(len(results))
        for row, mod in enumerate(results):
            self._modules_table.setItem(row, 0, QTableWidgetItem(mod.get("type", "")))
            self._modules_table.setItem(row, 1, QTableWidgetItem(mod.get("name", "")))

            rank_item = QTableWidgetItem(mod.get("rank", ""))
            rank = mod.get("rank", "").lower()
            if rank == "excellent":
                rank_item.setForeground(QColor("#2ecc71"))
            elif rank == "good":
                rank_item.setForeground(QColor("#f39c12"))
            self._modules_table.setItem(row, 2, rank_item)

            self._modules_table.setItem(row, 3, QTableWidgetItem(mod.get("description", "")))

            use_btn = QPushButton("Use")
            use_btn.clicked.connect(lambda _, m=mod: self._use_module(m))
            self._modules_table.setCellWidget(row, 4, use_btn)

    def set_sessions(self, sessions: list[dict]) -> None:
        self._sessions_table.setRowCount(len(sessions))
        for row, sess in enumerate(sessions):
            self._sessions_table.setItem(row, 0, QTableWidgetItem(str(sess.get("id", ""))))
            self._sessions_table.setItem(row, 1, QTableWidgetItem(sess.get("type", "")))
            self._sessions_table.setItem(row, 2, QTableWidgetItem(sess.get("target", "")))
            self._sessions_table.setItem(row, 3, QTableWidgetItem(sess.get("platform", "")))
            self._sessions_table.setItem(row, 4, QTableWidgetItem(sess.get("info", "")))

    def set_exploit_target(self, ip: str, port: int = 0, module: str = "") -> None:
        """Pre-fill exploit config from external trigger."""
        self._target_input.setText(ip)
        if port:
            self._rport_input.setText(str(port))
        if module:
            self._module_input.setText(module)

    def _use_module(self, mod: dict) -> None:
        self._module_input.setText(mod.get("name", ""))

    def _on_connect(self) -> None:
        host = self._host_input.text()
        port = int(self._port_input.text() or "55553")
        password = self._pass_input.text()
        self.connect_requested.emit(host, port, password)

    def _on_search(self) -> None:
        # This will be connected to main window which calls MetasploitBridge
        pass

    def _on_run_exploit(self) -> None:
        module = self._module_input.text()
        target = self._target_input.text()
        if not module or not target:
            QMessageBox.warning(self, "Missing Fields", "Module and target IP are required.")
            return

        reply = QMessageBox.question(
            self, "Confirm Exploit Execution",
            f"Run {module} against {target}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            port = int(self._rport_input.text() or "0")
            payload = self._payload_combo.currentText()
            self.exploit_run.emit(module, target, port, payload, {})

    def _on_refresh_sessions(self) -> None:
        pass  # Connected in main_window
