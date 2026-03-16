"""Metasploit Bridge — communication with Metasploit Framework via MSFRPC."""

from __future__ import annotations

import time
from typing import Any, Optional

from core.logger import get_logger, get_audit_logger

log = get_logger("metasploit")


class MetasploitBridge:
    """Interface to Metasploit Framework via msfrpc."""

    def __init__(self, host: str = "", port: int = 0, password: str = "") -> None:
        self._client = None
        self._connected = False
        self._host = host or "127.0.0.1"
        self._port = port or 55553
        self._password = password or "msf"

    @property
    def is_connected(self) -> bool:
        return self._connected and self._client is not None

    def connect(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        password: str = "msf",
    ) -> bool:
        """Connect to msfrpcd."""
        self._host = host
        self._port = port
        self._password = password

        log.info(f"Connecting to Metasploit RPC at {host}:{port}")

        try:
            from pymsf import MsfRpcClient
            self._client = MsfRpcClient(password, server=host, port=port, ssl=True)
            self._connected = True
            log.info("Connected to Metasploit RPC")
            return True
        except ImportError:
            log.error("pymsf not installed — run: pip install pymsf")
            return False
        except Exception as e:
            log.error(f"Metasploit connection failed: {e}")
            self._connected = False
            return False

    def start_msfrpcd(self, password: str = "msf") -> bool:
        """Start msfrpcd daemon if not running."""
        import subprocess
        import shutil

        if not shutil.which("msfrpcd"):
            log.error("msfrpcd not found")
            return False

        log.info("Starting msfrpcd...")
        try:
            subprocess.Popen(
                ["msfrpcd", "-P", password, "-S", "-a", "127.0.0.1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(5)  # Wait for daemon to start
            return self.connect(password=password)
        except Exception as e:
            log.error(f"Failed to start msfrpcd: {e}")
            return False

    def search_exploits(self, query: str) -> list[dict]:
        """Search for Metasploit modules matching query."""
        if not self.is_connected:
            return []

        log.info(f"Searching Metasploit modules: {query}")
        try:
            modules = self._client.modules.search(query)
            results = []
            for mod in modules[:50]:  # Limit results
                results.append({
                    "type": mod.get("type", ""),
                    "name": mod.get("fullname", ""),
                    "rank": mod.get("rank", ""),
                    "description": mod.get("description", "")[:200],
                    "disclosure_date": mod.get("disclosure_date", ""),
                })
            log.info(f"Found {len(results)} modules for '{query}'")
            return results
        except Exception as e:
            log.error(f"Module search failed: {e}")
            return []

    def get_module_info(self, module_type: str, module_name: str) -> dict:
        """Get detailed info about a Metasploit module."""
        if not self.is_connected:
            return {}

        try:
            mod = self._client.modules.use(module_type, module_name)
            return {
                "name": module_name,
                "type": module_type,
                "description": mod.description,
                "authors": mod.authors,
                "references": mod.references,
                "options": {k: v for k, v in mod.options.items()},
                "required_options": mod.required,
                "rank": mod.rank,
            }
        except Exception as e:
            log.error(f"Failed to get module info: {e}")
            return {}

    def run_exploit(
        self,
        module_path: str,
        target_ip: str,
        target_port: int = 0,
        payload: str = "",
        options: dict[str, Any] | None = None,
    ) -> dict:
        """Run a Metasploit exploit module. Returns job info."""
        if not self.is_connected:
            return {"error": "Not connected to Metasploit"}

        audit = get_audit_logger()
        if audit:
            audit.log_exploit(module_path, f"{target_ip}:{target_port}", "started")

        log.info(f"Running exploit {module_path} against {target_ip}:{target_port}")

        try:
            # Parse module type and name
            parts = module_path.split("/", 1)
            if len(parts) == 2:
                mod_type = parts[0]
                mod_name = parts[1]
            else:
                mod_type = "exploit"
                mod_name = module_path

            exploit = self._client.modules.use(mod_type, mod_name)

            # Set target
            exploit["RHOSTS"] = target_ip
            if target_port:
                exploit["RPORT"] = target_port

            # Set payload
            if payload:
                exploit["PAYLOAD"] = payload

            # Set additional options
            if options:
                for key, value in options.items():
                    exploit[key] = value

            # Execute
            result = exploit.execute()

            job_id = result.get("job_id")
            log.info(f"Exploit launched: job_id={job_id}")

            if audit:
                audit.log_exploit(module_path, f"{target_ip}:{target_port}",
                                  f"job_id={job_id}")

            return {
                "job_id": job_id,
                "uuid": result.get("uuid", ""),
                "module": module_path,
                "target": f"{target_ip}:{target_port}",
                "status": "running",
            }

        except Exception as e:
            log.error(f"Exploit execution failed: {e}")
            if audit:
                audit.log_exploit(module_path, f"{target_ip}:{target_port}",
                                  f"FAILED: {e}")
            return {"error": str(e)}

    def get_sessions(self) -> list[dict]:
        """List active Metasploit sessions."""
        if not self.is_connected:
            return []

        try:
            sessions = self._client.sessions.list
            result = []
            for sid, info in sessions.items():
                result.append({
                    "id": sid,
                    "type": info.get("type", ""),
                    "tunnel": info.get("tunnel_local", ""),
                    "target": info.get("session_host", ""),
                    "platform": info.get("platform", ""),
                    "info": info.get("info", ""),
                })
            return result
        except Exception as e:
            log.error(f"Failed to list sessions: {e}")
            return []

    def get_jobs(self) -> dict:
        """List running Metasploit jobs."""
        if not self.is_connected:
            return {}
        try:
            return dict(self._client.jobs.list)
        except Exception as e:
            log.error(f"Failed to list jobs: {e}")
            return {}

    def run_auxiliary(
        self,
        module_path: str,
        options: dict[str, Any] | None = None,
    ) -> dict:
        """Run a Metasploit auxiliary module (scanner, etc.)."""
        if not self.is_connected:
            return {"error": "Not connected"}

        log.info(f"Running auxiliary module: {module_path}")
        try:
            mod = self._client.modules.use("auxiliary", module_path)

            if options:
                for key, value in options.items():
                    mod[key] = value

            result = mod.execute()
            return {
                "job_id": result.get("job_id"),
                "module": module_path,
                "status": "running",
            }
        except Exception as e:
            log.error(f"Auxiliary module failed: {e}")
            return {"error": str(e)}

    def suggest_exploit(self, cve_id: str) -> Optional[dict]:
        """Suggest the best Metasploit exploit for a given CVE."""
        if not self.is_connected:
            return None

        results = self.search_exploits(cve_id)
        exploits = [r for r in results if r["type"] == "exploit"]

        if not exploits:
            return None

        # Sort by rank
        rank_order = {"excellent": 0, "great": 1, "good": 2, "normal": 3,
                       "average": 4, "low": 5, "manual": 6}
        exploits.sort(key=lambda x: rank_order.get(x.get("rank", ""), 99))

        return exploits[0]

    def disconnect(self) -> None:
        """Disconnect from Metasploit RPC."""
        self._client = None
        self._connected = False
        log.info("Disconnected from Metasploit")
