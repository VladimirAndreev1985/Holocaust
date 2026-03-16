from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Credential:
    host_ip: str
    service: str  # e.g. "http", "rtsp", "smb", "ssh"
    port: int
    username: str
    password: str
    is_default: bool = True
    is_valid: bool = False
    tested_at: datetime | None = None
    source: str = ""  # e.g. "default_db", "brute_force"

    @property
    def display(self) -> str:
        status = "VALID" if self.is_valid else "untested"
        return f"{self.username}:{self.password} [{status}]"

    @property
    def url(self) -> str:
        return f"{self.service}://{self.username}:{self.password}@{self.host_ip}:{self.port}"
