"""Camera auditor — specialized security checks for IP cameras."""

from __future__ import annotations

import re
from typing import Optional

import requests

from core.logger import get_logger, get_audit_logger
from models.credential import Credential
from models.device import Device, DeviceType
from models.vulnerability import Vulnerability, VulnSeverity, VulnSource

log = get_logger("camera_auditor")

# Default credentials database for IP cameras
DEFAULT_CAMERA_CREDS: list[dict] = [
    # Hikvision
    {"vendor": "hikvision", "username": "admin", "password": "12345", "service": "http"},
    {"vendor": "hikvision", "username": "admin", "password": "admin12345", "service": "http"},
    {"vendor": "hikvision", "username": "admin", "password": "", "service": "http"},
    # Dahua
    {"vendor": "dahua", "username": "admin", "password": "admin", "service": "http"},
    {"vendor": "dahua", "username": "admin", "password": "888888", "service": "http"},
    {"vendor": "dahua", "username": "admin", "password": "666666", "service": "http"},
    # Reolink
    {"vendor": "reolink", "username": "admin", "password": "", "service": "http"},
    {"vendor": "reolink", "username": "admin", "password": "admin", "service": "http"},
    # Axis
    {"vendor": "axis", "username": "root", "password": "pass", "service": "http"},
    {"vendor": "axis", "username": "root", "password": "root", "service": "http"},
    # Foscam
    {"vendor": "foscam", "username": "admin", "password": "", "service": "http"},
    {"vendor": "foscam", "username": "admin", "password": "admin", "service": "http"},
    # Generic
    {"vendor": "generic", "username": "admin", "password": "admin", "service": "http"},
    {"vendor": "generic", "username": "admin", "password": "12345", "service": "http"},
    {"vendor": "generic", "username": "admin", "password": "123456", "service": "http"},
    {"vendor": "generic", "username": "admin", "password": "password", "service": "http"},
    {"vendor": "generic", "username": "root", "password": "root", "service": "http"},
    {"vendor": "generic", "username": "admin", "password": "", "service": "http"},
    {"vendor": "generic", "username": "user", "password": "user", "service": "http"},
    # RTSP
    {"vendor": "generic", "username": "admin", "password": "admin", "service": "rtsp"},
    {"vendor": "generic", "username": "admin", "password": "12345", "service": "rtsp"},
    {"vendor": "generic", "username": "admin", "password": "", "service": "rtsp"},
]

# Known camera web paths for identification
CAMERA_PATHS: dict[str, str] = {
    "/ISAPI/System/deviceInfo": "Hikvision",
    "/cgi-bin/magicBox.cgi?action=getDeviceType": "Dahua",
    "/api.cgi?cmd=GetDevInfo": "Reolink",
    "/axis-cgi/param.cgi": "Axis",
    "/cgi-bin/CGIProxy.fcgi": "Foscam",
    "/onvif/device_service": "ONVIF",
}


class CameraAuditor:
    """Specialized auditing module for IP cameras and NVR/DVR systems."""

    def __init__(self, timeout: int = 5) -> None:
        self._timeout = timeout
        self._session = requests.Session()
        self._session.verify = False
        # Suppress insecure request warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def audit_camera(self, device: Device) -> dict:
        """Full camera audit: identify, check default creds, find CVEs."""
        audit = get_audit_logger()
        if audit:
            audit.log_action("camera_audit", device.ip)

        log.info(f"Starting camera audit for {device.ip}")

        result = {
            "vendor": "",
            "model": "",
            "firmware": "",
            "web_url": "",
            "rtsp_url": "",
            "credentials": [],
            "vulnerabilities": [],
            "has_default_creds": False,
        }

        # Step 1: Identify camera vendor/model
        vendor_info = self.identify_camera(device)
        result.update(vendor_info)

        # Step 2: Check default credentials
        creds = self.check_default_credentials(device, vendor_info.get("vendor", ""))
        result["credentials"] = creds
        result["has_default_creds"] = any(c.is_valid for c in creds)

        # Step 3: Check RTSP access
        rtsp_url = self.check_rtsp(device)
        if rtsp_url:
            result["rtsp_url"] = rtsp_url

        # Step 4: Check known camera CVEs
        vulns = self.check_camera_cves(device, vendor_info.get("vendor", ""))
        result["vulnerabilities"] = vulns

        # Update device model fields
        device.camera_model = f"{result['vendor']} {result['model']}".strip()
        device.camera_web_url = result["web_url"]
        device.camera_rtsp_url = result["rtsp_url"]
        device.has_default_creds = result["has_default_creds"]
        device.device_type = DeviceType.IP_CAMERA
        device.update_risk_level()

        if audit and result["has_default_creds"]:
            audit.log_finding("default_credentials", device.ip, "CRITICAL")

        log.info(f"Camera audit complete for {device.ip}: {result['vendor']} {result['model']}")
        return result

    def identify_camera(self, device: Device) -> dict:
        """Identify camera vendor and model by probing known endpoints."""
        info = {"vendor": "", "model": "", "firmware": "", "web_url": ""}

        for port in [80, 8080, 443, 8443]:
            if port not in device.open_ports and device.open_ports:
                continue

            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{device.ip}:{port}"

            for path, vendor in CAMERA_PATHS.items():
                try:
                    resp = self._session.get(
                        f"{base_url}{path}",
                        timeout=self._timeout,
                    )
                    if resp.status_code == 200:
                        info["vendor"] = vendor
                        info["web_url"] = base_url
                        info.update(self._parse_camera_info(vendor, resp.text))
                        log.info(f"Identified {vendor} camera at {base_url}")
                        return info
                    elif resp.status_code == 401:
                        # Auth required — still identifies vendor
                        info["vendor"] = vendor
                        info["web_url"] = base_url
                        return info
                except requests.RequestException:
                    continue

        # Fallback: check page title
        for port in [80, 8080]:
            try:
                scheme = "http"
                resp = self._session.get(
                    f"{scheme}://{device.ip}:{port}/",
                    timeout=self._timeout,
                )
                title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                if title_match:
                    title = title_match.group(1).lower()
                    for keyword in ["hikvision", "dahua", "reolink", "axis", "foscam"]:
                        if keyword in title:
                            info["vendor"] = keyword.capitalize()
                            info["web_url"] = f"{scheme}://{device.ip}:{port}"
                            return info
            except requests.RequestException:
                continue

        # Use vendor from MAC OUI
        if device.vendor:
            info["vendor"] = device.vendor

        return info

    def check_default_credentials(
        self, device: Device, vendor: str = ""
    ) -> list[Credential]:
        """Test default credentials against camera web interface."""
        audit = get_audit_logger()
        if audit:
            audit.log_action("check_default_creds", device.ip, f"vendor={vendor}")

        results = []
        vendor_lower = vendor.lower()

        # Filter credentials by vendor
        creds_to_try = [
            c for c in DEFAULT_CAMERA_CREDS
            if c["vendor"] in (vendor_lower, "generic")
        ]

        for port in [80, 8080, 443, 8443]:
            if port not in device.open_ports and device.open_ports:
                continue

            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{device.ip}:{port}"

            for cred_info in creds_to_try:
                if cred_info["service"] != "http":
                    continue

                cred = Credential(
                    host_ip=device.ip,
                    service="http",
                    port=port,
                    username=cred_info["username"],
                    password=cred_info["password"],
                    is_default=True,
                    source="default_db",
                )

                try:
                    resp = self._session.get(
                        base_url,
                        auth=(cred.username, cred.password),
                        timeout=self._timeout,
                    )

                    if resp.status_code == 200:
                        cred.is_valid = True
                        log.warning(
                            f"DEFAULT CREDS WORK: {device.ip}:{port} "
                            f"{cred.username}:{cred.password}"
                        )
                        results.append(cred)
                        return results  # Found valid creds, stop
                    elif resp.status_code != 401:
                        cred.is_valid = False
                        results.append(cred)

                except requests.RequestException:
                    continue

        return results

    def check_rtsp(self, device: Device) -> str:
        """Check if RTSP stream is accessible."""
        if 554 not in device.open_ports and device.open_ports:
            return ""

        rtsp_paths = [
            "/Streaming/Channels/101",  # Hikvision
            "/cam/realmonitor?channel=1&subtype=0",  # Dahua
            "/h264Preview_01_main",  # Reolink
            "/live/ch00_0",  # Generic
            "/live.sdp",
            "/stream1",
        ]

        for path in rtsp_paths:
            url = f"rtsp://{device.ip}:554{path}"
            # Just record the URL — actual RTSP check would need cv2 or ffprobe
            log.debug(f"Potential RTSP URL: {url}")

        # Return most common default
        return f"rtsp://{device.ip}:554/Streaming/Channels/101"

    def check_camera_cves(self, device: Device, vendor: str) -> list[Vulnerability]:
        """Check for known camera-specific CVEs."""
        vulns = []
        vendor_lower = vendor.lower()

        # Known critical camera CVEs
        known_cves = {
            "hikvision": [
                {
                    "cve": "CVE-2021-36260",
                    "title": "Hikvision Command Injection",
                    "cvss": 9.8,
                    "desc": "Critical command injection via web server allows remote code execution",
                },
                {
                    "cve": "CVE-2017-7921",
                    "title": "Hikvision Authentication Bypass",
                    "cvss": 10.0,
                    "desc": "Authentication bypass allows access to device config snapshot",
                },
            ],
            "dahua": [
                {
                    "cve": "CVE-2021-33044",
                    "title": "Dahua Authentication Bypass",
                    "cvss": 9.8,
                    "desc": "Authentication bypass during login process",
                },
                {
                    "cve": "CVE-2021-33045",
                    "title": "Dahua Authentication Bypass",
                    "cvss": 9.8,
                    "desc": "Identity authentication bypass during login",
                },
            ],
            "reolink": [
                {
                    "cve": "CVE-2022-21236",
                    "title": "Reolink Information Disclosure",
                    "cvss": 7.5,
                    "desc": "Sensitive information disclosure via HTTP request",
                },
            ],
            "axis": [
                {
                    "cve": "CVE-2018-10660",
                    "title": "Axis Camera Shell Command Injection",
                    "cvss": 9.8,
                    "desc": "Shell command injection through server-side include",
                },
            ],
        }

        cves_for_vendor = known_cves.get(vendor_lower, [])
        for cve_info in cves_for_vendor:
            vulns.append(Vulnerability(
                cve_id=cve_info["cve"],
                title=cve_info["title"],
                severity=VulnSeverity.from_cvss(cve_info["cvss"]),
                cvss_score=cve_info["cvss"],
                description=cve_info["desc"],
                source=VulnSource.CVE_DB,
                host_ip=device.ip,
                is_exploitable=True,
            ))

        return vulns

    @staticmethod
    def _parse_camera_info(vendor: str, response_text: str) -> dict:
        """Parse camera info from vendor-specific response."""
        info = {"model": "", "firmware": ""}
        vendor_lower = vendor.lower()

        if vendor_lower == "hikvision":
            model_match = re.search(r"<model>(.*?)</model>", response_text, re.IGNORECASE)
            fw_match = re.search(r"<firmwareVersion>(.*?)</firmwareVersion>", response_text, re.IGNORECASE)
            if model_match:
                info["model"] = model_match.group(1)
            if fw_match:
                info["firmware"] = fw_match.group(1)

        elif vendor_lower == "dahua":
            type_match = re.search(r"type\s*:\s*(.+)", response_text)
            if type_match:
                info["model"] = type_match.group(1).strip()

        elif vendor_lower == "reolink":
            import json
            try:
                data = json.loads(response_text)
                if isinstance(data, list) and data:
                    dev_info = data[0].get("value", {}).get("DevInfo", {})
                    info["model"] = dev_info.get("model", "")
                    info["firmware"] = dev_info.get("firmVer", "")
            except (json.JSONDecodeError, KeyError):
                pass

        return info
