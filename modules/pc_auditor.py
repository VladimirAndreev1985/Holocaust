"""PC Auditor — specialized security checks for Windows/Linux workstations and servers."""

from __future__ import annotations

import nmap

from core.logger import get_logger, get_audit_logger
from models.credential import Credential
from models.device import Device, DeviceType
from models.vulnerability import Exploit, Vulnerability, VulnSeverity, VulnSource

log = get_logger("pc_auditor")


# Known critical PC vulnerabilities
CRITICAL_PC_CHECKS = [
    {
        "name": "EternalBlue (MS17-010)",
        "script": "smb-vuln-ms17-010",
        "cve": "CVE-2017-0144",
        "cvss": 9.8,
        "ports": "445",
        "msf_module": "exploit/windows/smb/ms17_010_eternalblue",
        "os": "windows",
    },
    {
        "name": "BlueKeep (RDP)",
        "script": "rdp-vuln-ms12-020",
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "ports": "3389",
        "msf_module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "os": "windows",
    },
    {
        "name": "SMBGhost",
        "script": "smb-vuln-cve-2020-0796",
        "cve": "CVE-2020-0796",
        "cvss": 10.0,
        "ports": "445",
        "msf_module": "exploit/windows/smb/cve_2020_0796_smbghost",
        "os": "windows",
    },
    {
        "name": "PrintNightmare",
        "script": "",
        "cve": "CVE-2021-34527",
        "cvss": 8.8,
        "ports": "135,445",
        "msf_module": "exploit/windows/dcerpc/cve_2021_1675_printnightmare",
        "os": "windows",
    },
    {
        "name": "Log4Shell",
        "script": "log4shell",
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "ports": "8080,8443,9200",
        "msf_module": "",
        "os": "any",
    },
]


class PcAuditor:
    """Targeted security checks for PC/workstation/server systems."""

    def __init__(self) -> None:
        self._scanner = nmap.PortScanner()

    def audit_pc(self, device: Device) -> dict:
        """Run all PC-specific security checks."""
        audit = get_audit_logger()
        if audit:
            audit.log_action("pc_audit", device.ip,
                             f"os={device.os_name} type={device.device_type.value}")

        log.info(f"Starting PC audit for {device.ip} ({device.os_name})")

        result = {
            "smb_info": {},
            "rdp_info": {},
            "ssh_info": {},
            "shares": [],
            "vulnerabilities": [],
            "credentials": [],
        }

        # SMB checks
        if device.has_service("microsoft-ds") or 445 in device.open_ports:
            result["smb_info"] = self.check_smb(device)
            result["shares"] = self.enumerate_shares(device)

        # RDP checks
        if 3389 in device.open_ports:
            result["rdp_info"] = self.check_rdp(device)

        # SSH checks
        if 22 in device.open_ports:
            result["ssh_info"] = self.check_ssh(device)

        # Critical vulnerability checks
        vulns = self.check_critical_vulns(device)
        result["vulnerabilities"] = vulns

        # Default credential checks
        creds = self.check_default_credentials(device)
        result["credentials"] = creds

        # Update device
        for v in vulns:
            if v.cve_id and v.cve_id not in device.vulnerabilities:
                device.vulnerabilities.append(v.cve_id)
        device.update_risk_level()

        log.info(f"PC audit complete for {device.ip}: {len(vulns)} vulns found")
        return result

    def check_smb(self, device: Device) -> dict:
        """Check SMB configuration and security."""
        log.info(f"Checking SMB on {device.ip}")
        info = {"signing": "", "version": "", "os": "", "domain": ""}

        try:
            self._scanner.scan(
                hosts=device.ip,
                ports="445",
                arguments="--script=smb-os-discovery,smb-security-mode,smb2-security-mode -T4",
                timeout=60,
            )

            host_data = self._scanner[device.ip]
            scripts = {}
            if "tcp" in host_data and 445 in host_data["tcp"]:
                scripts = host_data["tcp"][445].get("script", {})

            if "smb-os-discovery" in scripts:
                output = scripts["smb-os-discovery"]
                info["os"] = output
                # Parse OS info
                import re
                os_match = re.search(r"OS:\s*(.+)", output)
                if os_match:
                    info["os"] = os_match.group(1).strip()
                domain_match = re.search(r"Domain name:\s*(.+)", output)
                if domain_match:
                    info["domain"] = domain_match.group(1).strip()

            if "smb-security-mode" in scripts:
                info["signing"] = scripts["smb-security-mode"]

            if "smb2-security-mode" in scripts:
                output = scripts["smb2-security-mode"]
                if "not required" in output.lower():
                    info["signing"] = "not required (vulnerable to relay)"

        except Exception as e:
            log.error(f"SMB check failed for {device.ip}: {e}")

        return info

    def enumerate_shares(self, device: Device) -> list[dict]:
        """Enumerate SMB shares."""
        log.info(f"Enumerating shares on {device.ip}")
        shares = []

        try:
            self._scanner.scan(
                hosts=device.ip,
                ports="445",
                arguments="--script=smb-enum-shares -T4",
                timeout=60,
            )

            host_data = self._scanner[device.ip]
            if "tcp" in host_data and 445 in host_data["tcp"]:
                scripts = host_data["tcp"][445].get("script", {})
                if "smb-enum-shares" in scripts:
                    output = scripts["smb-enum-shares"]
                    # Parse share names from output
                    import re
                    for match in re.finditer(r"\\\\[^\\]+\\(\S+)", output):
                        share_name = match.group(1)
                        shares.append({
                            "name": share_name,
                            "anonymous": "anonymous" in output.lower(),
                        })

        except Exception as e:
            log.error(f"Share enumeration failed for {device.ip}: {e}")

        return shares

    def check_rdp(self, device: Device) -> dict:
        """Check RDP configuration and vulnerabilities."""
        log.info(f"Checking RDP on {device.ip}")
        info = {"nla": True, "encryption": "", "version": ""}

        try:
            self._scanner.scan(
                hosts=device.ip,
                ports="3389",
                arguments="--script=rdp-enum-encryption,rdp-ntlm-info -T4",
                timeout=60,
            )

            host_data = self._scanner[device.ip]
            if "tcp" in host_data and 3389 in host_data["tcp"]:
                scripts = host_data["tcp"][3389].get("script", {})

                if "rdp-enum-encryption" in scripts:
                    output = scripts["rdp-enum-encryption"]
                    info["encryption"] = output
                    if "NONE" in output:
                        info["nla"] = False

                if "rdp-ntlm-info" in scripts:
                    info["version"] = scripts["rdp-ntlm-info"]

        except Exception as e:
            log.error(f"RDP check failed for {device.ip}: {e}")

        return info

    def check_ssh(self, device: Device) -> dict:
        """Check SSH configuration."""
        log.info(f"Checking SSH on {device.ip}")
        info = {"version": "", "auth_methods": "", "weak_keys": False}

        try:
            self._scanner.scan(
                hosts=device.ip,
                ports="22",
                arguments="--script=ssh2-enum-algos,ssh-auth-methods -T4",
                timeout=60,
            )

            host_data = self._scanner[device.ip]
            if "tcp" in host_data and 22 in host_data["tcp"]:
                port_info = host_data["tcp"][22]
                info["version"] = f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()

                scripts = port_info.get("script", {})
                if "ssh-auth-methods" in scripts:
                    info["auth_methods"] = scripts["ssh-auth-methods"]
                if "ssh2-enum-algos" in scripts:
                    algos = scripts["ssh2-enum-algos"]
                    weak_algos = ["arcfour", "des-cbc", "blowfish-cbc"]
                    if any(w in algos.lower() for w in weak_algos):
                        info["weak_keys"] = True

        except Exception as e:
            log.error(f"SSH check failed for {device.ip}: {e}")

        return info

    def check_critical_vulns(self, device: Device) -> list[Vulnerability]:
        """Run critical vulnerability checks (EternalBlue, BlueKeep, etc.)."""
        vulns = []
        os_lower = device.os_name.lower()

        for check in CRITICAL_PC_CHECKS:
            # Skip OS-specific checks
            if check["os"] == "windows" and "windows" not in os_lower and os_lower:
                continue

            # Skip if required ports not open
            required_ports = {int(p) for p in check["ports"].split(",")}
            if device.open_ports and not required_ports & set(device.open_ports):
                continue

            if not check["script"]:
                continue

            log.info(f"Checking {check['name']} on {device.ip}")

            try:
                self._scanner.scan(
                    hosts=device.ip,
                    ports=check["ports"],
                    arguments=f"--script={check['script']} -T4",
                    timeout=60,
                )

                host_data = self._scanner[device.ip]
                for proto in host_data.all_protocols():
                    for port in host_data[proto].keys():
                        scripts = host_data[proto][port].get("script", {})
                        for script_name, output in scripts.items():
                            if "VULNERABLE" in output.upper():
                                vuln = Vulnerability(
                                    cve_id=check["cve"],
                                    title=check["name"],
                                    severity=VulnSeverity.from_cvss(check["cvss"]),
                                    cvss_score=check["cvss"],
                                    description=output[:300],
                                    source=VulnSource.NMAP_NSE,
                                    affected_port=port,
                                    host_ip=device.ip,
                                    is_confirmed=True,
                                    is_exploitable=True,
                                )
                                if check["msf_module"]:
                                    vuln.exploits.append(Exploit(
                                        name=check["name"],
                                        source="metasploit",
                                        module_path=check["msf_module"],
                                        reliability="excellent",
                                    ))
                                vulns.append(vuln)

                                audit = get_audit_logger()
                                if audit:
                                    audit.log_finding(
                                        check["cve"], device.ip, "CRITICAL"
                                    )

            except Exception as e:
                log.error(f"Check {check['name']} failed for {device.ip}: {e}")

        return vulns

    def check_default_credentials(self, device: Device) -> list[Credential]:
        """Check common default credentials for PC services."""
        creds = []

        # SMB anonymous access
        if 445 in device.open_ports:
            creds.append(Credential(
                host_ip=device.ip,
                service="smb",
                port=445,
                username="",
                password="",
                is_default=True,
                source="anonymous_check",
            ))

        # RDP (just report it as open, don't brute)
        if 3389 in device.open_ports:
            creds.append(Credential(
                host_ip=device.ip,
                service="rdp",
                port=3389,
                username="administrator",
                password="",
                is_default=True,
                source="default_db",
            ))

        return creds
