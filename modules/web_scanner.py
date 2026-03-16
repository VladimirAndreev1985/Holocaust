"""Web Vulnerability Scanner — SQLi, XSS, directory brute-force, header analysis."""

from __future__ import annotations

import re
import socket
import ssl
import urllib.parse
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.logger import get_logger, get_audit_logger
from models.device import Device
from models.vulnerability import Vulnerability, VulnSeverity, VulnSource, Exploit

log = get_logger("web_scanner")

# Common SQL injection test payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "\" OR \"1\"=\"1\"--",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT SLEEP(5)--",
]

# SQL error signatures
SQLI_ERRORS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySqlException",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"Warning.*\Wpg_",
    r"org\.postgresql\.util\.PSQLException",
    r"Microsoft SQL Native Client error",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"ORA-\d{5}",
    r"Oracle error",
    r"SQLite/JQS",
    r"SQLiteException",
    r"sqlite3\.OperationalError",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
]

# XSS test payloads
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]

# Common interesting paths
COMMON_PATHS = [
    "/admin", "/login", "/wp-admin", "/wp-login.php",
    "/administrator", "/phpmyadmin", "/phpinfo.php",
    "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
    "/api", "/api/v1", "/swagger", "/swagger-ui.html",
    "/server-status", "/server-info", "/.htaccess",
    "/backup", "/backup.sql", "/dump.sql", "/db.sql",
    "/config.php", "/config.yml", "/config.json",
    "/wp-config.php.bak", "/web.config",
    "/.DS_Store", "/crossdomain.xml",
    "/actuator", "/actuator/health", "/actuator/env",
    "/console", "/debug", "/trace",
]

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — no HTTPS enforcement",
    "X-Content-Type-Options": "X-Content-Type-Options missing — MIME sniffing possible",
    "X-Frame-Options": "X-Frame-Options missing — clickjacking possible",
    "Content-Security-Policy": "CSP missing — XSS risk increased",
    "X-XSS-Protection": "X-XSS-Protection missing",
    "Referrer-Policy": "Referrer-Policy missing — may leak URLs",
    "Permissions-Policy": "Permissions-Policy missing",
}


class WebScanner:
    """Web application vulnerability scanner.

    Checks for:
      - SQL injection (error-based, time-based)
      - Cross-site scripting (reflected XSS)
      - Directory/file enumeration
      - Security header analysis
      - SSL/TLS configuration issues
      - Information disclosure
      - Server misconfigurations
    """

    def __init__(self, timeout: int = 10, threads: int = 5) -> None:
        self._timeout = timeout
        self._threads = threads
        self._session = None

    def _get_session(self):
        """Lazy-init requests session."""
        if self._session is None:
            try:
                import requests
                self._session = requests.Session()
                self._session.headers.update({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                })
                self._session.verify = False
                # Suppress InsecureRequestWarning
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                log.error("requests library not installed — pip install requests")
                return None
        return self._session

    def scan_target(self, target: str, port: int = 80,
                    use_ssl: bool = False) -> list[Vulnerability]:
        """Full web vulnerability scan on a target.

        Args:
            target: IP or hostname
            port: Web server port
            use_ssl: Use HTTPS

        Returns:
            List of discovered vulnerabilities
        """
        audit = get_audit_logger()
        if audit:
            audit.log_action("web_scan", target, f"port={port}, ssl={use_ssl}")

        scheme = "https" if use_ssl or port == 443 else "http"
        base_url = f"{scheme}://{target}:{port}"

        vulns: list[Vulnerability] = []

        log.info(f"Web scan starting: {base_url}")

        # 1. Check security headers
        header_vulns = self._check_headers(base_url, target, port)
        vulns.extend(header_vulns)

        # 2. Directory enumeration
        dir_vulns = self._enumerate_dirs(base_url, target, port)
        vulns.extend(dir_vulns)

        # 3. SSL/TLS check
        if use_ssl or port == 443:
            ssl_vulns = self._check_ssl(target, port)
            vulns.extend(ssl_vulns)

        # 4. Server info disclosure
        info_vulns = self._check_info_disclosure(base_url, target, port)
        vulns.extend(info_vulns)

        log.info(f"Web scan complete: {base_url} — {len(vulns)} issues found")
        return vulns

    def scan_device(self, device: Device) -> list[Vulnerability]:
        """Scan all HTTP/HTTPS services on a device."""
        vulns = []
        web_ports = []

        for service in device.services:
            if service.name in ("http", "https", "http-proxy", "http-alt"):
                use_ssl = service.name == "https" or service.port == 443
                web_ports.append((service.port, use_ssl))

        # Also check common web ports if not in services
        for port in [80, 443, 8080, 8443, 8000, 8888]:
            if port not in [p for p, _ in web_ports]:
                if self._port_open(device.ip, port):
                    use_ssl = port in (443, 8443)
                    web_ports.append((port, use_ssl))

        for port, use_ssl in web_ports:
            try:
                port_vulns = self.scan_target(device.ip, port, use_ssl)
                vulns.extend(port_vulns)
            except Exception as e:
                log.error(f"Web scan failed for {device.ip}:{port}: {e}")

        return vulns

    def check_sqli(self, url: str, params: dict,
                   target_ip: str = "") -> list[Vulnerability]:
        """Test URL parameters for SQL injection.

        Args:
            url: Target URL
            params: GET parameters to test
            target_ip: For vulnerability reporting
        """
        session = self._get_session()
        if not session:
            return []

        vulns = []

        for param_name, param_value in params.items():
            for payload in SQLI_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    resp = session.get(url, params=test_params, timeout=self._timeout)
                    body = resp.text

                    for pattern in SQLI_ERRORS:
                        if re.search(pattern, body, re.IGNORECASE):
                            vuln = Vulnerability(
                                cve_id="",
                                title=f"SQL Injection in parameter '{param_name}'",
                                severity=VulnSeverity.CRITICAL,
                                cvss_score=9.8,
                                description=(
                                    f"Error-based SQL injection found in parameter "
                                    f"'{param_name}' at {url}.\n"
                                    f"Payload: {payload}\n"
                                    f"Error pattern: {pattern}"
                                ),
                                source=VulnSource.MANUAL,
                                affected_service="http",
                                affected_port=self._port_from_url(url),
                                host_ip=target_ip,
                                exploits=[Exploit(
                                    name="sqlmap",
                                    source="sqlmap",
                                    module_path=f"sqlmap -u '{url}?{param_name}={payload}'",
                                    reliability="excellent",
                                    description="Automated SQL injection exploitation",
                                )],
                            )
                            vulns.append(vuln)
                            log.warning(f"SQLi found: {url} param={param_name}")
                            break  # Found vuln for this param, skip other payloads

                except Exception:
                    continue

            # Time-based blind SQLi check
            try:
                test_params = params.copy()
                test_params[param_name] = "1; SELECT SLEEP(5)--"
                import time
                start = time.time()
                session.get(url, params=test_params, timeout=self._timeout + 6)
                elapsed = time.time() - start

                if elapsed >= 5:
                    vuln = Vulnerability(
                        cve_id="",
                        title=f"Blind SQL Injection (time-based) in '{param_name}'",
                        severity=VulnSeverity.CRITICAL,
                        cvss_score=9.8,
                        description=(
                            f"Time-based blind SQL injection in parameter "
                            f"'{param_name}' at {url}. "
                            f"Response delayed by {elapsed:.1f}s."
                        ),
                        source=VulnSource.MANUAL,
                        affected_service="http",
                        affected_port=self._port_from_url(url),
                        host_ip=target_ip,
                    )
                    vulns.append(vuln)
            except Exception:
                pass

        return vulns

    def check_xss(self, url: str, params: dict,
                  target_ip: str = "") -> list[Vulnerability]:
        """Test URL parameters for reflected XSS."""
        session = self._get_session()
        if not session:
            return []

        vulns = []

        for param_name in params:
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param_name] = payload

                try:
                    resp = session.get(url, params=test_params, timeout=self._timeout)

                    if payload in resp.text:
                        vuln = Vulnerability(
                            cve_id="",
                            title=f"Reflected XSS in parameter '{param_name}'",
                            severity=VulnSeverity.HIGH,
                            cvss_score=6.1,
                            description=(
                                f"Reflected cross-site scripting in parameter "
                                f"'{param_name}' at {url}.\n"
                                f"Payload reflected in response: {payload}"
                            ),
                            source=VulnSource.MANUAL,
                            affected_service="http",
                            affected_port=self._port_from_url(url),
                            host_ip=target_ip,
                        )
                        vulns.append(vuln)
                        log.warning(f"XSS found: {url} param={param_name}")
                        break

                except Exception:
                    continue

        return vulns

    def _check_headers(self, base_url: str, target: str, port: int) -> list[Vulnerability]:
        """Check for missing security headers."""
        session = self._get_session()
        if not session:
            return []

        vulns = []
        try:
            resp = session.get(base_url, timeout=self._timeout, allow_redirects=True)
            headers = resp.headers

            missing = []
            for header, desc in SECURITY_HEADERS.items():
                if header not in headers:
                    missing.append(f"• {desc}")

            if missing:
                vuln = Vulnerability(
                    cve_id="",
                    title="Missing Security Headers",
                    severity=VulnSeverity.LOW,
                    cvss_score=3.0,
                    description=(
                        f"The web server at {base_url} is missing "
                        f"{len(missing)} security headers:\n" + "\n".join(missing)
                    ),
                    source=VulnSource.MANUAL,
                    affected_service="http",
                    affected_port=port,
                    host_ip=target,
                )
                vulns.append(vuln)

        except Exception as e:
            log.debug(f"Header check failed for {base_url}: {e}")

        return vulns

    def _enumerate_dirs(self, base_url: str, target: str, port: int) -> list[Vulnerability]:
        """Check for common sensitive directories/files."""
        session = self._get_session()
        if not session:
            return []

        vulns = []
        found_paths = []

        def check_path(path: str) -> Optional[tuple[str, int]]:
            try:
                url = f"{base_url}{path}"
                resp = session.get(url, timeout=self._timeout, allow_redirects=False)
                if resp.status_code in (200, 301, 302, 403):
                    return path, resp.status_code
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self._threads) as pool:
            futures = {pool.submit(check_path, path): path for path in COMMON_PATHS}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_paths.append(result)

        # Categorize findings
        sensitive = []
        info = []
        for path, status in found_paths:
            if any(x in path for x in [".env", ".git", "backup", ".sql", "config",
                                        ".bak", ".htaccess", "web.config"]):
                sensitive.append(f"{path} (HTTP {status})")
            else:
                info.append(f"{path} (HTTP {status})")

        if sensitive:
            vuln = Vulnerability(
                cve_id="",
                title="Sensitive Files/Directories Exposed",
                severity=VulnSeverity.HIGH,
                cvss_score=7.5,
                description=(
                    f"Sensitive files or directories found on {base_url}:\n" +
                    "\n".join(f"• {p}" for p in sensitive)
                ),
                source=VulnSource.MANUAL,
                affected_service="http",
                affected_port=port,
                host_ip=target,
            )
            vulns.append(vuln)

        if info:
            vuln = Vulnerability(
                cve_id="",
                title="Interesting Directories Found",
                severity=VulnSeverity.INFO,
                cvss_score=0.0,
                description=(
                    f"Accessible paths on {base_url}:\n" +
                    "\n".join(f"• {p}" for p in info)
                ),
                source=VulnSource.MANUAL,
                affected_service="http",
                affected_port=port,
                host_ip=target,
            )
            vulns.append(vuln)

        return vulns

    def _check_ssl(self, target: str, port: int) -> list[Vulnerability]:
        """Check SSL/TLS configuration."""
        vulns = []
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=self._timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    issues = []

                    # Check protocol version
                    if protocol in ("TLSv1", "TLSv1.1"):
                        issues.append(f"Deprecated protocol: {protocol}")

                    # Check cipher strength
                    if cipher and cipher[2] < 128:
                        issues.append(f"Weak cipher: {cipher[0]} ({cipher[2]}-bit)")

                    # Try to check for self-signed / expired
                    try:
                        ctx2 = ssl.create_default_context()
                        with socket.create_connection((target, port), timeout=self._timeout) as s2:
                            with ctx2.wrap_socket(s2, server_hostname=target) as ss2:
                                pass  # If this succeeds, cert is valid
                    except ssl.SSLCertVerificationError as e:
                        if "self-signed" in str(e).lower() or "self signed" in str(e).lower():
                            issues.append("Self-signed certificate")
                        elif "expired" in str(e).lower():
                            issues.append("Expired certificate")
                        else:
                            issues.append(f"Certificate error: {e}")

                    if issues:
                        vuln = Vulnerability(
                            cve_id="",
                            title="SSL/TLS Configuration Issues",
                            severity=VulnSeverity.MEDIUM,
                            cvss_score=5.3,
                            description=(
                                f"SSL/TLS issues on {target}:{port}:\n" +
                                "\n".join(f"• {i}" for i in issues)
                            ),
                            source=VulnSource.MANUAL,
                            affected_service="https",
                            affected_port=port,
                            host_ip=target,
                        )
                        vulns.append(vuln)

        except Exception as e:
            log.debug(f"SSL check failed for {target}:{port}: {e}")

        return vulns

    def _check_info_disclosure(self, base_url: str, target: str, port: int) -> list[Vulnerability]:
        """Check for server information disclosure."""
        session = self._get_session()
        if not session:
            return []

        vulns = []
        try:
            resp = session.get(base_url, timeout=self._timeout)
            disclosures = []

            # Server header
            server = resp.headers.get("Server", "")
            if server and any(v in server.lower() for v in ["apache/", "nginx/", "iis/", "lighttpd/"]):
                disclosures.append(f"Server version: {server}")

            # X-Powered-By
            powered = resp.headers.get("X-Powered-By", "")
            if powered:
                disclosures.append(f"X-Powered-By: {powered}")

            # X-AspNet-Version
            aspnet = resp.headers.get("X-AspNet-Version", "")
            if aspnet:
                disclosures.append(f"ASP.NET version: {aspnet}")

            if disclosures:
                vuln = Vulnerability(
                    cve_id="",
                    title="Server Information Disclosure",
                    severity=VulnSeverity.LOW,
                    cvss_score=2.0,
                    description=(
                        f"Server at {base_url} discloses version information:\n" +
                        "\n".join(f"• {d}" for d in disclosures)
                    ),
                    source=VulnSource.MANUAL,
                    affected_service="http",
                    affected_port=port,
                    host_ip=target,
                )
                vulns.append(vuln)

        except Exception:
            pass

        return vulns

    @staticmethod
    def _port_from_url(url: str) -> int:
        parsed = urllib.parse.urlparse(url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80

    @staticmethod
    def _port_open(host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False
