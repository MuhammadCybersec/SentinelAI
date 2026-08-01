"""
===========================================================
Project : Sentinel AI
Module  : Recon Agent
File ID : AGENT-RECON-001
Version : 0.1.0
===========================================================
"""

import concurrent.futures
import socket
from urllib.parse import urlparse

import dns.resolver
import requests

from app.modules.recon.api_discovery import discover_api
from app.modules.recon.http_methods import detect_http_methods
from app.modules.recon.javascript import discover_javascript
from app.modules.recon.js_endpoints import discover_js_endpoints
from app.modules.recon.js_secrets import discover_js_secrets
from app.modules.recon.waf import detect_waf


class ReconAgent:
    """Performs basic reconnaissance on a target."""

    def scan_ports(self, hostname: str) -> list:
        common_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            111,
            135,
            139,
            143,
            443,
            445,
            993,
            995,
            1723,
            3306,
            3389,
            5900,
            8080,
        ]
        open_ports = []

        def scan_port(port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((hostname, port))
                if result == 0:
                    open_ports.append(port)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(scan_port, common_ports)

        return sorted(open_ports)

    def dns_lookup(self, hostname: str) -> dict:
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(hostname, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except Exception:
                records[record_type] = []
        return records

    def run(self, target: str) -> dict:
        report = {"target": target, "status": None, "server": None, "title": None}
        fake_status = 404
        fake_length = 0

        try:
            response = requests.get(target, timeout=10, allow_redirects=True)

            # Soft-404 Baseline
            try:
                fake_response = requests.get(
                    target.rstrip("/") + "/thispagedoesnotexist",
                    timeout=10,
                    allow_redirects=True,
                )
                fake_status = fake_response.status_code
                fake_length = len(fake_response.text)
            except Exception:
                fake_status = 404
                fake_length = 0

            report["headers"] = dict(response.headers)
            report["waf"] = detect_waf(target)
            report["http_methods"] = detect_http_methods(target)
            report["javascript_files"] = discover_javascript(target)
            report["javascript_endpoints"] = discover_js_endpoints(
                report["javascript_files"]
            )
            report["javascript_secrets"] = discover_js_secrets(
                report["javascript_files"]
            )
            report["api_discovery"] = discover_api(target, fake_status, fake_length)

            report["redirected"] = len(response.history) > 0
            report["final_url"] = response.url

            hostname = urlparse(response.url).hostname
            if hostname:
                report["hostname"] = hostname
                report["dns_records"] = self.dns_lookup(hostname)

                # Subdomains
                subdomains = []
                if hostname:
                    domain = hostname
                    domain = domain.removeprefix("www.")
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=20
                    ) as executor:
                        futures = [
                            executor.submit(discover_subdomain, domain, sub)
                            for sub in SUBDOMAIN_WORDLIST
                        ]
                        for future in concurrent.futures.as_completed(futures):
                            result = future.result()
                            if result:
                                subdomains.append(result)
                report["subdomains"] = sorted(list(set(subdomains)))

                # Sensitive Files
                sensitive_files = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [
                        executor.submit(
                            scan_sensitive_file,
                            target,
                            filename,
                            fake_status,
                            fake_length,
                        )
                        for filename in SENSITIVE_FILES
                    ]
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        if result:
                            sensitive_files.append(result)
                report["sensitive_files"] = sorted(
                    sensitive_files, key=lambda x: x["file"]
                )

                report["open_ports"] = self.scan_ports(hostname)
                try:
                    report["ip_address"] = socket.gethostbyname(hostname)
                except Exception:
                    report["ip_address"] = "Unknown"
            else:
                report["hostname"] = "Unknown"
                report["ip_address"] = "Unknown"

            # Security Headers
            security_headers = {}
            important_headers = [
                "Server",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            for header in important_headers:
                security_headers[header] = response.headers.get(header, "Not Found")
            report["security_headers"] = security_headers

            # Technology Detection
            technologies = []
            server = response.headers.get("Server", "").lower()
            powered = response.headers.get("X-Powered-By", "").lower()
            html = response.text.lower()

            if "nginx" in server:
                technologies.append("Nginx")
            if "apache" in server:
                technologies.append("Apache")
            if "cloudflare" in server:
                technologies.append("Cloudflare")
            if "express" in powered:
                technologies.append("Express.js")
            if "asp.net" in powered:
                technologies.append("ASP.NET")
            if "laravel" in html:
                technologies.append("Laravel")
            if "wp-content" in html:
                technologies.append("WordPress")
            if "__next" in html or "_next/static" in html:
                technologies.append("Next.js")
            if "react" in html:
                technologies.append("React")
            if "vue" in html:
                technologies.append("Vue.js")
            if "angular" in html:
                technologies.append("Angular")
            report["technologies"] = sorted(list(set(technologies)))

            report["status"] = response.status_code
            report["server"] = response.headers.get("Server", "Unknown")

            if "<title>" in html:
                start = html.find("<title>") + 7
                end = html.find("</title>")
                report["title"] = response.text[start:end].strip()

        except Exception as e:
            report["error"] = str(e)

        # robots.txt
        try:
            robots = requests.get(target.rstrip("/") + "/robots.txt", timeout=5)
            report["robots.txt"] = robots.status_code == 200
        except Exception:
            report["robots.txt"] = False

        # security.txt
        try:
            security = requests.get(
                target.rstrip("/") + "/.well-known/security.txt", timeout=5
            )
            report["security.txt"] = security.status_code == 200
        except Exception:
            report["security.txt"] = False

        return report


recon_agent = ReconAgent()

SUBDOMAIN_WORDLIST = [
    "www",
    "api",
    "admin",
    "mail",
    "vpn",
    "portal",
    "dashboard",
    "blog",
    "docs",
    "support",
    "dev",
    "test",
    "staging",
    "stage",
    "beta",
    "cdn",
    "img",
    "static",
    "assets",
]


def discover_subdomain(domain: str, sub: str):
    host = f"{sub}.{domain}"
    try:
        socket.gethostbyname(host)
        return host
    except Exception:
        return None


def scan_sensitive_file(
    base_url: str, filename: str, fake_status: int, fake_length: int
):
    url = base_url.rstrip("/") + "/" + filename
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        if response.status_code in (200, 301, 302, 401, 403):
            if (
                response.status_code == fake_status
                and abs(len(response.text) - fake_length) < 100
            ):
                return None
            return {
                "file": filename,
                "url": response.url,
                "status": response.status_code,
            }
    except Exception:
        pass
    return None


SENSITIVE_FILES = [
    "robots.txt",
    "sitemap.xml",
    ".well-known/security.txt",
    "security.txt",
    ".env",
    ".git/config",
    ".git/HEAD",
    "backup.zip",
    "backup.tar.gz",
    "database.sql",
    "db.sql",
    "config.php",
    "phpinfo.php",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "humans.txt",
    "ads.txt",
    "manifest.json",
]
