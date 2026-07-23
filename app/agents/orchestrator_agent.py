"""
===========================================================
Project : Sentinel AI
Module  : Orchestrator Agent
File ID : AGENT-ORCHESTRATOR-001
Version : 1.0.0
===========================================================

Description:
Complete automated security assessment pipeline.
Just provide a target URL, and everything else is automatic.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# ============================================================
# Recon Agent Import (Simple)
# ============================================================

try:
    from app.agents.recon_agent import ReconAgent

    recon_agent_available = True
except ImportError:
    recon_agent_available = False
    ReconAgent = None

# ============================================================
# Logger
# ============================================================

logger = logging.getLogger(__name__)


# ============================================================
# Models
# ============================================================


@dataclass
class Finding:
    title: str = ""
    severity: str = "Medium"
    confidence: float = 0.0
    url: str = ""
    parameter: str = ""
    payload: str = ""
    description: str = ""
    remediation: str = ""


@dataclass
class ScanResult:
    target_url: str
    start_time: datetime
    end_time: datetime
    recon_data: Dict[str, Any] = field(default_factory=dict)
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    vulnerabilities_found: int = 0
    report_path: str = ""
    report_formats: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


# ============================================================
# Orchestrator Agent
# ============================================================


class OrchestratorAgent:
    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        self.recon_agent = None
        if recon_agent_available and ReconAgent is not None:
            self.recon_agent = ReconAgent()
        self.scanner_modules: Dict[str, Any] = {}
        self.current_scan: Optional[ScanResult] = None
        self.findings: List[Finding] = []
        self.report_formats = self.config.get("report_formats", ["pdf", "html", "json"])

    def scan(self, target_url: str) -> ScanResult:
        logger.info("Starting automated scan for: %s", target_url)

        self.current_scan = ScanResult(
            target_url=target_url,
            start_time=datetime.now(),
            end_time=datetime.now(),
        )

        # Phase 1: Reconnaissance
        logger.info("Phase 1: Reconnaissance...")
        recon_data = {"target": target_url}
        if self.recon_agent is not None:
            try:
                recon_data = self.recon_agent.run(target_url)
            except Exception as e:
                logger.error("Reconnaissance failed: %s", e)
        self.current_scan.recon_data = recon_data

        endpoints = self._extract_endpoints(recon_data)
        parameters = self._extract_parameters(recon_data)
        self.current_scan.endpoints = endpoints
        self.current_scan.parameters = parameters

        logger.info("Discovered %d endpoints", len(endpoints))
        logger.info("Discovered %d parameters", len(parameters))

        # Phase 2: Scanning
        logger.info("Phase 2: Vulnerability Scanning...")
        self._run_scanners(target_url, endpoints, parameters)
        logger.info("Found %d vulnerabilities", len(self.findings))

        # Phase 3: Reporting
        logger.info("Phase 3: Generating Report...")
        self.current_scan.findings = self.findings
        self.current_scan.vulnerabilities_found = len(self.findings)

        report_paths = self._generate_reports(target_url, recon_data)
        self.current_scan.report_path = (
            next(iter(report_paths.values())) if report_paths else ""
        )
        self.current_scan.report_formats = list(report_paths.keys())
        self.current_scan.end_time = datetime.now()
        self.current_scan.summary = self._generate_summary()

        logger.info("Scan complete!")
        logger.info("Reports: %s", ", ".join(self.current_scan.report_formats))
        return self.current_scan

    def _run_scanners(
        self, target_url: str, endpoints: List[str], parameters: List[str]
    ) -> None:
        self._load_scanner_modules()
        if not self.scanner_modules:
            return

        for endpoint in endpoints:
            for parameter in parameters:
                test_url = self._build_test_url(endpoint, parameter)
                for scanner_name, scanner_class in self.scanner_modules.items():
                    try:
                        scanner = scanner_class(test_url)
                        findings = scanner.scan()
                        if findings:
                            for finding in findings:
                                self.findings.append(finding)
                                logger.info(
                                    "⚠️ %s vulnerability found in %s",
                                    scanner_name.upper(),
                                    parameter,
                                )
                    except Exception as e:
                        logger.debug("%s scan failed: %s", scanner_name, e)

    def _load_scanner_modules(self) -> None:
        self.scanner_modules.clear()
        try:
            from app.modules.scanner.modules.sqli import SQLiScanner

            self.scanner_modules["sqli"] = SQLiScanner
        except ImportError:
            pass
        try:
            from app.modules.scanner.modules.xss import XSSScanner

            self.scanner_modules["xss"] = XSSScanner
        except ImportError:
            pass
        try:
            from app.modules.scanner.modules.lfi import LFIScanner

            self.scanner_modules["lfi"] = LFIScanner
        except ImportError:
            pass
        try:
            from app.modules.scanner.modules.ssrf import SSRFScanner

            self.scanner_modules["ssrf"] = SSRFScanner
        except ImportError:
            pass
        try:
            from app.modules.scanner.modules.open_redirect import OpenRedirectScanner

            self.scanner_modules["redirect"] = OpenRedirectScanner
        except ImportError:
            pass
        try:
            from app.modules.scanner.modules.login_bypass import LoginBypassScanner

            self.scanner_modules["login_bypass"] = LoginBypassScanner
        except ImportError:
            pass

    def _generate_reports(
        self, target_url: str, recon_data: Dict[str, Any]
    ) -> Dict[str, str]:
        report_paths: Dict[str, str] = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"sentinelai_report_{timestamp}"
        output_dir = self.config.get("output_dir", "./reports")
        reports_dir = os.path.join(output_dir, base_name)
        os.makedirs(reports_dir, exist_ok=True)

        for fmt in self.report_formats:
            try:
                if fmt == "json":
                    path = self._generate_json_report(reports_dir, base_name)
                elif fmt == "html":
                    path = self._build_html_report_file(reports_dir, base_name)
                elif fmt == "pdf":
                    path = self._generate_pdf_report(reports_dir, base_name)
                else:
                    continue
                if path:
                    report_paths[fmt] = path
                    logger.info("✅ %s report: %s", fmt.upper(), path)
            except Exception as e:
                logger.warning("Failed to generate %s report: %s", fmt, e)
        return report_paths

    def _build_html_report_file(self, reports_dir: str, base_name: str) -> str:
        """Generate HTML report file."""
        path = os.path.join(reports_dir, f"{base_name}.html")
        html_content = self._build_html_report()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)
        return path

    def _generate_json_report(self, reports_dir: str, base_name: str) -> str:
        if self.current_scan is None:
            return ""
        report_data = {
            "target": self.current_scan.target_url,
            "timestamp": self.current_scan.start_time.isoformat(),
            "duration": (
                self.current_scan.end_time - self.current_scan.start_time
            ).total_seconds(),
            "recon": self.current_scan.recon_data,
            "findings": [
                {
                    "title": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", ""),
                    "confidence": getattr(f, "confidence", 0.0),
                    "url": getattr(f, "url", ""),
                    "parameter": getattr(f, "parameter", ""),
                    "payload": getattr(f, "payload", ""),
                    "description": getattr(f, "description", ""),
                    "remediation": getattr(f, "remediation", ""),
                }
                for f in self.findings
            ],
            "summary": self.current_scan.summary,
        }
        path = os.path.join(reports_dir, f"{base_name}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        return path

    def _generate_pdf_report(self, reports_dir: str, base_name: str) -> str:
        """Generate PDF report."""
        path = os.path.join(reports_dir, f"{base_name}.pdf")
        try:
            from app.modules.reporting.pdf_report import PDFReport

            pdf = PDFReport()

            # Analysis data prepare karein
            analysis_data = {
                "target": self.current_scan.target_url if self.current_scan else "",
                "summary": self.current_scan.summary if self.current_scan else {},
                "findings": self.findings,
                "recommendations": [],
            }

            pdf.generate(analysis_data, path)
            return path
        except (ImportError, AttributeError) as e:
            logger.warning("PDF generation failed: %s, falling back to HTML", e)
            return self._build_html_report_file(reports_dir, base_name)

    def _build_html_report(self) -> str:
        if self.current_scan is None:
            return "<html><body><h1>Error: No scan data</h1></body></html>"

        severity_colors = {
            "Critical": "#dc3545",
            "High": "#fd7e14",
            "Medium": "#ffc107",
            "Low": "#28a745",
        }

        findings_html = ""
        if self.findings:
            for f in self.findings:
                severity = getattr(f, "severity", "Medium")
                color = severity_colors.get(severity, "#6c757d")
                findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; margin: 10px 0; padding: 10px; background: #f8f9fa;">
                <h3 style="color: {color};">[{severity}] {getattr(f, 'title', 'Unknown')}</h3>
                <p><strong>URL:</strong> {getattr(f, 'url', 'N/A')}</p>
                <p><strong>Parameter:</strong> {getattr(f, 'parameter', 'N/A')}</p>
                <p><strong>Payload:</strong> <code>{getattr(f, 'payload', 'N/A')}</code></p>
                <p><strong>Confidence:</strong> {getattr(f, 'confidence', 0.0) * 100:.0f}%</p>
                <p><strong>Description:</strong> {getattr(f, 'description', 'N/A')}</p>
                <p><strong>Remediation:</strong> {getattr(f, 'remediation', 'N/A')}</p>
            </div>
            """
        else:
            findings_html = "<p>No vulnerabilities found.</p>"

        summary = self.current_scan.summary

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SentinelAI Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .summary table {{ width: 100%; }}
                .summary td {{ padding: 5px 10px; }}
                .finding {{ margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
                .finding h3 {{ margin-top: 0; }}
                code {{ background: #e9ecef; padding: 2px 6px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <h1>SentinelAI Security Assessment Report</h1>
            <p><strong>Target:</strong> {self.current_scan.target_url}</p>
            <p><strong>Date:</strong> {self.current_scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Duration:</strong> {summary.get('duration_seconds', 0):.2f} seconds</p>

            <div class="summary">
                <h2>Executive Summary</h2>
                <table>
                    <tr><td><strong>Total Vulnerabilities:</strong></td><td>{len(self.findings)}</td></tr>
                    <tr><td><strong>Critical:</strong></td><td style="color: #dc3545;">{summary.get('critical', 0)}</td></tr>
                    <tr><td><strong>High:</strong></td><td style="color: #fd7e14;">{summary.get('high', 0)}</td></tr>
                    <tr><td><strong>Medium:</strong></td><td style="color: #ffc107;">{summary.get('medium', 0)}</td></tr>
                    <tr><td><strong>Low:</strong></td><td style="color: #28a745;">{summary.get('low', 0)}</td></tr>
                    <tr><td><strong>Endpoints Scanned:</strong></td><td>{summary.get('endpoints_scanned', 0)}</td></tr>
                    <tr><td><strong>WAF Detected:</strong></td><td>{summary.get('waf_detected', 'None')}</td></tr>
                    <tr><td><strong>Technologies:</strong></td><td>{', '.join(summary.get('technologies', [])) or 'Unknown'}</td></tr>
                </table>
            </div>

            <h2>Findings</h2>
            {findings_html}

            <hr>
            <p style="color: #6c757d; font-size: 12px;">Generated by SentinelAI</p>
        </body>
        </html>
        """

    def _build_test_url(self, endpoint: str, parameter: str) -> str:
        if "?" in endpoint:
            return f"{endpoint}&{parameter}=test"
        return f"{endpoint}?{parameter}=test"

    def _extract_endpoints(self, recon_data: Dict[str, Any]) -> List[str]:
        endpoints: List[str] = []
        target = recon_data.get("target", "")
        if target:
            endpoints.append(target)

        api_discovery = recon_data.get("api_discovery", [])
        if api_discovery:
            for api in api_discovery:
                if isinstance(api, dict) and "endpoint" in api:
                    endpoints.append(str(api["endpoint"]))
                elif isinstance(api, str):
                    endpoints.append(api)

        js_endpoints = recon_data.get("javascript_endpoints", [])
        if js_endpoints:
            endpoints.extend([str(ep) for ep in js_endpoints])

        clean_endpoints: List[str] = []
        for ep in endpoints:
            if ep and isinstance(ep, str):
                if ep.startswith("/") and target:
                    ep = target.rstrip("/") + ep
                clean_endpoints.append(ep)
        return list(set(clean_endpoints))

    def _extract_parameters(self, recon_data: Dict[str, Any]) -> List[str]:
        parameters: List[str] = []
        common_params = [
            "id",
            "page",
            "view",
            "action",
            "q",
            "query",
            "search",
            "file",
            "path",
            "url",
            "redirect",
            "return",
            "next",
            "category",
            "product",
            "user",
            "username",
            "email",
            "password",
            "pass",
            "token",
            "session",
            "cookie",
            "debug",
            "test",
            "admin",
            "api",
            "key",
            "secret",
            "sort",
            "order",
            "limit",
            "offset",
            "filter",
            "callback",
            "jsonp",
            "format",
            "lang",
            "locale",
        ]
        parameters.extend(common_params)
        return list(set(parameters))

    def _generate_summary(self) -> Dict[str, Any]:
        if self.current_scan is None:
            return {}
        critical = sum(
            1 for f in self.findings if getattr(f, "severity", "") == "Critical"
        )
        high = sum(1 for f in self.findings if getattr(f, "severity", "") == "High")
        medium = sum(1 for f in self.findings if getattr(f, "severity", "") == "Medium")
        low = sum(1 for f in self.findings if getattr(f, "severity", "") == "Low")

        return {
            "total_vulnerabilities": len(self.findings),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "endpoints_scanned": len(self.current_scan.endpoints),
            "parameters_tested": len(self.current_scan.parameters),
            "duration_seconds": (
                self.current_scan.end_time - self.current_scan.start_time
            ).total_seconds(),
            "waf_detected": self.current_scan.recon_data.get("waf"),
            "technologies": self.current_scan.recon_data.get("technologies", []),
        }


# ============================================================
# CLI
# ============================================================


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SentinelAI")
    parser.add_argument("target", help="Target URL")
    parser.add_argument(
        "--report-format", choices=["pdf", "html", "json", "all"], default="all"
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--output-dir", "-o", default="./reports")

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    config: Dict[str, Any] = {
        "report_formats": (
            ["pdf", "html", "json"]
            if args.report_format == "all"
            else [args.report_format]
        ),
        "output_dir": args.output_dir,
    }

    orchestrator = OrchestratorAgent(config)
    result = orchestrator.scan(args.target)

    print(f"\n{'='*60}")
    print("SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Target: {result.target_url}")
    print(f"Duration: {result.summary['duration_seconds']:.2f} seconds")
    print(f"Vulnerabilities Found: {result.vulnerabilities_found}")
    print(f"  Critical: {result.summary['critical']}")
    print(f"  High: {result.summary['high']}")
    print(f"  Medium: {result.summary['medium']}")
    print(f"  Low: {result.summary['low']}")
    print(f"Reports: {', '.join(result.report_formats)}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
