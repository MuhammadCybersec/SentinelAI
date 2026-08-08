"""
Scanner Manager - Orchestrates multiple scanners for comprehensive security scanning.

This module provides centralized management of all security scanners with
parallel execution, result aggregation, reporting, and statistics generation.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from app.agents.planner_agent import PlannerAgent
from app.modules.scanner.modules.secrets_scanner import SecretsScanner
from app.modules.scanner.modules.sqli import SQLiScanner
from app.modules.scanner.modules.xss_scanner import XSSScanner


@dataclass(slots=True)
class ScanFinding:
    """
    Unified scan finding with all metadata.

    Attributes:
        id: Unique identifier
        scanner: Scanner name
        title: Finding title
        description: Detailed description
        severity: Critical, High, Medium, Low
        cwe: CWE identifier
        owasp: OWASP category
        cvss: CVSS score
        url: Target URL
        payload: Payload used
        evidence: List of evidence items
        remediation: Remediation steps
        references: List of references
        timestamp: When found
        metadata: Additional metadata
    """

    id: UUID = field(default_factory=uuid4)
    scanner: str = ""
    title: str = ""
    description: str = ""
    severity: str = "Medium"
    cwe: str = ""
    owasp: str = ""
    cvss: str = ""
    url: str = ""
    payload: str = ""
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanStatistics:
    """
    Statistics for a scan session.

    Attributes:
        total_findings: Total findings count
        critical: Critical severity count
        high: High severity count
        medium: Medium severity count
        low: Low severity count
        scanners_used: List of scanner names
        total_scanners: Number of scanners used
        start_time: Session start time
        end_time: Session end time
        duration: Duration in seconds
        findings_by_scanner: Breakdown by scanner
    """

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    scanners_used: list[str] = field(default_factory=list)
    total_scanners: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration: float = 0.0
    findings_by_scanner: dict[str, int] = field(default_factory=dict)


class ScannerManagerError(Exception):
    pass


class ScannerNotFoundError(ScannerManagerError):
    pass


class ScannerRegistrationError(ScannerManagerError):
    pass


class ScannerExecutionError(ScannerManagerError):
    pass


@dataclass(slots=True)
class ScannerInfo:
    name: str
    version: str = "1.0.0"
    description: str = ""
    severity: str = ""


@dataclass(slots=True)
class ScannerExecutionResult:
    scanner: str
    success: bool
    findings: list[ScanFinding] = field(default_factory=list)
    error: str | None = None
    duration: float = 0.0


class ScannerManager:
    """
    Centralized manager for orchestrating all security scanners.

    Features:
        - Parallel scanner execution
        - Result aggregation
        - Database persistence
        - PDF report generation
        - Statistics collection
        - Thread-safe operations
    """

    def __init__(
        self,
        base_manager: Any | None = None,
        max_workers: int = 4,
        timeout: float = 60.0,
        db_path: str | None = None,
    ) -> None:
        """
        Initialize the Scanner Manager.

        Args:
            base_manager: BaseScannerManager instance (not used, kept for compatibility)
            max_workers: Maximum parallel workers
            timeout: Default timeout per scanner
            db_path: Database path for storing findings
        """
        self._base_manager = base_manager
        self._max_workers = max_workers
        self._timeout = timeout
        self._db_path = db_path or "scan_results.json"
        self._logger = logging.getLogger(__name__)
        self._planner = PlannerAgent()

        # Thread-safe state
        self._lock = threading.RLock()
        self._findings: list[ScanFinding] = []
        self._statistics = ScanStatistics()
        self._scan_id: UUID | None = None
        self._is_running: bool = False

        # Scanner registry - only existing scanners
        self._scanners = {
            "xss": XSSScanner,
            "sqli": SQLiScanner,
            "secrets": SecretsScanner,
        }
        self._scanner_names = list(self._scanners.keys())

    def run_scan(
        self,
        target: str,
        scanners: list[str] | None = None,
        save_to_db: bool = True,
        generate_report: bool = True,
    ) -> tuple[list[ScanFinding], ScanStatistics]:

        if not target or not target.strip():
            raise ValueError("Target URL cannot be empty")

        try:
            analysis = self._planner.analyze_target(target)
            recommended_scanners = analysis.recommended_scanners

            self._logger.info(f"Recommended scanners: {recommended_scanners}")

        except Exception as exc:
            self._logger.warning(f"Planner analysis failed: {exc}")

            recommended_scanners = []

        if scanners is None and recommended_scanners:
            scanners = recommended_scanners

        if scanners is not None:
            valid_scanners = [
                scanner for scanner in scanners if scanner in self._scanners
            ]

            if not valid_scanners:
                self._logger.warning(f"No valid scanners found in: {scanners}")

                valid_scanners = self._scanner_names
        else:
            valid_scanners = self._scanner_names

        with self._lock:
            if self._is_running:
                raise RuntimeError("A scan is already running")

            self._is_running = True
            self._scan_id = uuid4()
            self._findings.clear()

            self._statistics = ScanStatistics(
                start_time=datetime.now(timezone.utc),
                scanners_used=valid_scanners,
                total_scanners=len(valid_scanners),
            )

        return self._findings, self._statistics

    def _run_scanners_parallel(
        self, target: str, scanners: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Run selected scanners in parallel.

        Args:
            target: Target URL
            scanners: List of scanner names

        Returns:
            Dictionary of scan results by scanner
        """
        scanner_names = scanners or self._scanner_names
        results: dict[str, Any] = {}

        # Create scanner instances
        scanner_instances = {}
        for name in scanner_names:
            if name not in self._scanners:
                self._logger.warning(f"Scanner '{name}' not found, skipping")
                continue

            try:
                scanner_class = self._scanners[name]

                # Create scanner instance with target
                scanner_instance = scanner_class(target=target)

                # Check if scanner has a scan method (including mock objects)
                scan_method = getattr(scanner_instance, "scan", None)
                if scan_method is not None and callable(scan_method):
                    scanner_instances[name] = scanner_instance
                else:
                    self._logger.warning(f"Scanner '{name}' has no scan method")
            except (ValueError, TypeError, AttributeError) as e:
                self._logger.error(f"Failed to initialize scanner '{name}': {e}")

        if not scanner_instances:
            self._logger.warning("No scanners available to run")
            return results

        # Run scanners in parallel using asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            # Create tasks for each scanner
            tasks = {}
            for name, scanner in scanner_instances.items():
                tasks[name] = loop.run_in_executor(None, scanner.scan)

            # Run all tasks concurrently
            if tasks:
                done = loop.run_until_complete(
                    asyncio.gather(*tasks.values(), return_exceptions=True)
                )

                # Collect results
                for i, (name, _) in enumerate(tasks.items()):
                    result = done[i]
                    print("=" * 50)
                    print(f"[DEBUG] Scanner Name: {name}")
                    print(f"[DEBUG] Result Type: {type(result)}")
                    if isinstance(result, Exception):

                        self._logger.error(f"Scanner '{name}' failed: {result}")
                        results[name] = {"error": str(result), "findings": []}
                    else:
                        # Convert to ScanFinding objects
                        findings = self._convert_findings(name, result, target)
                        results[name] = {"findings": findings}

        finally:
            loop.close()

        return results

    def _convert_findings(
        self, scanner_name: str, scanner_result: Any, target: str
    ) -> list[ScanFinding]:
        """
        Convert scanner-specific findings to unified ScanFinding objects.

        Args:
            scanner_name: Name of the scanner
            scanner_result: Scanner result object
            target: Target URL

        Returns:
            List of ScanFinding objects
        """
        findings = []

        # Handle different scanner result types
        if hasattr(scanner_result, "findings"):
            raw_findings = scanner_result.findings
        elif isinstance(scanner_result, list):
            raw_findings = scanner_result
        else:
            raw_findings = []

        for raw in raw_findings:
            finding = ScanFinding()
            finding.scanner = scanner_name
            finding.url = target

            # Extract data based on scanner type
            if scanner_name == "sqli":
                self._convert_sqli_finding(finding, raw)
            elif scanner_name == "xss":
                self._convert_xss_finding(finding, raw)
            else:
                self._convert_generic_finding(finding, raw)

            # Ensure required fields
            if not finding.title:
                finding.title = f"{scanner_name.upper()} Vulnerability Detected"
            if not finding.severity:
                finding.severity = "Medium"
            if not finding.cwe:
                finding.cwe = "CWE-Unknown"

            findings.append(finding)

        return findings

    def _convert_sqli_finding(self, finding: ScanFinding, raw: Any) -> None:
        """Convert SQLi finding."""
        if isinstance(raw, dict):
            finding.title = raw.get("title", "SQL Injection Vulnerability")
            finding.description = raw.get("description", "SQL Injection detected")
            finding.severity = raw.get("severity", "High")
            finding.cwe = raw.get("cwe", "CWE-89")
            finding.owasp = raw.get("owasp", "OWASP Top 10 2021 - A03: Injection")
            finding.cvss = raw.get(
                "cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (7.5)"
            )
            finding.payload = raw.get("payload", "")
            finding.evidence = raw.get("evidence", [])
            finding.remediation = raw.get("remediation", "Use parameterized queries")
            finding.references = raw.get("references", [])
            finding.metadata = {
                "dbms": raw.get("dbms", "Unknown"),
                "technique": raw.get("technique", ""),
            }

    def _convert_xss_finding(self, finding: ScanFinding, raw: Any) -> None:
        """Convert XSS finding."""
        if isinstance(raw, dict):
            finding.title = raw.get("title", "Cross-Site Scripting (XSS) Vulnerability")
            finding.description = raw.get("description", "XSS vulnerability detected")
            finding.severity = raw.get("severity", "Medium")
            finding.cwe = raw.get("cwe", "CWE-79")
            finding.owasp = raw.get("owasp", "OWASP Top 10 2021 - A03: Injection")
            finding.cvss = raw.get(
                "cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)"
            )
            finding.payload = raw.get("payload", "")
            finding.evidence = raw.get("evidence", [])
            finding.remediation = raw.get(
                "remediation", "Encode output, use CSP headers"
            )
            finding.references = raw.get("references", [])
            finding.metadata = {"type": raw.get("type", "Reflected")}

    def _convert_generic_finding(self, finding: ScanFinding, raw: Any) -> None:
        """Convert generic finding."""
        if isinstance(raw, dict):
            finding.title = raw.get("title", str(raw.get("type", "Vulnerability")))
            finding.description = raw.get("description", str(raw))
            finding.severity = raw.get("severity", "Medium")
            finding.cwe = raw.get("cwe", "CWE-Unknown")
            finding.payload = raw.get("payload", "")
            finding.evidence = raw.get("evidence", [])
            finding.remediation = raw.get("remediation", "")
            finding.references = raw.get("references", [])
        elif hasattr(raw, "__dict__"):
            # Try to extract from object
            for attr in [
                "title",
                "description",
                "severity",
                "cwe",
                "payload",
                "evidence",
                "remediation",
            ]:
                if hasattr(raw, attr):
                    setattr(finding, attr, getattr(raw, attr))

    def _process_results(self, results: dict[str, Any], target: str) -> None:
        """
        Process and aggregate scan results.

        Args:
            results: Dictionary of results by scanner
            target: Target URL
        """
        with self._lock:
            for scanner_name, data in results.items():
                findings = data.get("findings", [])
                self._findings.extend(findings)

                # Track findings by scanner
                self._statistics.findings_by_scanner[scanner_name] = len(findings)

    def _update_statistics(self) -> None:
        """Update scan statistics."""
        with self._lock:
            self._statistics.total_findings = len(self._findings)

            for finding in self._findings:
                severity = finding.severity.lower()
                if severity == "critical":
                    self._statistics.critical += 1
                elif severity == "high":
                    self._statistics.high += 1
                elif severity == "medium":
                    self._statistics.medium += 1
                elif severity == "low":
                    self._statistics.low += 1

    def _save_to_database(self) -> None:
        """Save findings to database (JSON file)."""
        with self._lock:
            if not self._findings:
                self._logger.info("No findings to save")
                return

            data = {
                "scan_id": str(self._scan_id),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "statistics": {
                    "total_findings": self._statistics.total_findings,
                    "critical": self._statistics.critical,
                    "high": self._statistics.high,
                    "medium": self._statistics.medium,
                    "low": self._statistics.low,
                },
                "findings": [
                    {
                        "id": str(f.id),
                        "scanner": f.scanner,
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity,
                        "cwe": f.cwe,
                        "owasp": f.owasp,
                        "cvss": f.cvss,
                        "url": f.url,
                        "payload": f.payload,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                        "references": f.references,
                        "timestamp": f.timestamp.isoformat(),
                    }
                    for f in self._findings
                ],
            }

            try:
                path = Path(self._db_path)
                path.parent.mkdir(parents=True, exist_ok=True)

                # Load existing data if any
                existing = []
                if path.exists():
                    try:
                        with open(path, "r", encoding="utf-8") as f:
                            content = f.read().strip()
                            if content:
                                existing = json.loads(content)
                                if not isinstance(existing, list):
                                    existing = []
                    except (json.JSONDecodeError, OSError):
                        # File exists but is empty or corrupted, start fresh
                        existing = []

                existing.append(data)

                with open(path, "w", encoding="utf-8") as f:
                    json.dump(existing, f, indent=2)

                self._logger.info(
                    f"Saved {len(self._findings)} findings to {self._db_path}"
                )
            except (OSError, json.JSONDecodeError) as e:
                self._logger.error(f"Failed to save to database: {e}")

    def _generate_pdf_report(self) -> None:
        """
        Generate a professional PDF report.

        Note: This is a placeholder that generates a JSON report.
        PDF generation requires additional libraries.
        """
        try:
            # Generate report data
            report = self._generate_report_data()

            # Save as JSON (placeholder for PDF)
            report_path = Path(f"report_{self._scan_id}.json")
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)

            self._logger.info(f"Report generated: {report_path}")

        except (OSError, json.JSONDecodeError) as e:
            self._logger.error(f"Failed to generate report: {e}")

    def _generate_report_data(self) -> dict[str, Any]:
        """
        Generate report data structure.

        Returns:
            Dictionary containing complete report data
        """
        return {
            "title": "SentinelAI Security Scan Report",
            "scan_id": str(self._scan_id),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "executive_summary": self._generate_executive_summary(),
            "statistics": {
                "total_findings": self._statistics.total_findings,
                "critical": self._statistics.critical,
                "high": self._statistics.high,
                "medium": self._statistics.medium,
                "low": self._statistics.low,
                "scanners_used": self._statistics.scanners_used,
                "duration": f"{self._statistics.duration:.2f}s",
            },
            "findings": [
                {
                    "scanner": f.scanner,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "cvss": f.cvss,
                    "url": f.url,
                    "payload": f.payload,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "references": f.references,
                }
                for f in self._findings
            ],
            "recommendations": self._generate_recommendations(),
        }

    def _generate_executive_summary(self) -> str:
        """Generate executive summary."""
        total = self._statistics.total_findings
        if total == 0:
            return "No security vulnerabilities were detected during the scan."

        critical = self._statistics.critical
        high = self._statistics.high
        medium = self._statistics.medium
        low = self._statistics.low

        parts = []
        if critical > 0:
            parts.append(f"{critical} critical")
        if high > 0:
            parts.append(f"{high} high")
        if medium > 0:
            parts.append(f"{medium} medium")
        if low > 0:
            parts.append(f"{low} low")

        summary = f"A total of {total} vulnerabilities were identified: "
        summary += ", ".join(parts)
        summary += ". Immediate remediation is recommended for critical and high severity findings."

        return summary

    def _generate_recommendations(self) -> list[str]:
        """Generate recommendations based on findings."""
        recommendations = set()

        for finding in self._findings:
            if finding.remediation:
                recommendations.add(finding.remediation)

        # Add general recommendations
        recommendations.add("Implement regular security scanning and testing")
        recommendations.add("Follow secure coding best practices")
        recommendations.add("Keep dependencies and libraries updated")

        return list(recommendations)

    def get_findings(self) -> list[ScanFinding]:
        """Get all findings from the last scan."""
        with self._lock:
            return self._findings.copy()

    def get_statistics(self) -> ScanStatistics:
        """Get statistics from the last scan."""
        with self._lock:
            return self._statistics

    def get_status(self) -> dict[str, Any]:
        """Get current scan status."""
        with self._lock:
            return {
                "is_running": self._is_running,
                "scan_id": str(self._scan_id) if self._scan_id else None,
                "total_findings": len(self._findings),
                "scanners_available": list(self._scanners.keys()),
            }

    def register_scanner(self, name: str, scanner_class: Any) -> None:
        """
        Register a new scanner.

        Args:
            name: Scanner name
            scanner_class: Scanner class
        """
        with self._lock:
            self._scanners[name] = scanner_class
            if name not in self._scanner_names:
                self._scanner_names.append(name)

    def clear_findings(self) -> None:
        """Clear all findings."""
        with self._lock:
            self._findings.clear()
            self._statistics = ScanStatistics()
