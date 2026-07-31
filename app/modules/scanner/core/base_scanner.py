"""
===========================================================
Project : Sentinel AI
Module  : Base Scanner
File ID : SCANNER-CORE-BASE-001
Version : 2.0.0
===========================================================

Description:

Base class for every vulnerability scanner.

Provides:

• Request Engine
• Response Analyzer
• Scope Validation
• Findings Management
• Statistics
• Logging
• Production-grade ScanResult

===========================================================
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from time import perf_counter
from typing import Any, Self, Optional

from app.modules.recon.scope_manager import ScopeManager
from app.modules.scanner.core.request_engine import (
    RequestEngine,
    ResponseData,
)
from app.modules.scanner.core.response_analyzer import (
    AnalysisResult,
    ResponseAnalyzer,
)

# ===========================================================
# Scan Result - Production Grade
# ===========================================================


@dataclass(slots=True)
class ScanResult:
    """
    Production-grade standardized scan result for SentinelAI.

    This dataclass provides a consistent format for all scanner results
    across the entire SentinelAI framework.

    Fields:
        scanner_name: Name of the scanner that produced this result
        vulnerability_type: Type of vulnerability (e.g., 'sql_injection', 'xss')
        severity: Severity level ('critical', 'high', 'medium', 'low', 'info')
        confidence: Confidence score (0.0 to 100.0)
        url: Target URL where vulnerability was found
        method: HTTP method used (GET, POST, PUT, DELETE, etc.)
        parameter: Parameter name that is vulnerable
        payload: Payload that triggered the vulnerability
        evidence: Evidence of the vulnerability (response snippet, error message, etc.)
        description: Human-readable description of the vulnerability
        remediation: Recommended remediation steps
        references: List of reference URLs or CVE IDs
        cwe_id: CWE ID (e.g., 'CWE-89')
        cvss_score: CVSS score (0.0 to 10.0)
        status_code: HTTP status code of the response
        response_time: Response time in seconds
        tags: List of tags for categorization
        metadata: Additional metadata dictionary
        timestamp: When the result was created
        scan_id: Unique scan identifier (optional)
        raw_response: Raw response data (optional)
        scanner_version: Version of the scanner (optional)
        # Backward compatibility fields
        scanner: str = ""  # Alias for scanner_name (deprecated)
        target: str = ""   # Alias for url (deprecated)
        vulnerable: bool = False  # For backward compatibility
    """

    # Required fields
    scanner_name: str
    vulnerability_type: str
    severity: str
    confidence: float
    url: str

    # Optional fields with defaults
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe_id: str = ""
    cvss_score: float = 0.0
    status_code: int = 0
    response_time: float = 0.0
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: Optional[str] = None
    raw_response: Optional[str] = None
    scanner_version: Optional[str] = None

    success: bool = True
    findings: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    # Backward compatibility fields
    scanner: str = ""
    target: str = ""
    vulnerable: bool = False

    # New fields for SecretsScanner
    success: bool = True
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate and normalize fields after initialization."""
        # Validate confidence
        if not 0.0 <= self.confidence <= 100.0:
            raise ValueError(
                f"Confidence must be between 0.0 and 100.0, got {self.confidence}"
            )

        # Validate severity
        valid_severities = {"critical", "high", "medium", "low", "info"}
        if self.severity.lower() not in valid_severities:
            raise ValueError(
                f"Invalid severity: {self.severity}. Must be one of {valid_severities}"
            )

        # Normalize severity to lowercase
        self.severity = self.severity.lower()

        # Ensure timestamp has timezone
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

        # Backward compatibility: populate scanner and target if empty
        if not self.scanner:
            self.scanner = self.scanner_name
        if not self.target:
            self.target = self.url

        # Set vulnerable based on severity (if not explicitly set)
        if not self.vulnerable and self.severity in ("critical", "high", "medium"):
            self.vulnerable = True

    def to_dict(self) -> dict[str, Any]:
        """
        Convert ScanResult to dictionary.

        Returns:
            dict[str, Any]: Dictionary representation
        """
        return {
            "scanner_name": self.scanner_name,
            "scanner": self.scanner,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "target": self.target,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "status_code": self.status_code,
            "response_time": self.response_time,
            "tags": self.tags,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
            "scan_id": self.scan_id,
            "raw_response": self.raw_response,
            "scanner_version": self.scanner_version,
            "success": self.success,
            "findings": self.findings,
            "error": self.error,
            "vulnerable": self.vulnerable,
        }

    def to_json(self, indent: int = 2) -> str:
        """
        Convert ScanResult to JSON string.

        Args:
            indent: Indentation level for pretty printing

        Returns:
            str: JSON string
        """
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def get_severity_level(self) -> int:
        """
        Get numeric severity level for sorting/comparison.

        Returns:
            int: Severity level (5=critical, 4=high, 3=medium, 2=low, 1=info)
        """
        severity_map = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }
        return severity_map.get(self.severity, 0)

    def is_critical(self) -> bool:
        """Check if severity is critical."""
        return self.severity == "critical"

    def is_high(self) -> bool:
        """Check if severity is high or critical."""
        return self.severity in ("critical", "high")

    def get_summary(self) -> str:
        """
        Get a human-readable summary of the result.

        Returns:
            str: Summary string
        """
        return (
            f"[{self.severity.upper()}] {self.vulnerability_type} "
            f"at {self.url} (confidence: {self.confidence:.1f}%)"
        )

    def get_short_id(self) -> str:
        """
        Generate a short unique identifier for this result.

        Returns:
            str: Short ID
        """
        import hashlib

        data = (
            f"{self.scanner_name}:{self.url}:{self.parameter}:{self.vulnerability_type}"
        )
        return hashlib.md5(data.encode()).hexdigest()[:8]

    # ===========================================================
    # Migration Adapter
    # ===========================================================

    def adapt_legacy_finding(
        scanner_name: str,
        target: str,
        vulnerable: bool,
        severity: str,
        description: str,
        confidence: float,
        evidence: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """
        Adapt legacy finding format to new ScanResult.

        Args:
            scanner_name: Scanner name
            target: Target URL
            vulnerable: Whether vulnerable
            severity: Severity level
            description: Description
            confidence: Confidence score
            evidence: Evidence list
            metadata: Metadata

        Returns:
            ScanResult: New ScanResult instance
        """
        return ScanResult(
            scanner_name=scanner_name,
            vulnerability_type=description[:50] if description else "unknown",
            severity=severity.lower() if severity else "info",
            confidence=confidence if confidence is not None else 0.0,
            url=target,
            description=description or "",
            evidence="\n".join(evidence) if evidence else "",
            metadata=metadata or {},
            scanner=scanner_name,
            target=target,
            vulnerable=vulnerable,
        )


# ===========================================================
# Scan Status
# ===========================================================


class ScanStatus(str, Enum):
    """
    Scanner lifecycle.
    """

    IDLE = "idle"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"


# ===========================================================
# Scanner Configuration
# ===========================================================


@dataclass(slots=True)
class ScannerConfig:
    """
    Common configuration shared by every scanner.
    """

    timeout: float = 15.0
    retries: int = 1
    verify_ssl: bool = True
    follow_redirects: bool = True
    user_agent: str | None = None
    proxy: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


# ===========================================================
# Base Scanner
# ===========================================================


class BaseScanner:
    """
    Base class used by every scanner.
    """

    def __init__(
        self,
        target: str,
        scope: ScopeManager | None = None,
        config: ScannerConfig | None = None,
    ) -> None:

        self.target = target
        self.scope = scope
        self.config = config or ScannerConfig()
        self.version = "1.0.0"

        self.logger = logging.getLogger(self.__class__.__name__)

        self.request = RequestEngine()
        self.analyzer = ResponseAnalyzer()

        self.findings: list[ScanResult] = []

        self.started_at = 0.0
        self.finished_at = 0.0
        self.requests_sent = 0
        self.responses_received = 0
        self.errors = 0
        self.status = ScanStatus.IDLE

    # ===========================================================
    # Scope Validation
    # ===========================================================

    def in_scope(self, url: str) -> bool:
        """
        Check whether URL is inside scope.
        """
        if self.scope is None:
            return True
        return self.scope.is_allowed(url)

    # ===========================================================
    # GET Request
    # ===========================================================

    def get(self, url: str, **kwargs: Any) -> ResponseData:
        """
        Send GET request.
        """
        self.requests_sent += 1
        self.before_request(url)

        self.logger.debug("GET %s", url)

        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verify_ssl)

        if self.config.headers:
            headers = kwargs.setdefault("headers", {})
            headers.update(self.config.headers)

        response = self.request.get(url, **kwargs)

        self.responses_received += 1
        self.after_request(response)

        self.logger.debug("Response %s (%d)", url, response.status_code)

        return response

    # ===========================================================
    # POST Request
    # ===========================================================

    def post(self, url: str, **kwargs: Any) -> ResponseData:
        """
        Send POST request.
        """
        self.requests_sent += 1
        self.before_request(url)

        self.logger.debug("POST %s", url)

        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("verify", self.config.verify_ssl)

        if self.config.headers:
            headers = kwargs.setdefault("headers", {})
            headers.update(self.config.headers)

        response = self.request.post(url, **kwargs)

        self.responses_received += 1
        self.after_request(response)

        self.logger.debug("Response %s (%d)", url, response.status_code)

        return response

    # ===========================================================
    # Analyze Response
    # ===========================================================

    def analyze(self, response: ResponseData) -> AnalysisResult:
        """
        Analyze HTTP response.
        """
        return self.analyzer.analyze(response)

    # ===========================================================
    # Add Finding
    # ===========================================================

    def add_finding(self, finding: ScanResult) -> None:
        """
        Store finding.
        """
        self.findings.append(finding)

    # ===========================================================
    # Create Finding
    # ===========================================================

    def create_finding(
        self,
        *,
        vulnerability_type: str,
        severity: str,
        description: str,
        confidence: float,
        url: Optional[str] = None,
        method: str = "GET",
        parameter: str = "",
        payload: str = "",
        evidence: str = "",
        remediation: str = "",
        references: Optional[list[str]] = None,
        cwe_id: str = "",
        cvss_score: float = 0.0,
        status_code: int = 0,
        response_time: float = 0.0,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
        # Backward compatibility
        vulnerable: bool = False,
    ) -> ScanResult:
        """
        Create a standardized ScanResult instance.

        Args:
            vulnerability_type: Type of vulnerability
            severity: Severity level
            description: Description of the vulnerability
            confidence: Confidence score (0-100)
            url: Target URL (defaults to self.target)
            method: HTTP method used
            parameter: Vulnerable parameter
            payload: Payload used
            evidence: Evidence of vulnerability
            remediation: Remediation steps
            references: Reference URLs or CVE IDs
            cwe_id: CWE ID
            cvss_score: CVSS score
            status_code: HTTP status code
            response_time: Response time in seconds
            tags: Tags for categorization
            metadata: Additional metadata
            vulnerable: For backward compatibility

        Returns:
            ScanResult: ScanResult instance
        """
        return ScanResult(
            scanner_name=self.__class__.__name__,
            scanner_version=getattr(self, "version", "1.0.0"),
            vulnerability_type=vulnerability_type,
            severity=severity,
            confidence=confidence,
            url=url or self.target,
            method=method,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            description=description,
            remediation=remediation,
            references=references or [],
            cwe_id=cwe_id,
            cvss_score=cvss_score,
            status_code=status_code,
            response_time=response_time,
            tags=tags or [],
            metadata=metadata or {},
            vulnerable=vulnerable,
            scanner=self.__class__.__name__,
            target=url or self.target,
        )

    # ===========================================================
    # Start Scan
    # ===========================================================

    def start_scan(self) -> None:
        """
        Initialize scanner runtime.
        """
        self.started_at = perf_counter()
        self.status = ScanStatus.RUNNING
        self.finished_at = 0.0
        self.requests_sent = 0
        self.responses_received = 0
        self.errors = 0
        self.findings.clear()

        self.before_scan()

        self.logger.info("Started scan: %s", self.target)

    # ===========================================================
    # Finish Scan
    # ===========================================================

    def finish_scan(self) -> None:
        """
        Finish scanner runtime.
        """
        self.finished_at = perf_counter()
        self.status = ScanStatus.FINISHED

        self.after_scan()

        self.logger.info("Finished scan: %s", self.target)

    # ===========================================================
    # Scan Hooks
    # ===========================================================

    def before_scan(self) -> None:
        """
        Hook executed before scan starts.

        Child scanners may override this.
        """
        pass

    def after_scan(self) -> None:
        """
        Hook executed after scan finishes.

        Child scanners may override this.
        """
        pass

    def before_request(self, url: str) -> None:
        """
        Hook executed before every HTTP request.

        Child scanners may override this.
        """
        pass

    def after_request(self, response: ResponseData) -> None:
        """
        Hook executed after every HTTP response.

        Child scanners may override this.
        """
        pass

    # ===========================================================
    # Scan Duration
    # ===========================================================

    def scan_duration(self) -> float:
        """
        Return scan duration in seconds.
        """
        if self.finished_at == 0.0:
            return perf_counter() - self.started_at
        return self.finished_at - self.started_at

    # ===========================================================
    # Record Error
    # ===========================================================

    def record_error(self) -> None:
        """
        Increase scanner error counter.
        """
        self.errors += 1
        self.status = ScanStatus.FAILED

    # ===========================================================
    # Safe Request
    # ===========================================================

    def safe_get(self, url: str, **kwargs: Any) -> ResponseData | None:
        """
        Execute GET request safely.

        Returns None on failure.
        """
        try:
            return self.get(url, **kwargs)
        except Exception:
            self.record_error()
            self.logger.exception("GET request failed: %s", url)
            return None

    # ===========================================================
    # Safe POST
    # ===========================================================

    def safe_post(self, url: str, **kwargs: Any) -> ResponseData | None:
        """
        Execute POST request safely.

        Returns None on failure.
        """
        try:
            return self.post(url, **kwargs)
        except Exception:
            self.record_error()
            self.logger.exception("POST request failed: %s", url)
            return None

    # ===========================================================
    # Summary
    # ===========================================================

    def summary(self) -> dict[str, Any]:
        """
        Return scanner summary.
        """
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in self.findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            "scanner": self.__class__.__name__,
            "target": self.target,
            "requests": self.requests_sent,
            "responses": self.responses_received,
            "errors": self.errors,
            "status": self.status.value,
            "findings": len(self.findings),
            "severity_counts": severity_counts,
            "duration": round(self.scan_duration(), 2),
        }

    # ===========================================================
    # Reset
    # ===========================================================

    def reset(self) -> None:
        """
        Reset scanner state.
        """
        self.findings.clear()
        self.started_at = 0.0
        self.finished_at = 0.0
        self.requests_sent = 0
        self.responses_received = 0
        self.errors = 0
        self.status = ScanStatus.IDLE

    # ===========================================================
    # Run
    # ===========================================================

    def run(self) -> list[ScanResult]:
        """
        Scanner entry point.

        Must be implemented by child classes.
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement run().")

    # ===========================================================
    # Context Manager
    # ===========================================================

    def __enter__(self) -> Self:
        self.start_scan()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.finish_scan()
        self.request.close()

    # ===========================================================
    # String Representation
    # ===========================================================

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(target='{self.target}')"


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    class DemoScanner(BaseScanner):
        def run(self) -> list[ScanResult]:
            self.start_scan()

            finding = self.create_finding(
                vulnerability_type="self_test",
                severity="info",
                confidence=100.0,
                description="BaseScanner self-test with new ScanResult format.",
                evidence="All systems operational.",
                tags=["test", "base"],
            )

            self.add_finding(finding)
            self.finish_scan()
            return self.findings

    scanner = DemoScanner("https://example.com")
    results = scanner.run()

    print("=" * 60)
    print("SentinelAI BaseScanner")
    print("=" * 60)
    print(scanner.summary())
    print()

    for result in results:
        print("Finding:")
        print(f"  Scanner: {result.scanner_name}")
        print(f"  Type: {result.vulnerability_type}")
        print(f"  Severity: {result.severity}")
        print(f"  Confidence: {result.confidence}%")
        print(f"  Description: {result.description}")
        print(f"  Evidence: {result.evidence}")
        print(f"  Tags: {result.tags}")
        print(f"  Vulnerable: {result.vulnerable}")
        print()
