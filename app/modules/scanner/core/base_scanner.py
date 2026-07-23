"""
===========================================================
Project : Sentinel AI
Module  : Base Scanner
File ID : SCANNER-CORE-BASE-001
Version : 1.0.0
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

===========================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter
from typing import Any

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
# Scan Result
# ===========================================================


@dataclass(slots=True)
class ScanResult:
    """
    Generic scanner result.
    """

    scanner: str

    target: str

    vulnerable: bool = False

    severity: str = "Info"

    confidence: float = 0.0

    description: str = ""

    evidence: list[str] = field(
        default_factory=list,
    )

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )


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
    ) -> None:

        self.target = target

        self.scope = scope

        self.request = RequestEngine()

        self.analyzer = ResponseAnalyzer()

        self.findings: list[ScanResult] = []

        self.started_at = 0.0

        self.finished_at = 0.0

        self.requests_sent = 0

        self.responses_received = 0

        self.errors = 0

    # ===========================================================

    # Scope Validation
    # ===========================================================

    def in_scope(
        self,
        url: str,
    ) -> bool:
        """
        Check whether URL is inside scope.
        """

        if self.scope is None:

            return True

        return self.scope.is_allowed(
            url,
        )

    # ===========================================================
    # GET Request
    # ===========================================================

    def get(
        self,
        url: str,
        **kwargs: Any,
    ) -> ResponseData:
        """
        Send GET request.
        """

        self.requests_sent += 1

        response = self.request.get(
            url,
            **kwargs,
        )

        self.responses_received += 1

        return response

    # ===========================================================
    # POST Request
    # ===========================================================

    def post(
        self,
        url: str,
        **kwargs: Any,
    ) -> ResponseData:
        """
        Send POST request.
        """

        self.requests_sent += 1

        response = self.request.post(
            url,
            **kwargs,
        )

        self.responses_received += 1

        return response

    # ===========================================================
    # Analyze Response
    # ===========================================================

    def analyze(
        self,
        response: ResponseData,
    ) -> AnalysisResult:
        """
        Analyze HTTP response.
        """

        return self.analyzer.analyze(
            response,
        )

    # ===========================================================
    # Add Finding
    # ===========================================================

    def add_finding(
        self,
        finding: ScanResult,
    ) -> None:
        """
        Store finding.
        """

        self.findings.append(
            finding,
        )

    # ===========================================================
    # Create Finding
    # ===========================================================

    def create_finding(
        self,
        *,
        vulnerable: bool,
        severity: str,
        description: str,
        confidence: float,
        evidence: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> ScanResult:
        """
        Create a ScanResult instance.
        """

        return ScanResult(
            scanner=self.__class__.__name__,
            target=self.target,
            vulnerable=vulnerable,
            severity=severity,
            confidence=confidence,
            description=description,
            evidence=evidence or [],
            metadata=metadata or {},
        )
        # ===========================================================

    # Start Scan
    # ===========================================================

    def start_scan(
        self,
    ) -> None:
        """
        Initialize scanner runtime.
        """

        self.started_at = perf_counter()

        self.finished_at = 0.0

        self.requests_sent = 0

        self.responses_received = 0

        self.errors = 0

        self.findings.clear()

    # ===========================================================
    # Finish Scan
    # ===========================================================

    def finish_scan(
        self,
    ) -> None:
        """
        Finish scanner runtime.
        """

        self.finished_at = perf_counter()

    # ===========================================================
    # Scan Duration
    # ===========================================================

    def scan_duration(
        self,
    ) -> float:
        """
        Return scan duration in seconds.
        """

        if self.finished_at == 0.0:

            return perf_counter() - self.started_at

        return self.finished_at - self.started_at

    # ===========================================================
    # Record Error
    # ===========================================================

    def record_error(
        self,
    ) -> None:
        """
        Increase scanner error counter.
        """

        self.errors += 1

    # ===========================================================
    # Summary
    # ===========================================================

    def summary(
        self,
    ) -> dict[str, Any]:
        """
        Return scanner summary.
        """

        return {
            "scanner": self.__class__.__name__,
            "target": self.target,
            "requests": self.requests_sent,
            "responses": self.responses_received,
            "errors": self.errors,
            "findings": len(self.findings),
            "duration": round(
                self.scan_duration(),
                2,
            ),
        }

    # ===========================================================
    # Reset
    # ===========================================================

    def reset(
        self,
    ) -> None:
        """
        Reset scanner state.
        """

        self.findings.clear()

        self.started_at = 0.0

        self.finished_at = 0.0

        self.requests_sent = 0

        self.responses_received = 0

        self.errors = 0
        # ===========================================================

    # Run
    # ===========================================================

    def run(
        self,
    ) -> list[ScanResult]:
        """
        Scanner entry point.

        Must be implemented by child classes.
        """

        raise NotImplementedError(f"{self.__class__.__name__} must implement run().")

    # ===========================================================
    # Context Manager
    # ===========================================================

    def __enter__(
        self,
    ) -> "BaseScanner":

        self.start_scan()

        return self

    def __exit__(
        self,
        exc_type,
        exc,
        traceback,
    ) -> None:

        self.finish_scan()

        self.request.close()

    # ===========================================================
    # String Representation
    # ===========================================================

    def __repr__(
        self,
    ) -> str:

        return f"{self.__class__.__name__}" f"(target='{self.target}')"


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    class DemoScanner(BaseScanner):

        def run(
            self,
        ) -> list[ScanResult]:

            self.start_scan()

            finding = self.create_finding(
                vulnerable=False,
                severity="Info",
                confidence=0.0,
                description="BaseScanner self-test.",
            )

            self.add_finding(
                finding,
            )

            self.finish_scan()

            return self.findings

    scanner = DemoScanner(
        "https://example.com",
    )

    results = scanner.run()

    print("=" * 60)

    print("SentinelAI BaseScanner")

    print("=" * 60)

    print(scanner.summary())

    print()

    print(results)
