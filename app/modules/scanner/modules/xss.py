"""
SentinelAI - Production XSS Scanner

Features
--------
- Reflected XSS
- Stored XSS (Future)
- DOM XSS Hooks (Future)
- GET parameter scanning
- POST parameter scanning
- Multiple payload support
- Reflection detection
- Context-aware analysis
- Confidence scoring
"""

from __future__ import annotations

import time
from typing import Any

from app.modules.scanner.payloads.xss_payloads import get_payloads

from app.modules.scanner.core.base_scanner import BaseScanner
from app.modules.scanner.core.request_engine import RequestEngine
from app.modules.scanner.core.response_analyzer_v2 import ResponseAnalyzer


class XSSScanner(BaseScanner):
    """
    SentinelAI Production XSS Scanner.
    """

    NAME = "Cross-Site Scripting"

    SLUG = "xss"

    SEVERITY = "High"

    CWE = 79

    OWASP = "A03:2021"

    def __init__(
        self,
        request_engine: RequestEngine,
        analyzer: ResponseAnalyzer,
    ) -> None:

        super().__init__(
            target="",
        )

        self.request_engine = request_engine

        self.analyzer = analyzer

        self.payloads = get_payloads()

        self.timeout = 10

        self.max_payloads = len(self.payloads)

        self.total_requests = 0

        self.start_time = 0.0

        self.end_time = 0.0

    @property
    def scanner_name(
        self,
    ) -> str:

        return self.NAME

    def reset(
        self,
    ) -> None:
        """
        Reset runtime statistics.
        """

        self.total_requests = 0

        self.start_time = 0.0

        self.end_time = 0.0

    def runtime(
        self,
    ) -> float:

        if self.end_time == 0:
            return 0.0

        return round(
            self.end_time - self.start_time,
            2,
        )
        # =======================================================

    # Collect Parameters
    # =======================================================

    def _collect_parameters(
        self,
        target: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Collect GET and POST parameters.
        """

        parameters: list[dict[str, Any]] = []

        for parameter in target.get("get_params", []):
            parameters.append(
                {
                    "location": "GET",
                    "name": parameter,
                }
            )

        for parameter in target.get("post_params", []):
            parameters.append(
                {
                    "location": "POST",
                    "name": parameter,
                }
            )

        return parameters

    # =======================================================
    # Payload Iterator
    # =======================================================

    def _payload_iterator(
        self,
    ):
        """
        Yield payloads one by one.
        """

        for payload in self.payloads:
            if isinstance(payload, dict):
                yield payload

            else:
                yield {
                    "payload": payload,
                    "context": "generic",
                }

    # =======================================================
    # Build Test Case
    # =======================================================

    def _build_test_case(
        self,
        target: dict[str, Any],
        parameter: dict[str, Any],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Build a single XSS test case.
        """

        return {
            "url": target["url"],
            "method": parameter["location"],
            "parameter": parameter["name"],
            "payload": payload["payload"],
            "context": payload.get(
                "context",
                "generic",
            ),
        }

    # =======================================================
    # Prepare Scan
    # =======================================================

    def _prepare_scan(
        self,
        target: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Generate all scan test cases.
        """

        test_cases = []

        parameters = self._collect_parameters(
            target,
        )

        for parameter in parameters:
            for payload in self._payload_iterator():
                test_cases.append(
                    self._build_test_case(
                        target,
                        parameter,
                        payload,
                    )
                )

        return test_cases
        # =======================================================

    # Execute GET Test
    # =======================================================

    def _execute_get(
        self,
        test_case: dict[str, Any],
    ):
        """
        Execute one GET XSS test.
        """

        params = {
            test_case["parameter"]: test_case["payload"],
        }

        self.total_requests += 1

        return self.request_engine.send(
            method="GET",
            url=test_case["url"],
            params=params,
            timeout=self.timeout,
        )

    # =======================================================
    # Execute POST Test
    # =======================================================

    def _execute_post(
        self,
        test_case: dict[str, Any],
    ):
        """
        Execute one POST XSS test.
        """

        data = {
            test_case["parameter"]: test_case["payload"],
        }

        self.total_requests += 1

        return self.request_engine.send(
            method="POST",
            url=test_case["url"],
            data=data,
            timeout=self.timeout,
        )

    # =======================================================
    # Execute Test
    # =======================================================

    def _execute_test(
        self,
        test_case: dict[str, Any],
    ):
        """
        Execute a single test case.
        """

        if test_case["method"] == "GET":
            return self._execute_get(
                test_case,
            )

        return self._execute_post(
            test_case,
        )

    # =======================================================
    # Run Test Cases
    # =======================================================

    def _run_test_cases(
        self,
        test_cases: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Execute every prepared test case.
        """

        responses = []

        for test_case in test_cases:
            try:
                response = self._execute_test(
                    test_case,
                )

                responses.append(
                    {
                        "test_case": test_case,
                        "response": response,
                    }
                )

            except Exception:
                continue

        return responses
        # =======================================================

    # Analyze Response
    # =======================================================

    def _analyze_response(
        self,
        test_case: dict[str, Any],
        response,
    ) -> dict[str, Any]:
        """
        Analyze one HTTP response.
        """

        analysis = self.analyzer.analyze(
            response=response,
        )

        return {
            "test_case": test_case,
            "response": response,
            "analysis": analysis,
        }

    # =======================================================
    # Analyze All Responses
    # =======================================================

    def _analyze_responses(
        self,
        responses: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Analyze every collected response.
        """

        analyzed = []

        for item in responses:
            try:
                analyzed.append(
                    self._analyze_response(
                        item["test_case"],
                        item["response"],
                    )
                )

            except Exception:
                continue

        return analyzed

    # =======================================================
    # Reflection Check
    # =======================================================

    def _is_reflected(
        self,
        analysis: dict[str, Any],
    ) -> bool:
        """
        Check whether payload is reflected.
        """

        return bool(
            analysis.get(
                "reflected",
                False,
            )
        )

    # =======================================================
    # Candidate Detection
    # =======================================================

    def _find_candidates(
        self,
        analyzed_results: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Extract possible XSS findings.
        """

        candidates = []

        for result in analyzed_results:
            if self._is_reflected(
                result["analysis"],
            ):
                candidates.append(result)

        return candidates
        # =======================================================

    # Confidence Score
    # =======================================================

    def _calculate_confidence(
        self,
        analysis: dict[str, Any],
    ) -> float:
        """
        Calculate confidence score.
        """

        score = 0.0

        if analysis.get("reflected", False):
            score += 0.50

        if analysis.get("reflection_count", 0) > 0:
            score += 0.20

        if analysis.get("context") in (
            "html",
            "attribute",
            "script",
        ):
            score += 0.20

        if analysis.get("encoding") == "none":
            score += 0.10

        return round(min(score, 1.0), 2)

    # =======================================================
    # Severity
    # =======================================================

    def _calculate_severity(
        self,
        confidence: float,
    ) -> str:

        if confidence >= 0.90:
            return "Critical"

        if confidence >= 0.75:
            return "High"

        if confidence >= 0.50:
            return "Medium"

        return "Low"

    # =======================================================
    # Build Finding
    # =======================================================

    def _build_finding(
        self,
        candidate: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Convert candidate into finding.
        """

        analysis = candidate["analysis"]

        confidence = self._calculate_confidence(
            analysis,
        )

        return {
            "scanner": self.NAME,
            "slug": self.SLUG,
            "severity": self._calculate_severity(
                confidence,
            ),
            "confidence": confidence,
            "url": candidate["test_case"]["url"],
            "method": candidate["test_case"]["method"],
            "parameter": candidate["test_case"]["parameter"],
            "payload": candidate["test_case"]["payload"],
            "cwe": self.CWE,
            "owasp": self.OWASP,
            "analysis": analysis,
        }

    # =======================================================
    # Build Findings
    # =======================================================

    def _build_findings(
        self,
        candidates: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Convert all candidates into findings.
        """

        findings = []

        for candidate in candidates:
            findings.append(
                self._build_finding(
                    candidate,
                )
            )

        return findings
        # =======================================================

    # Main Scan
    # =======================================================

    def scan(
        self,
        target: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Execute complete XSS scan.
        """

        self.reset()

        self.start_time = time.time()

        try:
            test_cases = self._prepare_scan(
                target,
            )

            if not test_cases:
                self.end_time = time.time()

                return []

            responses = self._run_test_cases(
                test_cases,
            )

            analyzed = self._analyze_responses(
                responses,
            )

            candidates = self._find_candidates(
                analyzed,
            )

            findings = self._build_findings(
                candidates,
            )

            self.end_time = time.time()

            return findings

        except Exception as exc:
            self.end_time = time.time()

            print(f"[XSS] Scan failed: {exc}")

            return []
        # =======================================================

    # Statistics
    # =======================================================

    def statistics(
        self,
    ) -> dict[str, Any]:
        """
        Scanner runtime statistics.
        """

        return {
            "scanner": self.NAME,
            "slug": self.SLUG,
            "requests": self.total_requests,
            "payloads": self.max_payloads,
            "runtime": self.runtime(),
        }

    # =======================================================
    # Information
    # =======================================================

    def info(
        self,
    ) -> dict[str, Any]:
        """
        Scanner metadata.
        """

        return {
            "name": self.NAME,
            "slug": self.SLUG,
            "severity": self.SEVERITY,
            "cwe": self.CWE,
            "owasp": self.OWASP,
        }


# ==========================================================
# Self Test
# ==========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("SentinelAI XSS Scanner")
    print("=" * 60)

    print()
    print("Scanner Information")
    print("-------------------")

    print(f"Name      : {XSSScanner.NAME}")
    print(f"Slug      : {XSSScanner.SLUG}")
    print(f"Severity  : {XSSScanner.SEVERITY}")
    print(f"CWE       : {XSSScanner.CWE}")
    print(f"OWASP     : {XSSScanner.OWASP}")

    print()
    print("Production XSS Scanner Loaded Successfully.")
