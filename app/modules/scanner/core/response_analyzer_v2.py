"""
===========================================================
Project : Sentinel AI
Module  : Response Analyzer
File ID : SCANNER-CORE-RESPONSE-001
Version : 2.0.0
===========================================================

Description:

Production Response Analyzer.

Responsible for:

• Response Analysis
• Reflection Detection
• SQL Error Detection
• Stack Trace Detection
• Security Header Analysis
• WAF Detection
• Similarity Analysis
• Technology Indicators

===========================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field

import re

# ===========================================================
# Analysis Result
# ===========================================================


@dataclass(slots=True)
class AnalysisResult:
    """
    Normalized analysis object returned to scanners.
    """

    status_code: int = 0

    title: str = ""

    server: str = ""

    content_type: str = ""

    content_length: int = 0

    response_time: float = 0.0

    reflected: bool = False

    reflection_count: int = 0

    sql_errors: list[str] = field(
        default_factory=list,
    )

    stack_traces: list[str] = field(
        default_factory=list,
    )

    waf_detected: bool = False

    waf_name: str = ""

    technologies: list[str] = field(
        default_factory=list,
    )

    security_headers: list[str] = field(
        default_factory=list,
    )

    interesting_headers: list[str] = field(
        default_factory=list,
    )

    interesting_patterns: list[str] = field(
        default_factory=list,
    )

    confidence: float = 0.0


# ===========================================================
# Response Analyzer
# ===========================================================


class ResponseAnalyzer:
    """
    SentinelAI Production Response Analyzer.
    """

    def __init__(self) -> None:

        self.sql_patterns: list[str] = []

        self.stack_patterns: list[str] = []

        self.waf_patterns: list[str] = []

        self.security_headers: list[str] = []

        self.interesting_patterns: list[str] = []

        self._load_patterns()
        # ===========================================================

    # Load Detection Patterns
    # ===========================================================

    def _load_patterns(
        self,
    ) -> None:
        """
        Load built-in detection patterns.
        """

        # -------------------------------------------------------
        # SQL Error Patterns
        # -------------------------------------------------------

        self.sql_patterns = [
            r"sql syntax",
            r"mysql",
            r"mariadb",
            r"postgresql",
            r"pg_query",
            r"sqlite",
            r"sqlite3",
            r"oracle error",
            r"ora-\d+",
            r"odbc",
            r"jdbc",
            r"sql server",
            r"unclosed quotation mark",
            r"syntax error",
            r"native client",
            r"supplied argument is not a valid mysql",
            r"warning.*mysql",
            r"you have an error in your sql syntax",
        ]

        # -------------------------------------------------------
        # Stack Trace Patterns
        # -------------------------------------------------------

        self.stack_patterns = [
            r"traceback",
            r"exception",
            r"stack trace",
            r"fatal error",
            r"nullpointerexception",
            r"runtimeexception",
            r"system\.exception",
            r"call stack",
            r"at .*\.java",
            r"line \d+",
            r"php warning",
            r"php notice",
            r"undefined index",
            r"undefined variable",
        ]

        # -------------------------------------------------------
        # WAF Patterns
        # -------------------------------------------------------

        self.waf_patterns = [
            r"cloudflare",
            r"sucuri",
            r"akamai",
            r"imperva",
            r"f5",
            r"aws waf",
            r"barracuda",
            r"incapsula",
            r"mod_security",
            r"modsecurity",
        ]

        # -------------------------------------------------------
        # Security Headers
        # -------------------------------------------------------

        self.security_headers = [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "strict-transport-security",
            "referrer-policy",
            "permissions-policy",
            "cross-origin-resource-policy",
            "cross-origin-opener-policy",
            "cross-origin-embedder-policy",
        ]

        # -------------------------------------------------------
        # Interesting Patterns
        # -------------------------------------------------------

        self.interesting_patterns = [
            r"\.git",
            r"\.env",
            r"backup",
            r"config",
            r"debug",
            r"swagger",
            r"openapi",
            r"admin",
            r"phpinfo",
            r"internal",
            r"staging",
            r"dev",
            r"test",
            r"api",
        ]
        # ===========================================================

    # Analyze Response
    # ===========================================================

    def analyze(
        self,
        response,
    ) -> AnalysisResult:
        """
        Analyze a normalized HTTP response.
        """

        result = AnalysisResult()

        # -------------------------------------------------------
        # Basic Information
        # -------------------------------------------------------

        result.status_code = response.status_code

        result.title = response.title

        result.server = response.server

        result.content_type = response.content_type

        result.content_length = response.content_length

        result.response_time = response.elapsed

        # -------------------------------------------------------
        # Advanced Analysis
        # -------------------------------------------------------

        self._detect_sql_errors(
            response.body,
            result,
        )

        self._detect_stack_traces(
            response.body,
            result,
        )

        self._detect_security_headers(
            response.headers,
            result,
        )

        self._detect_waf(
            response,
            result,
        )

        self._detect_interesting_patterns(
            response.body,
            result,
        )
        self.analyze_headers(
            response.headers,
            result,
        )

        self._calculate_confidence(
            result,
        )

        return result

    # ===========================================================
    # Extract HTML Title
    # ===========================================================

    def extract_title(
        self,
        html: str,
    ) -> str:
        """
        Extract HTML title.
        """

        match = re.search(
            r"<title>(.*?)</title>",
            html,
            re.IGNORECASE | re.DOTALL,
        )

        if match:

            return match.group(
                1,
            ).strip()

        return ""

    # ===========================================================
    # Detect SQL Errors
    # ===========================================================

    def _detect_sql_errors(
        self,
        body: str,
        result: AnalysisResult,
    ) -> None:

        text = body.lower()

        for pattern in self.sql_patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE,
            ):

                result.sql_errors.append(
                    pattern,
                )

    # ===========================================================
    # Detect Stack Traces
    # ===========================================================

    def _detect_stack_traces(
        self,
        body: str,
        result: AnalysisResult,
    ) -> None:

        text = body.lower()

        for pattern in self.stack_patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE,
            ):

                result.stack_traces.append(
                    pattern,
                )
        # ===========================================================

    # Reflection Detection
    # ===========================================================

    def detect_reflection(
        self,
        payload: str,
        body: str,
        result: AnalysisResult,
    ) -> None:
        """
        Detect reflected payload occurrences.
        """

        if not payload or not body:
            return

        count = body.count(payload)

        if count > 0:
            result.reflected = True
            result.reflection_count = count

    # ===========================================================
    # Detect Security Headers
    # ===========================================================

    def _detect_security_headers(
        self,
        headers: dict[str, str],
        result: AnalysisResult,
    ) -> None:
        """
        Detect security headers present in response.
        """

        header_names = {key.lower() for key in headers.keys()}

        for header in self.security_headers:

            if header in header_names:

                result.security_headers.append(
                    header,
                )

    # ===========================================================
    # Detect WAF
    # ===========================================================

    def _detect_waf(
        self,
        response,
        result: AnalysisResult,
    ) -> None:
        """
        Detect common WAF products.
        """

        text = (response.body + "\n" + str(response.headers)).lower()

        for pattern in self.waf_patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE,
            ):

                result.waf_detected = True

                result.waf_name = pattern

                break

    # ===========================================================
    # Detect Interesting Patterns
    # ===========================================================

    def _detect_interesting_patterns(
        self,
        body: str,
        result: AnalysisResult,
    ) -> None:
        """
        Detect interesting keywords inside response.
        """

        text = body.lower()

        for pattern in self.interesting_patterns:

            if re.search(
                pattern,
                text,
                re.IGNORECASE,
            ):

                result.interesting_patterns.append(
                    pattern,
                )
        # ===========================================================

    # Compare Responses
    # ===========================================================

    def compare_responses(
        self,
        first,
        second,
    ) -> float:
        """
        Compare two response bodies.

        Returns similarity percentage.
        """

        from difflib import SequenceMatcher

        return SequenceMatcher(
            None,
            first.body,
            second.body,
        ).ratio()

    # ===========================================================
    # Length Difference
    # ===========================================================

    def length_difference(
        self,
        first,
        second,
    ) -> int:
        """
        Difference in response length.
        """

        return abs(first.content_length - second.content_length)

    # ===========================================================
    # Is Different
    # ===========================================================

    def is_different(
        self,
        first,
        second,
        threshold: float = 0.95,
    ) -> bool:
        """
        Decide whether two responses are different.
        """

        similarity = self.compare_responses(
            first,
            second,
        )

        return similarity < threshold

    # ===========================================================
    # Confidence Score
    # ===========================================================

    def _calculate_confidence(
        self,
        result: AnalysisResult,
    ) -> None:
        """
        Calculate confidence score.
        """

        score = 0.0

        if result.reflected:

            score += 0.35

        if result.sql_errors:

            score += 0.35

        if result.stack_traces:

            score += 0.10

        if result.waf_detected:

            score += 0.05

        if result.interesting_patterns:

            score += 0.10

        if result.security_headers:

            score += 0.05

        result.confidence = round(
            min(
                score,
                1.0,
            ),
            2,
        )

    # ===========================================================
    # Suspicious Response
    # ===========================================================

    def is_suspicious(
        self,
        result: AnalysisResult,
    ) -> bool:
        """
        Decide whether response looks suspicious.
        """

        return result.confidence >= 0.50
        # ===========================================================

    # Technology Detection
    # ===========================================================

    def detect_technology(
        self,
        headers: dict[str, str],
        result: AnalysisResult,
    ) -> None:
        """
        Detect technologies from HTTP headers.
        """

        server = headers.get(
            "server",
            "",
        )

        powered_by = headers.get(
            "x-powered-by",
            "",
        )

        if server:

            result.server = server

            result.technologies.append(
                server,
            )

        if powered_by:

            result.technologies.append(
                powered_by,
            )

    # ===========================================================
    # Missing Security Headers
    # ===========================================================

    def missing_security_headers(
        self,
        headers: dict[str, str],
    ) -> list[str]:
        """
        Return missing security headers.
        """

        existing = {key.lower() for key in headers.keys()}

        missing = []

        for header in self.security_headers:

            if header not in existing:

                missing.append(
                    header,
                )

        return missing

    # ===========================================================
    # Interesting Headers
    # ===========================================================

    def detect_interesting_headers(
        self,
        headers: dict[str, str],
        result: AnalysisResult,
    ) -> None:
        """
        Detect interesting HTTP headers.
        """

        interesting = [
            "server",
            "x-powered-by",
            "x-runtime",
            "x-generator",
            "x-aspnet-version",
            "via",
            "cf-cache-status",
            "cf-ray",
            "x-cache",
            "x-served-by",
        ]

        lower_headers = {k.lower(): v for k, v in headers.items()}

        for header in interesting:

            if header in lower_headers:

                result.interesting_headers.append(f"{header}: {lower_headers[header]}")

    # ===========================================================
    # Analyze Headers
    # ===========================================================

    def analyze_headers(
        self,
        headers: dict[str, str],
        result: AnalysisResult,
    ) -> None:
        """
        Analyze all response headers.
        """

        self.detect_technology(
            headers,
            result,
        )

        self.detect_interesting_headers(
            headers,
            result,
        )

        result.interesting_patterns.extend(
            self.missing_security_headers(
                headers,
            )
        )
        # ===========================================================

    # Risk Level
    # ===========================================================

    def risk_level(
        self,
        result: AnalysisResult,
    ) -> str:
        """
        Calculate overall risk level.
        """

        score = result.confidence

        if score >= 0.90:
            return "Critical"

        if score >= 0.70:
            return "High"

        if score >= 0.50:
            return "Medium"

        if score >= 0.30:
            return "Low"

        return "Informational"

    # ===========================================================
    # Summary
    # ===========================================================

    def summary(
        self,
        result: AnalysisResult,
    ) -> dict[str, object]:
        """
        Return summarized analysis.
        """

        return {
            "status_code": result.status_code,
            "title": result.title,
            "server": result.server,
            "risk": self.risk_level(result),
            "confidence": result.confidence,
            "reflected": result.reflected,
            "reflection_count": result.reflection_count,
            "sql_errors": len(result.sql_errors),
            "stack_traces": len(result.stack_traces),
            "waf_detected": result.waf_detected,
            "waf_name": result.waf_name,
            "technologies": result.technologies,
            "security_headers": result.security_headers,
            "interesting_headers": result.interesting_headers,
            "interesting_patterns": result.interesting_patterns,
        }

    # ===========================================================
    # Reset Result
    # ===========================================================

    def reset(
        self,
    ) -> AnalysisResult:
        """
        Create a fresh AnalysisResult.
        """

        return AnalysisResult()

    # ===========================================================
    # Analyzer Information
    # ===========================================================

    @staticmethod
    def version() -> str:
        """
        Analyzer version.
        """

        return "2.0.0"

    # ===========================================================
    # Temporary Test
    # ===========================================================


if __name__ == "__main__":

    analyzer = ResponseAnalyzer()

    print("=" * 60)
    print("SentinelAI Response Analyzer")
    print("=" * 60)

    print("Version :", analyzer.version())

    result = analyzer.reset()

    print("Risk :", analyzer.risk_level(result))

    print("Summary :")

    print(
        analyzer.summary(
            result,
        )
    )
