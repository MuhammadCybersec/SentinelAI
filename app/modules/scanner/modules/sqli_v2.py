"""
SentinelAI Production SQL Injection Scanner

Features
--------
- Error-Based SQL Injection
- Boolean-Based SQL Injection
- Time-Based SQL Injection
- UNION-Based SQL Injection
- DBMS Fingerprinting
- WAF Aware Payload Selection
- Evidence Collection
- Confidence Scoring
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import perf_counter

# from typing import Any

from app.modules.recon.scope_manager import ScopeManager
from app.modules.scanner.core.base_scanner import BaseScanner
from app.modules.scanner.core.response_analyzer import AnalysisResult
from app.modules.scanner.payloads.sql_payloads import get_payloads

# ==========================================================
# Metadata
# ==========================================================


@dataclass(slots=True)
class SQLScannerInfo:

    name: str = "SQL Injection"

    slug: str = "sqli"

    severity: str = "Critical"

    cwe: int = 89

    owasp: str = "A03:2021"

    description: str = (
        "Detects SQL Injection vulnerabilities using "
        "multiple production-grade techniques."
    )


# ==========================================================
# Result Model
# ==========================================================


@dataclass(slots=True)
class SQLFinding:

    vulnerable: bool = False

    url: str = ""

    parameter: str = ""

    payload: str = ""

    technique: str = ""

    dbms: str = ""

    evidence: list[str] = field(
        default_factory=list,
    )
    # ----------------------------------------------------------
    # Vulnerability Metadata
    # ----------------------------------------------------------

    severity: str = "Unknown"

    cwe: str = ""

    owasp: str = ""

    cvss: str = ""

    references: list[str] = field(
        default_factory=list,
    )

    remediation: str = ""

    analyzer: AnalysisResult | None = None


# ==========================================================
# Production SQL Scanner
# ==========================================================


class SQLiScanner(BaseScanner):

    def __init__(
        self,
        target: str,
        scope: ScopeManager | None = None,
    ) -> None:

        super().__init__(
            target=target,
            scope=scope,
        )

        self.info = SQLScannerInfo()

        self.payloads = get_payloads()

        self.findings: list[SQLFinding] = []

        self.detected_dbms: str | None = None
        self.baseline_response_time: float | None = None

        self.statistics = {
            "payloads": 0,
            "requests": 0,
            "vulnerabilities": 0,
            "errors": 0,
        }

    # ==========================================================
    # DBMS Fingerprinting
    # ==========================================================

    DBMS_ERRORS: dict[str, tuple[str, ...]] = {
        "MySQL": (
            "You have an error in your SQL syntax",
            "Warning: mysql",
            "MySQL server version",
            "mysqli_",
            "mysql_fetch",
            "SQL syntax.*MySQL",
        ),
        "PostgreSQL": (
            "PostgreSQL",
            "pg_query",
            "pg_exec",
            "pg_fetch",
            "PG::SyntaxError",
            "psql:",
        ),
        "Microsoft SQL Server": (
            "Microsoft SQL Server",
            "ODBC SQL Server Driver",
            "Unclosed quotation mark",
            "SQLServerException",
            "System.Data.SqlClient",
        ),
        "Oracle": (
            "ORA-",
            "Oracle error",
            "Oracle Database",
            "OCIError",
            "ORA-00933",
            "ORA-01756",
        ),
        "SQLite": (
            "SQLite",
            "sqlite3.",
            "SQLiteException",
            "OperationalError",
            'near "',
        ),
    }
    # ==========================================================
    # Time-Based SQL Injection Payloads
    # ==========================================================

    TIME_PAYLOADS: dict[str, tuple[str, ...]] = {
        "MySQL": (
            "' AND SLEEP(5)--",
            '" AND SLEEP(5)--',
            "' OR SLEEP(5)--",
        ),
        "PostgreSQL": (
            "'; SELECT pg_sleep(5)--",
            '"; SELECT pg_sleep(5)--',
        ),
        "Microsoft SQL Server": (
            "'; WAITFOR DELAY '0:0:5'--",
            "\"; WAITFOR DELAY '0:0:5'--",
        ),
        "Oracle": ("' AND DBMS_PIPE.RECEIVE_MESSAGE('A',5)--",),
    }

    # ==========================================================
    # Time-Based Payload Selection
    # ==========================================================

    def get_time_payloads(
        self,
        dbms: str | None = None,
    ) -> list[str]:
        """
        Return Time-Based SQL Injection payloads.

        If a DBMS has already been detected,
        only payloads for that DBMS are returned.
        Otherwise payloads for every supported
        database are returned.
        """

        if dbms is not None:
            return list(
                self.TIME_PAYLOADS.get(
                    dbms,
                    (),
                )
            )

        payloads: list[str] = []

        for values in self.TIME_PAYLOADS.values():
            payloads.extend(values)

        return payloads

    # ==========================================================
    # Smart Payload Selection
    # ==========================================================

    def get_smart_payloads(
        self,
    ) -> list[str]:
        """
        Return SQL Injection payloads based on the
        detected backend database.

        If DBMS is unknown, return every payload.
        """

        if self.detected_dbms is None:
            return self.get_all_payloads()

        dbms = self.detected_dbms.lower()

        payloads: list[str] = []

        for payload in self.get_all_payloads():

            lower = payload.lower()

            if "mysql" in dbms:

                if "sleep(" in lower or "benchmark(" in lower or "mysql" in lower:
                    payloads.append(payload)

            elif "postgres" in dbms:

                if "pg_sleep" in lower:
                    payloads.append(payload)

            elif "sql server" in dbms:

                if "waitfor" in lower:
                    payloads.append(payload)

            elif "oracle" in dbms:

                if "dbms_pipe" in lower or "utl_http" in lower:
                    payloads.append(payload)

            else:
                payloads.append(payload)

        if not payloads:
            return self.get_all_payloads()

        return payloads

    # ==========================================================

    # Baseline Response Time
    # ==========================================================

    def get_baseline_time(
        self,
    ) -> float:
        """
        Cache baseline response time.
        """

        if self.baseline_response_time is not None:
            return self.baseline_response_time

        start = perf_counter()

        response = self.request.send(
            method="GET",
            url=self.target,
        )

        if response is None:
            return 0.0

        self.baseline_response_time = perf_counter() - start

        return self.baseline_response_time

    # ==========================================================
    # Test Time-Based SQL Injection
    # ==========================================================

    def test_time_payload(
        self,
        payload: str,
    ) -> SQLFinding | None:
        """
        Test a single Time-Based SQL Injection payload.
        """

        # ----------------------------------------
        # Baseline Request
        # ----------------------------------------

        baseline_time = self.get_baseline_time()

        if baseline_time <= 0:
            self.errors += 1
            return None

        # ----------------------------------------
        # Injected Request
        # ----------------------------------------

        self.requests_sent += 1

        injected_start = perf_counter()

        response = self.request.send(
            method="GET",
            url=self.target,
            payload=payload,
        )

        injected_time = perf_counter() - injected_start

        if response is None:
            self.errors += 1
            return None

        self.responses_received += 1

        # ----------------------------------------
        # Time-Based Detection
        # ----------------------------------------

        if not self.detect_time_sqli(
            baseline_time,
            injected_time,
        ):
            return None

        # ----------------------------------------
        # Analyze Response
        # ----------------------------------------

        analysis = self.analyzer.analyze(
            response,
            payload,
        )

        finding = SQLFinding()

        finding.vulnerable = True
        finding.url = self.target
        finding.payload = payload
        finding.technique = "Time-Based"
        finding.dbms = self.detected_dbms or "Unknown"
        finding.analyzer = analysis

        finding.evidence.append(f"Baseline Response: {baseline_time:.2f}s")

        finding.evidence.append(f"Injected Response: {injected_time:.2f}s")

        finding.evidence.append(f"Delay: {injected_time - baseline_time:.2f}s")

        if finding.analyzer is not None:
            finding.analyzer.risk.confidence = max(
                finding.analyzer.risk.confidence,
                0.95,
            )

        self.statistics["vulnerabilities"] += 1

        return finding

    def detect_dbms(
        self,
        response_text: str,
    ) -> str | None:
        """
        Detect backend DBMS from SQL error messages.
        """

        body = response_text.lower()

        for dbms, signatures in self.DBMS_ERRORS.items():

            for signature in signatures:

                if signature.lower() in body:

                    self.detected_dbms = dbms

                    return dbms

        return None

    # ==========================================================
    # SQL Error Verification
    # ==========================================================

    def has_sql_error(
        self,
        response_text: str,
    ) -> bool:
        """
        Check whether the response contains a known SQL
        database error message.
        """

        return self.detect_dbms(response_text) is not None

    # ==========================================================
    # Boolean-Based SQLi Detection
    # ==========================================================

    def detect_boolean_sqli(
        self,
        normal_response: str,
        injected_response: str,
    ) -> bool:
        """
        Compare two responses and determine whether a
        Boolean-Based SQL Injection may exist.
        """

        normal = normal_response.strip()
        injected = injected_response.strip()

        if not normal or not injected:
            return False

        if normal == injected:
            return False

        length_difference = abs(len(normal) - len(injected))

        if length_difference > 50:
            return True

        return False

    # ==========================================================
    # Time-Based SQLi Detection
    # ==========================================================

    def detect_time_sqli(
        self,
        baseline_time: float,
        injected_time: float,
        threshold: float = 5.0,
    ) -> bool:
        """
        Detect a possible Time-Based SQL Injection by
        comparing response times.
        """

        if baseline_time <= 0:
            return False

        if injected_time <= 0:
            return False

        delay = injected_time - baseline_time

        return delay >= threshold

    # ==========================================================
    # Confidence Scoring
    # ==========================================================

    def calculate_confidence(
        self,
        *,
        has_error: bool = False,
        boolean_detected: bool = False,
        time_detected: bool = False,
        dbms: str | None = None,
    ) -> float:
        """
        Calculate confidence score for the detected
        SQL Injection finding.
        """

        score = 0.0

        if has_error:
            score += 0.45

        if boolean_detected:
            score += 0.30

        if time_detected:
            score += 0.20

        if dbms is not None:
            score += 0.05

        return min(score, 1.0)

    # ==========================================================

    # Payload Engine
    # ==========================================================

    def get_all_payloads(
        self,
    ) -> list[str]:
        """
        Return all SQL Injection payloads.
        """

        return list(self.payloads)

    def payload_count(
        self,
    ) -> int:
        """
        Total payload count.
        """

        return len(self.payloads)

    def iter_payloads(
        self,
    ):
        """
        Iterate through every payload.
        """

        for payload in self.payloads:

            self.statistics["payloads"] += 1

            yield payload

    # ==========================================================
    # Boolean-Based Payload Pair
    # ==========================================================

    def get_boolean_payload_pair(
        self,
    ) -> tuple[str, str]:
        """
        Return payloads for Boolean-Based SQL Injection testing.
        """

        true_payload = "' AND 1=1--"

        false_payload = "' AND 1=2--"

        return (
            true_payload,
            false_payload,
        )

    # ==========================================================
    # Compare Boolean Responses
    # ==========================================================

    def compare_boolean_responses(
        self,
        true_response,
        false_response,
    ) -> bool:
        """
        Compare responses from TRUE and FALSE payloads.
        Returns True when a meaningful difference is detected.
        """

        if true_response is None or false_response is None:
            return False

        true_body = getattr(true_response, "text", "")
        false_body = getattr(false_response, "text", "")

        if true_body == false_body:
            return False

        length_difference = abs(len(true_body) - len(false_body))

        if length_difference > 50:
            return True

        return self.detect_boolean_sqli(
            true_body,
            false_body,
        )

    # ==========================================================
    # Response Evaluation
    # ==========================================================

    def evaluate_response(
        self,
        url: str,
        payload: str,
        response,
    ) -> SQLFinding | None:
        """
        Analyze a response after sending a SQL payload.
        """

        analysis = self.analyzer.analyze(
            response,
            payload,
        )

        body = ""

        if hasattr(response, "text"):

            body = response.text

        dbms = self.detect_dbms(body)

        has_error = dbms is not None

        if not has_error:
            return None

        confidence = self.calculate_confidence(
            has_error=has_error,
            boolean_detected=False,
            time_detected=False,
            dbms=dbms,
        )

        finding = SQLFinding()

        finding.vulnerable = True

        finding.url = url

        finding.payload = payload

        finding.technique = "Error-Based"

        finding.dbms = dbms

        finding.analyzer = analysis

        analysis.risk.confidence = confidence

        finding.evidence.append(f"Detected database: {dbms}")

        self.statistics["vulnerabilities"] += 1

        return finding

    # ==========================================================
    # Merge Duplicate Findings
    # ==========================================================

    def merge_findings(
        self,
        findings: list[SQLFinding],
    ) -> list[SQLFinding]:
        """
        Merge duplicate SQL Injection findings.

        Duplicate criteria:
            - Same URL
            - Same Payload
            - Same DBMS
        """

        merged: dict[tuple[str, str, str], SQLFinding] = {}

        for finding in findings:

            key = (
                finding.url,
                finding.payload,
                finding.dbms,
            )

            if key not in merged:

                merged[key] = finding
                continue

            current = merged[key]

            # --------------------------------------
            # Merge Technique
            # --------------------------------------

            techniques = {
                t.strip()
                for t in (current.technique + "," + finding.technique).split(",")
            }

            current.technique = ", ".join(sorted(techniques))

            # --------------------------------------
            # Merge Evidence
            # --------------------------------------

            for evidence in finding.evidence:

                if evidence not in current.evidence:

                    current.evidence.append(evidence)

            # --------------------------------------
            # Keep Highest Confidence
            # --------------------------------------

            if current.analyzer is not None and finding.analyzer is not None:
                current.analyzer.risk.confidence = max(
                    current.analyzer.risk.confidence,
                    finding.analyzer.risk.confidence,
                )

        return list(merged.values())

    # ==========================================================
    # Enrich Finding
    # ==========================================================

    def enrich_finding(
        self,
        finding: SQLFinding,
    ) -> SQLFinding:
        """
        Add production vulnerability metadata.
        """

        if finding.analyzer is not None:

            score = finding.analyzer.risk.score

            if score >= 90:
                severity = "Critical"
            elif score >= 70:
                severity = "High"
            elif score >= 40:
                severity = "Medium"
            else:
                severity = "Low"

        else:
            severity = "Medium"

        # ------------------------------------------------------
        # Standard Metadata
        # ------------------------------------------------------

        finding.severity = severity

        finding.cwe = "CWE-89"

        finding.owasp = "OWASP Top 10 2021 - A03: Injection"

        finding.cvss = "CVSS v3.1"

        finding.references = [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ]

        finding.remediation = (
            "Use parameterized queries (Prepared Statements), "
            "avoid dynamic SQL, validate user input, "
            "and apply least-privilege database accounts."
        )

        return finding

    # ==========================================================
    # Main Scan
    # ==========================================================

    def scan(
        self,
    ) -> list[SQLFinding]:
        """
        Execute the complete SQL Injection scan.
        """

        self.started_at = perf_counter()

        self.findings.clear()

        self.statistics["payloads"] = 0
        self.statistics["requests"] = 0
        self.statistics["vulnerabilities"] = 0
        self.statistics["errors"] = 0

        # ------------------------------------------------------
        # Error-Based / Boolean-Based
        # ------------------------------------------------------

        for payload in self.get_smart_payloads():

            self.statistics["payloads"] += 1

            try:

                finding = self.test_payload(payload)

                if finding is not None:
                    finding = self.enrich_finding(
                        finding,
                    )
                    self.findings.append(finding)

            except Exception:

                self.statistics["errors"] += 1

                self.errors += 1

        # ------------------------------------------------------
        # Time-Based
        # ------------------------------------------------------

        for payload in self.get_time_payloads(
            self.detected_dbms,
        ):

            self.statistics["payloads"] += 1

            try:

                finding = self.test_time_payload(payload)

                if finding is not None:
                    finding = self.enrich_finding(
                        finding,
                    )
                    self.findings.append(finding)

            except Exception:

                self.statistics["errors"] += 1

                self.errors += 1

        # ------------------------------------------------------
        # Finish
        # ------------------------------------------------------
        self.findings = self.merge_findings(
            self.findings,
        )

        self.finished_at = perf_counter()

        return self.findings

    print("[+] SQLiScanner started")

    # ==========================================================
    # Test Single Payload
    # ==========================================================

    def test_payload(
        self,
        payload: str,
    ) -> SQLFinding | None:
        """
        Send one SQL Injection payload and evaluate
        the returned response.
        """

        self.requests_sent += 1

        response = self.request.send(
            method="GET",
            url=self.target,
            payload=payload,
        )

        if response is None:
            self.errors += 1
            return None

        self.responses_received += 1

        finding = self.evaluate_response(
            self.target,
            payload,
            response,
        )

        # ----------------------------------------
        # Boolean-Based SQLi Verification
        # ----------------------------------------

        true_payload, false_payload = self.get_boolean_payload_pair()

        true_response = self.request.send(
            method="GET",
            url=self.target,
            payload=true_payload,
        )

        false_response = self.request.send(
            method="GET",
            url=self.target,
            payload=false_payload,
        )

        if true_response is not None and false_response is not None:
            if self.validate_boolean_detection(
                true_response,
                false_response,
            ):

                if finding is not None and finding.analyzer is not None:
                    finding.technique = "Boolean-Based"

                    finding.analyzer.risk.confidence = min(
                        finding.analyzer.risk.confidence + 0.20,
                        1.0,
                    )

                    finding.evidence.append(
                        "Boolean SQL Injection response difference detected."
                    )

    # ==========================================================
    # False Positive Filter
    # ==========================================================

    def is_false_positive(
        self,
        true_response,
        false_response,
    ) -> bool:
        """
        Filter obvious false positives before reporting
        a Boolean-Based SQL Injection finding.
        """

        if true_response is None or false_response is None:
            return True

        if getattr(true_response, "status_code", 0) != getattr(
            false_response, "status_code", 0
        ):
            return False

        true_body = getattr(true_response, "text", "")
        false_body = getattr(false_response, "text", "")

        if true_body == false_body:
            return True

        length_difference = abs(len(true_body) - len(false_body))

        if length_difference < 20:
            return True

        return False

    # ==========================================================
    # Advanced Response Similarity
    # ==========================================================

    def calculate_similarity(
        self,
        text1: str,
        text2: str,
    ) -> float:
        """
        Calculate similarity between two HTTP responses.
        Returns a value between 0.0 and 1.0.
        """

        from difflib import SequenceMatcher

        if not text1 and not text2:
            return 1.0

        return SequenceMatcher(
            None,
            text1,
            text2,
        ).ratio()

    # ==========================================================
    # Advanced Boolean Validation
    # ==========================================================

    def validate_boolean_detection(
        self,
        true_response,
        false_response,
    ) -> bool:
        """
        Validate Boolean-Based SQL Injection by comparing
        status codes, response sizes and similarity ratio.
        """

        if true_response is None or false_response is None:
            return False

        if getattr(true_response, "status_code", 0) != getattr(
            false_response, "status_code", 0
        ):
            return True

        true_body = getattr(true_response, "text", "")
        false_body = getattr(false_response, "text", "")

        similarity = self.calculate_similarity(
            true_body,
            false_body,
        )

        length_difference = abs(len(true_body) - len(false_body))

        if similarity < 0.95:
            return True

        if length_difference > 50:
            return True

        return False
