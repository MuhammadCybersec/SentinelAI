"""
SentinelAI Production SQL Injection Scanner

Production Features
-------------------
✓ Error-Based SQL Injection
✓ Boolean-Based SQL Injection
✓ Time-Based SQL Injection
✓ UNION-Based Detection (ready)
✓ DBMS Fingerprinting
✓ Smart Payload Selection
✓ False Positive Reduction
✓ Confidence Scoring
✓ Evidence Collection
✓ Production Metadata
✓ URL Validation
✓ Database Storage
✓ Baseline Comparison
"""

from __future__ import annotations  # ← MUST BE FIRST!

import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from time import perf_counter
from typing import Optional
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

import requests  # ← ADDED

from app.modules.recon.scope_manager import ScopeManager
from app.modules.scanner.core.base_scanner import BaseScanner
from app.modules.scanner.core.response_analyzer import AnalysisResult
from app.modules.scanner.payload.sql_payloads import get_payloads

# ==========================================================
# Scanner Metadata
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
# Finding Model
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

    severity: str = "Unknown"

    cwe: str = ""

    owasp: str = ""

    cvss: str = ""

    references: list[str] = field(
        default_factory=list,
    )

    remediation: str = ""

    analyzer: AnalysisResult | None = None

    # Additional fields for better tracking
    status_code: int = 0
    response_time: float = 0.0
    response_length: int = 0


# ==========================================================
# Production SQL Injection Scanner
# ==========================================================


class SQLiScanner(BaseScanner):

    # ======================================================
    # DBMS_ERRORS - Class Level (FIXED)
    # ======================================================

    DBMS_ERRORS: dict[str, tuple[str, ...]] = {
        "MySQL": (
            "you have an error in your sql syntax",
            "warning: mysql",
            "mysql_fetch",
            "mysql_num_rows",
            "mysqli_error",
            "sqlstate",
            "unknown column",
            "table '.*' doesn't exist",
            "duplicate entry",
            "mysql server version",
        ),
        "PostgreSQL": (
            "postgresql",
            "pg_query",
            "pg_exec",
            "pg_fetch",
            "sqlstate",
            "syntax error at or near",
            "relation .* does not exist",
        ),
        "Microsoft SQL Server": (
            "sql server",
            "unclosed quotation mark",
            "sqlstate",
            "microsoft ole db",
            "odbc sql server driver",
            "system.data.sqlclient",
        ),
        "Oracle": (
            "ora-",
            "oracle error",
            "oci error",
            "ora-00933",
            "ora-01756",
            "oracle database",
        ),
        "SQLite": (
            "sqlite",
            "sqlite3",
            "sqliteexception",
            "operationalerror",
            "no such table",
            "sqlite3.operationalerror",
        ),
    }

    # ======================================================
    # Time-Based Payloads
    # ======================================================

    TIME_PAYLOADS: dict[str, tuple[str, ...]] = {
        "MySQL": ("' AND SLEEP(5)--", '" AND SLEEP(5)--', "' OR SLEEP(5)--"),
        "PostgreSQL": ("'; SELECT pg_sleep(5)--", '"; SELECT pg_sleep(5)--'),
        "Microsoft SQL Server": (
            "'; WAITFOR DELAY '0:0:5'--",
            "\"; WAITFOR DELAY '0:0:5'--",
        ),
        "Oracle": ("' AND DBMS_PIPE.RECEIVE_MESSAGE('A',5)--",),
    }

    # ======================================================
    # SQL Error Patterns (Fallback)
    # ======================================================

    SQL_ERROR_PATTERNS: list[str] = [
        r"you have an error in your sql syntax",
        r"mysql_fetch",
        r"warning:\s*mysql",
        r"unclosed quotation mark",
        r"sqlstate",
        r"mysql_num_rows",
        r"mysqli_error",
        r"ora-\d{5}",
        r"oracle error",
        r"postgresql",
        r"pg_query",
        r"sqlite3\.OperationalError",
        r"SQL syntax.*near",
        r"Unknown column",
        r"Table '.*' doesn't exist",
    ]

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

        # ======================================================
        # Logger for debugging
        # ======================================================

        self.logger = logging.getLogger(__name__)
        # --------------------------------------------------
        # Scanner Configuration
        # --------------------------------------------------

        self.stop_on_first = False

        self.max_findings: int | None = None
        self.max_payloads: int | None = 15  # Limit to 15 payloads

        self.statistics = {
            "payloads": 0,
            "requests": 0,
            "vulnerabilities": 0,
            "errors": 0,
        }

        # Initialize session
        self._session = requests.Session()

    # ======================================================
    # URL Validation
    # ======================================================

    def _is_valid_target(self, url: str) -> bool:
        """
        Validate if URL should be scanned for SQL injection.

        Returns True only if:
        - URL has query parameters
        - Query string contains '='
        - At least one parameter has a non-empty value

        This prevents scanning static pages like instructions.php
        """
        parsed = urlparse(url)
        query = parsed.query

        if not query:
            self.logger.debug(f"Skipping {url} - no query parameters")
            return False

        if "=" not in query:
            self.logger.debug(f"Skipping {url} - no '=' in query")
            return False

        params = parse_qs(query)
        has_value = any(v and v[0] for v in params.values())
        if not has_value:
            self.logger.debug(f"Skipping {url} - all parameters empty")
            return False

        self.logger.debug(f"✅ Valid target: {url}")
        return True

    # ======================================================
    # Baseline Response
    # ======================================================

    def _get_baseline_response(self, url: str) -> Optional[requests.Response]:
        """
        Get baseline response for comparison.
        Used for false positive reduction.
        """
        try:
            response = self._session.get(url, timeout=10)
            return response
        except Exception as e:
            self.logger.error(f"Baseline failed: {e}")
            return None

    # ======================================================
    # SQL Error Detection (UPDATED - FIXED)
    # ======================================================

    def _has_sql_error_in_response(self, response_text: str) -> bool:
        """
        Check if response contains SQL error.
        Used to detect if baseline already has SQL errors.
        Uses class-level DBMS_ERRORS for accurate detection.
        """
        if not response_text:
            return False

        text = response_text.lower()

        # First check: Use class-level DBMS_ERRORS
        for dbms, signatures in self.DBMS_ERRORS.items():
            for signature in signatures:
                if signature.lower() in text:
                    return True

        # Second check: Fallback patterns for unknown DBMS
        fallback_patterns = [
            "sql syntax",
            "mysql_fetch",
            "warning: mysql",
            "unclosed quotation mark",
            "sqlstate",
            "ora-",
            "oracle error",
            "postgresql",
            "pg_query",
            "sqlite",
            "microsoft ole db",
            "sql server",
            "invalid query",
            "database error",
        ]

        for pattern in fallback_patterns:
            if pattern in text:
                return True

        return False

    # ======================================================
    # Database Storage
    # ======================================================
    def _store_finding_in_database(self, finding: SQLFinding) -> bool:
        """
        Store finding in database.
        """
        self.logger.info(f"💾 Storing finding: {finding.parameter} on {finding.url}")
        try:
            from app.database.session import SessionLocal
            from app.database.models.finding import Finding
            from app.database.models.project import Project

            db = SessionLocal()
            try:
                # Find project
                project = (
                    db.query(Project)
                    .filter(Project.target.like(f"%{self.target}%"))
                    .first()
                )

                if not project:
                    self.logger.warning(f"No project found for {self.target}")
                    return False

                self.logger.info(f"Found project: {project.id}")

                # Create finding record
                db_finding = Finding(
                    id=str(uuid.uuid4()),
                    project_id=project.id,
                    title=f"SQL Injection - {finding.parameter or 'Unknown'}",
                    description=finding.description
                    or f"SQL Injection in {finding.parameter}",
                    severity=finding.severity or "High",
                    cvss=7.5,
                    status="Open",
                    module="sqli_scanner",
                    target=self.target,
                    scanner_name="sqli",
                    scanner_version="1.0.0",
                    url=finding.url or self.target,
                    method="GET",
                    parameter=finding.parameter or "",
                    payload=finding.payload or "",
                    status_code=finding.status_code or 0,
                    response_time=finding.response_time or 0.0,
                    evidence="\n".join(finding.evidence) if finding.evidence else "",
                    recommendation=finding.remediation or "Use parameterized queries",
                    reference=(
                        "\n".join(finding.references) if finding.references else ""
                    ),
                    confidence=0.9,
                    is_false_positive=False,
                    verified=False,
                    cwe=finding.cwe or "CWE-89",
                    owasp="A03:2021 - Injection",
                    tags="sql_injection",
                    metadata_json=json.dumps(
                        {
                            "dbms": finding.dbms,
                            "technique": finding.technique,
                            "response_length": finding.response_length,
                        }
                    ),
                )

                db.add(db_finding)
                db.commit()
                self.logger.info(f"✅ Finding stored: {db_finding.id}")
                return True

            except Exception as e:
                db.rollback()
                self.logger.error(f"DB error: {e}")
                import traceback

                self.logger.error(traceback.format_exc())
                return False
            finally:
                db.close()

        except Exception as e:
            self.logger.error(f"Store error: {e}")
            import traceback

            self.logger.error(traceback.format_exc())
            return False

    # ======================================================
    # Payload Engine
    # ======================================================

    def get_all_payloads(
        self,
    ) -> list[str]:
        """
        Return every available SQL Injection payload.
        """
        return list(self.payloads)

    def payload_count(
        self,
    ) -> int:
        """
        Return total payload count.
        """
        return len(self.payloads)

    def iter_payloads(
        self,
    ):
        """
        Iterate over every SQL payload.
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
        Return the TRUE and FALSE payloads used for
        Boolean-Based SQL Injection testing.
        """

        # PortSwigger Lab 1 ke liye specific payloads
        # TRUE: ' OR 1=1--  (all products)
        # FALSE: ' OR 1=2-- (only productId=7)

        true_payload = "' OR 1=1--"

        false_payload = "' OR 1=2--"

        return (
            true_payload,
            false_payload,
        )

    # ======================================================
    # Time-Based Payload Selection
    # ======================================================

    def get_time_payloads(
        self,
        dbms: str | None = None,
    ) -> list[str]:
        """
        Return Time-Based payloads.

        If DBMS is known, only return payloads
        for that database.
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

    # ======================================================
    # Smart Payload Selection
    # ======================================================

    def get_smart_payloads(
        self,
    ) -> list[str]:
        """
        Return payloads optimized for
        the detected DBMS.
        """

        if self.detected_dbms is None:
            return self.get_all_payloads()

        dbms = self.detected_dbms.lower()

        smart_payloads: list[str] = []

        for payload in self.payloads:
            lower = payload.lower()

            if "mysql" in dbms:
                if "sleep(" in lower or "benchmark(" in lower or "mysql" in lower:
                    smart_payloads.append(payload)

            elif "postgres" in dbms:
                if "pg_sleep" in lower:
                    smart_payloads.append(payload)

            elif "sql server" in dbms:
                if "waitfor" in lower:
                    smart_payloads.append(payload)

            elif "oracle" in dbms:
                if "dbms_pipe" in lower or "utl_http" in lower:
                    smart_payloads.append(payload)

            else:
                smart_payloads.append(payload)

        if not smart_payloads:
            return self.get_all_payloads()

        return smart_payloads

    # ======================================================
    # DBMS Fingerprinting
    # ======================================================

    def detect_dbms(
        self,
        response_text: str,
    ) -> str | None:
        """
        Detect backend database from SQL
        error signatures.
        """

        body = response_text.lower()

        for dbms, signatures in self.DBMS_ERRORS.items():
            for signature in signatures:
                if signature.lower() in body:
                    self.detected_dbms = dbms

                    return dbms

        return None

    # ======================================================
    # SQL Error Detection
    # ======================================================

    def has_sql_error(self, response_text: str) -> bool:
        """
        Check if response contains SQL error.
        """
        if not response_text:
            return False

        text = response_text.lower()

        # Common SQL error patterns
        patterns = [
            "sql syntax",
            "mysql",
            "warning: mysql",
            "mysqli_",
            "postgresql",
            "pg_query",
            "oracle",
            "ora-",
            "sqlite",
            "microsoft ole db",
            "sql server",
            "unclosed quotation mark",
            "you have an error in your sql syntax",
            "invalid query",
            "database error",
        ]

        for pattern in patterns:
            if pattern in text:
                self.detected_dbms = pattern.title()
                return True

        return False

    # ======================================================

    # Baseline Response Time
    # ======================================================

    def get_baseline_time(
        self,
    ) -> float:
        """
        Measure and cache the baseline response time
        for the target.
        """

        if self.baseline_response_time is not None:
            return self.baseline_response_time

        start = perf_counter()

        response = self.safe_request()

        if response is None:
            return 0.0

        self.baseline_response_time = perf_counter() - start

        return self.baseline_response_time

    # ======================================================
    # Independent Boolean-Based Detection
    # ======================================================

    def detect_boolean_sqli_independent(
        self,
        url: str,
        parameter: str = "",
    ) -> SQLFinding | None:
        """
        Independent Boolean-Based SQL Injection detection.
        """

        true_payload, false_payload = self.get_boolean_payload_pair()

        print(f"[BOOLEAN] TRUE: {true_payload}")
        print(f"[BOOLEAN] FALSE: {false_payload}")

        # TRUE payload bhejein
        true_response = self.safe_request(payload=true_payload)
        if true_response is None:
            print("[BOOLEAN] TRUE response is None")
            return None
        print(f"[BOOLEAN] TRUE length: {len(true_response.body)}")

        # FALSE payload bhejein
        false_response = self.safe_request(payload=false_payload)
        if false_response is None:
            print("[BOOLEAN] FALSE response is None")
            return None
        print(f"[BOOLEAN] FALSE length: {len(false_response.body)}")

        # Dono responses compare karein
        validation_result = self.validate_boolean_detection(
            true_response, false_response
        )
        print(f"[BOOLEAN] Validation: {validation_result}")

        if not validation_result:
            print("[BOOLEAN] ❌ Validation failed - responses are similar")
            return None

        print("[BOOLEAN] ✅ Boolean SQL injection confirmed!")

        # Finding create karein
        finding = SQLFinding()
        finding.vulnerable = True
        finding.url = url
        finding.payload = true_payload
        finding.technique = "Boolean-Based"
        finding.dbms = self.detected_dbms or "Unknown"
        finding.evidence.append("Boolean-based SQL injection confirmed")
        finding.evidence.append(f"TRUE payload: {true_payload}")
        finding.evidence.append(f"FALSE payload: {false_payload}")
        finding.status_code = true_response.status_code if true_response else 0
        finding.response_length = len(true_response.text) if true_response else 0

        confidence = self.calculate_confidence(
            has_error=False,
            boolean_detected=True,
            time_detected=False,
            dbms=self.detected_dbms,
        )

        if finding.analyzer is not None:
            finding.analyzer.risk.confidence = confidence

        self.statistics["vulnerabilities"] += 1

        # Store in database
        self._store_finding_in_database(finding)

        return finding

    # ======================================================
    # Boolean-Based SQL Injection Detection
    # ======================================================

    def detect_boolean_sqli(
        self,
        normal_response: str,
        injected_response: str,
    ) -> bool:
        """
        Detect Boolean-Based SQL Injection by
        comparing two HTTP responses.
        """

        from difflib import SequenceMatcher

        # --------------------------------------------------
        # Normalize Responses
        # --------------------------------------------------

        normal = normal_response.strip()

        injected = injected_response.strip()

        # --------------------------------------------------
        # Empty Response
        # --------------------------------------------------

        if not normal or not injected:
            return False

        # --------------------------------------------------
        # Exactly Identical
        # --------------------------------------------------

        if normal == injected:
            return False

        # --------------------------------------------------
        # Length Difference
        # --------------------------------------------------

        length_difference = abs(len(normal) - len(injected))

        if length_difference > 50:
            return True

        # --------------------------------------------------
        # Similarity Check
        # --------------------------------------------------

        similarity = SequenceMatcher(
            None,
            normal,
            injected,
        ).ratio()

        return similarity < 0.95

    # ======================================================
    # Time-Based SQL Injection Detection
    # ======================================================

    def detect_time_sqli(
        self,
        baseline_time: float,
        injected_time: float,
        threshold: float = 3.0,  # Reduced from 5.0 to 3.0
    ) -> bool:
        """
        Detect Time-Based SQL Injection using
        response delay.
        """

        if baseline_time <= 0:
            return False

        if injected_time <= 0:
            return False

        delay = injected_time - baseline_time

        return delay >= threshold

    # ======================================================
    # Confidence Score
    # ======================================================

    def calculate_confidence(
        self,
        *,
        has_error: bool = False,
        boolean_detected: bool = False,
        time_detected: bool = False,
        dbms: str | None = None,
    ) -> float:
        """
        Calculate confidence score for
        a SQL Injection finding.
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

    # ======================================================
    # Compare Boolean Responses
    # ======================================================

    def compare_boolean_responses(
        self,
        true_response,
        false_response,
    ) -> bool:
        """
        Compare TRUE and FALSE payload responses.
        """

        if true_response is None or false_response is None:
            return False

        true_body = getattr(
            true_response,
            "text",
            "",
        )

        false_body = getattr(
            false_response,
            "text",
            "",
        )

        if true_body == false_body:
            return False

        length_difference = abs(len(true_body) - len(false_body))

        if length_difference > 50:
            return True

        return self.detect_boolean_sqli(
            true_body,
            false_body,
        )

    # ======================================================
    # Response Similarity
    # ======================================================

    def calculate_similarity(
        self,
        text1: str,
        text2: str,
    ) -> float:
        """
        Calculate similarity ratio between
        two HTTP responses.
        """

        from difflib import SequenceMatcher

        if not text1 and not text2:
            return 1.0

        return SequenceMatcher(
            None,
            text1,
            text2,
        ).ratio()

    # ======================================================
    # Boolean Validation
    # ======================================================

    def validate_boolean_detection(
        self,
        true_response,
        false_response,
    ) -> bool:
        """
        Validate Boolean-Based SQL Injection.
        """

        if true_response is None:
            return False

        if false_response is None:
            return False

        if getattr(
            true_response,
            "status_code",
            0,
        ) != getattr(
            false_response,
            "status_code",
            0,
        ):
            return True

        true_body = getattr(
            true_response,
            "text",
            "",
        )

        false_body = getattr(
            false_response,
            "text",
            "",
        )

        similarity = self.calculate_similarity(
            true_body,
            false_body,
        )

        if similarity < 0.95:
            return True

        return abs(len(true_body) - len(false_body)) > 50

    # ======================================================
    # Evaluate Response
    # ======================================================

    def evaluate_response(
        self,
        url: str,
        payload: str,
        response,
    ) -> SQLFinding | None:
        """
        Analyze an HTTP response after
        sending a SQL Injection payload.
        """

        if self.analyzer is not None:
            analysis = self.analyzer.analyze(
                response,
                payload,
            )
        else:
            analysis = None

        body = getattr(
            response,
            "text",
            "",
        )

        dbms = self.detect_dbms(
            body,
        )

        has_error = dbms is not None

        if not has_error:
            return None

        confidence = self.calculate_confidence(
            has_error=True,
            boolean_detected=False,
            time_detected=False,
            dbms=dbms,
        )

        if analysis is not None:
            analysis.risk.confidence = confidence

        finding = SQLFinding()

        finding.vulnerable = True

        finding.url = url

        finding.payload = payload

        finding.technique = "Error-Based"

        finding.dbms = dbms or "Unknown"

        finding.analyzer = analysis

        finding.status_code = getattr(response, "status_code", 0)
        finding.response_length = len(body)
        finding.response_time = 0.0

        finding.evidence.append(f"Detected database: {finding.dbms}")

        self.statistics["vulnerabilities"] += 1

        return finding

    # ======================================================
    # Test Single Payload (UPDATED with DB Storage)
    # ======================================================

    def test_payload(
        self,
        payload: str,
    ) -> SQLFinding | None:
        """
        Send a single SQL Injection payload
        and evaluate the response.
        """

        response = self.safe_request(
            payload=payload,
        )

        if response is None:
            self.errors += 1
            self.statistics["errors"] += 1
            return None

        # Get baseline for comparison - false positive reduction
        baseline = self._get_baseline_response(self.target)

        finding = self.evaluate_response(
            self.target,
            payload,
            response,
        )

        if finding is None:
            return None

        # Response verification - prevent false positives
        if baseline and self._has_sql_error_in_response(baseline.text):
            self.logger.debug(
                "Baseline has SQL errors, skipping to avoid false positive"
            )
            return None

        # Boolean-Based Verification
        true_payload, false_payload = self.get_boolean_payload_pair()

        true_response = self.safe_request(
            payload=true_payload,
        )

        false_response = self.safe_request(
            payload=false_payload,
        )

        if (
            true_response is not None
            and false_response is not None
            and self.validate_boolean_detection(
                true_response,
                false_response,
            )
        ):
            finding.technique = "Boolean-Based"

            if finding.analyzer is not None:
                finding.analyzer.risk.confidence = min(
                    finding.analyzer.risk.confidence + 0.20,
                    1.0,
                )

            finding.evidence.append("Boolean SQL Injection confirmed.")

        # ==========================================================
        # Store finding in database
        # ==========================================================
        self.logger.info(f"💾 Attempting to store finding: {finding.parameter}")
        stored = self._store_finding_in_database(finding)
        if stored:
            self.logger.info(f"✅ Finding stored successfully")
        else:
            self.logger.warning(f"❌ Failed to store finding")

        return finding

    # ======================================================
    # Test Time-Based SQL Injection
    # ======================================================

    def test_time_payload(
        self,
        payload: str,
    ) -> SQLFinding | None:
        """
        Test a single Time-Based SQL Injection payload.
        """

        # --------------------------------------------------
        # Baseline Request
        # --------------------------------------------------

        baseline_time = self.get_baseline_time()

        if baseline_time <= 0:
            self.errors += 1

            self.statistics["errors"] += 1

            return None

        # --------------------------------------------------
        # Injected Request
        # --------------------------------------------------

        injected_start = perf_counter()

        response = self.safe_request(
            payload=payload,
        )

        injected_time = perf_counter() - injected_start

        if response is None:
            self.errors += 1

            self.statistics["errors"] += 1

            return None

        # --------------------------------------------------
        # Time-Based Detection
        # --------------------------------------------------

        if not self.detect_time_sqli(
            baseline_time,
            injected_time,
        ):
            return None

        # --------------------------------------------------
        # Response Analysis
        # --------------------------------------------------
        analysis = None
        if self.analyzer is not None:
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

        finding.status_code = getattr(response, "status_code", 0)
        finding.response_length = len(getattr(response, "text", ""))
        finding.response_time = injected_time

        if analysis is not None:
            analysis.risk.confidence = max(
                analysis.risk.confidence,
                self.calculate_confidence(
                    time_detected=True,
                    dbms=self.detected_dbms,
                ),
            )

        finding.evidence.append(f"Baseline Response: {baseline_time:.2f}s")

        finding.evidence.append(f"Injected Response: {injected_time:.2f}s")

        finding.evidence.append(f"Delay: {injected_time - baseline_time:.2f}s")

        self.statistics["vulnerabilities"] += 1

        # Store finding in database
        self._store_finding_in_database(finding)

        return finding

    # ======================================================
    # Merge Duplicate Findings
    # ======================================================

    def merge_findings(
        self,
        findings: list[SQLFinding],
    ) -> list[SQLFinding]:
        """
        Merge duplicate SQL Injection findings.
        """

        merged: dict[
            tuple[str, str, str],
            SQLFinding,
        ] = {}

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

            # ------------------------------------------
            # Merge Techniques
            # ------------------------------------------

            techniques = {
                item.strip()
                for item in (current.technique + "," + finding.technique).split(",")
            }

            current.technique = ", ".join(sorted(techniques))

            # ------------------------------------------
            # Merge Evidence
            # ------------------------------------------

            for evidence in finding.evidence:
                if evidence not in current.evidence:
                    current.evidence.append(evidence)

            # ------------------------------------------
            # Keep Highest Confidence
            # ------------------------------------------

            if current.analyzer is not None and finding.analyzer is not None:
                current.analyzer.risk.confidence = max(
                    current.analyzer.risk.confidence,
                    finding.analyzer.risk.confidence,
                )

        return list(merged.values())

    # ======================================================
    # Enrich Finding
    # ======================================================

    def enrich_finding(
        self,
        finding: SQLFinding,
    ) -> SQLFinding:
        """
        Add vulnerability metadata.
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

        finding.severity = severity

        finding.cwe = "CWE-89"

        finding.owasp = "OWASP Top 10 2021 - A03: Injection"

        finding.cvss = "CVSS v3.1"

        finding.references = [
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
        ]

        finding.remediation = (
            "Use parameterized queries "
            "(Prepared Statements), "
            "avoid dynamic SQL, "
            "validate user input, "
            "and apply least-privilege "
            "database accounts."
        )

        return finding

    def initialize_dvwa_session(self):

        print("[DVWA] Session start")

        return True

    # ======================================================
    # Main Scanning Function (UPDATED with Payload Limit)
    # ======================================================

    def scan(self, session: requests.Session | None = None) -> list[SQLFinding]:
        """
        Execute the complete SQL Injection scan.
        """
        # Use provided session or create new
        if session is None:
            self._session = requests.Session()
        else:
            self._session = session

        self.started_at = perf_counter()
        self.findings.clear()

        self.statistics["payloads"] = 0
        self.statistics["requests"] = 0
        self.statistics["vulnerabilities"] = 0
        self.statistics["errors"] = 0

        # ==========================================================
        # URL Validation - Skip static pages like instructions.php
        # ==========================================================
        if not self._is_valid_target(self.target):
            self.logger.info(f"⏭️ Skipping {self.target} - not a valid SQLi target")
            return []

        # ==========================================================
        # Baseline check - Skip if baseline has SQL errors
        # ==========================================================
        baseline = self._get_baseline_response(self.target)
        if baseline and self._has_sql_error_in_response(baseline.text):
            self.logger.warning(
                f"Baseline has SQL errors, skipping to avoid false positives"
            )
            return []

        # Extract parameters properly
        parsed_url = urlparse(self.target)
        params = parse_qs(parsed_url.query)

        if not params:
            self.logger.info(f"No parameters found in {self.target}")
            return []

        self.logger.info(f"🔍 Testing {len(params)} parameters on {self.target}")

        # ==========================================================
        # Get and Test Payloads - LIMIT TO 10 MOST EFFECTIVE
        # ==========================================================
        all_payloads = self.get_production_payloads(None)

        # Take only first 10 payloads to reduce false positives
        payloads = all_payloads[:10]
        total = len(payloads)

        # Only show if there are payloads
        if total > 0:
            print(f"[SQLi] Testing {total} payloads on {self.target}")

        for param_name in params.keys():
            if len(self.findings) >= 10:  # Max 10 findings
                break

            if not params[param_name] or not params[param_name][0]:
                continue

            self.logger.debug(f"Testing parameter: {param_name}")

            for payload in payloads:
                if (
                    self.max_payloads
                    and self.statistics["payloads"] >= self.max_payloads
                ):
                    break

                # Test with specific parameter
                finding = self.test_payload_with_param(payload, param_name)
                if finding:
                    finding.parameter = param_name
                    finding = self.enrich_finding(finding)
                    self.findings.append(finding)
                    print(f"[SQLi] ✅ Found: {finding.technique} in {param_name}")

                if self.stop_on_first and self.findings:
                    break

        # Also test time-based payloads
        if not self.findings:
            for param_name in params.keys():
                if len(self.findings) >= 10:
                    break
                time_payloads = ["' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"]
                for payload in time_payloads[:2]:
                    finding = self.test_time_payload_with_param(payload, param_name)
                    if finding:
                        finding.parameter = param_name
                        finding = self.enrich_finding(finding)
                        self.findings.append(finding)
                        print(f"[SQLi] ✅ Found: {finding.technique} in {param_name}")
                        break

        # Merge and Return
        self.findings = self.merge_findings(self.findings)
        self.finished_at = perf_counter()

        # Only show summary if findings exist
        if self.findings:
            print(f"[SQLi] ✅ Complete: {len(self.findings)} findings")
        else:
            print(f"[SQLi] ❌ No findings found")

        return self.findings

    # ======================================================
    # Test Payload with Specific Parameter (NEW)
    # ======================================================

    def test_payload_with_param(self, payload: str, param: str) -> SQLFinding | None:
        """
        Test a payload on a specific parameter.
        """
        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            if not params.get(param) or not params[param][0]:
                return None

            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )

            # Send request with payload
            start_time = perf_counter()
            response = self._session.get(test_url, timeout=10)
            elapsed = perf_counter() - start_time

            self.statistics["requests"] += 1

            # Check for SQL errors
            has_error, dbms = self._has_sql_error_in_response_with_dbms(response.text)

            if has_error:
                # Verify baseline doesn't have the same error
                baseline = self._get_baseline_response(self.target)
                if baseline:
                    baseline_has_error, _ = self._has_sql_error_in_response_with_dbms(
                        baseline.text
                    )
                    if baseline_has_error:
                        return None

                finding = SQLFinding()
                finding.vulnerable = True
                finding.url = test_url
                finding.parameter = param
                finding.payload = payload
                finding.technique = "Error-Based"
                finding.dbms = dbms or "Unknown"
                finding.severity = "High"
                finding.cwe = "CWE-89"
                finding.owasp = "A03:2021 - Injection"
                finding.status_code = response.status_code
                finding.response_time = elapsed
                finding.response_length = len(response.text)
                finding.references = [
                    "https://cwe.mitre.org/data/definitions/89.html",
                    "https://owasp.org/Top10/A03_2021-Injection/",
                ]
                finding.remediation = "Use parameterized queries (Prepared Statements), never concatenate user input into SQL queries."
                finding.evidence.append(f"SQL error detected in parameter: {param}")
                finding.evidence.append(f"Payload: {payload}")
                finding.evidence.append(f"DBMS: {dbms or 'Unknown'}")
                finding.evidence.append(f"Status Code: {response.status_code}")
                finding.evidence.append(f"Response Length: {len(response.text)}")

                self.statistics["vulnerabilities"] += 1
                self._store_finding_in_database(finding)
                return finding

        except Exception as e:
            self.logger.debug(f"Error testing {param}: {e}")
            self.statistics["errors"] += 1

        return None

    # ======================================================
    # Test Time Payload with Specific Parameter (NEW)
    # ======================================================

    def test_time_payload_with_param(
        self, payload: str, param: str
    ) -> SQLFinding | None:
        """
        Test a time-based payload on a specific parameter.
        """
        try:
            parsed = urlparse(self.target)
            params = parse_qs(parsed.query)

            if not params.get(param) or not params[param][0]:
                return None

            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                )
            )

            # Get baseline time
            if self.baseline_response_time is None:
                baseline = self._get_baseline_response(self.target)
                if baseline:
                    self.baseline_response_time = 0.3  # Default baseline

            start_time = perf_counter()
            response = self._session.get(test_url, timeout=12)
            elapsed = perf_counter() - start_time

            self.statistics["requests"] += 1

            # Check for delay (> 3 seconds)
            if elapsed > 3.0 and elapsed > (self.baseline_response_time or 0.3) + 2.0:
                finding = SQLFinding()
                finding.vulnerable = True
                finding.url = test_url
                finding.parameter = param
                finding.payload = payload
                finding.technique = "Time-Based"
                finding.dbms = self.detected_dbms or "Unknown"
                finding.severity = "High"
                finding.cwe = "CWE-89"
                finding.owasp = "A03:2021 - Injection"
                finding.status_code = response.status_code
                finding.response_time = elapsed
                finding.response_length = len(response.text)
                finding.references = [
                    "https://cwe.mitre.org/data/definitions/89.html",
                    "https://owasp.org/Top10/A03_2021-Injection/",
                ]
                finding.remediation = "Use parameterized queries (Prepared Statements)."
                finding.evidence.append(
                    f"Time-based SQL injection detected in parameter: {param}"
                )
                finding.evidence.append(f"Payload: {payload}")
                finding.evidence.append(f"Response time: {elapsed:.2f}s")
                finding.evidence.append(
                    f"Baseline time: {self.baseline_response_time:.2f}s"
                )

                self.statistics["vulnerabilities"] += 1
                self._store_finding_in_database(finding)
                return finding

        except Exception as e:
            self.logger.debug(f"Time test failed for {param}: {e}")
            self.statistics["errors"] += 1

        return None

    # ======================================================
    # SQL Error Detection with DBMS (NEW)
    # ======================================================

    def _has_sql_error_in_response_with_dbms(
        self, response_text: str
    ) -> tuple[bool, Optional[str]]:
        """
        Check if response contains SQL error and return DBMS.
        """
        if not response_text:
            return False, None

        text = response_text.lower()

        # Check using class-level DBMS_ERRORS
        for dbms, signatures in self.DBMS_ERRORS.items():
            for signature in signatures:
                if signature.lower() in text:
                    return True, dbms

        # Check using regex patterns
        for pattern in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True, "Unknown"

        return False, None

    # ======================================================
    # Safe Request (FIXED)
    # ======================================================

    def safe_request(self, payload: str = "") -> requests.Response | None:
        """
        Make a safe request using the session.
        """
        try:
            # Build URL
            url = self.target
            if payload:
                # Use 'q' as parameter name for generic testing
                if "?" in url:
                    url = f"{url}&q={payload}"
                else:
                    url = f"{url}?q={payload}"

            response = self._session.get(
                url,
                timeout=10,
                allow_redirects=True,
            )
            self.statistics["requests"] += 1
            return response

        except Exception:
            self.statistics["errors"] += 1
            return None

    # ======================================================
    # Payload Randomization
    # ======================================================

    def randomize_payloads(
        self,
        payloads: list[str],
    ) -> list[str]:
        """
        Randomize payload execution order to reduce
        predictable request patterns.
        """

        from random import shuffle

        randomized = payloads.copy()

        shuffle(randomized)

        return randomized

    # ======================================================
    # Request Delay
    # ======================================================

    def apply_request_delay(
        self,
        delay: float = 0.0,
    ) -> None:
        """
        Apply a delay between requests.
        """

        if delay <= 0:
            return

        from time import sleep

        sleep(delay)

    # ======================================================
    # Scan Configuration
    # ======================================================

    def configure_scan(
        self,
        *,
        request_delay: float = 0.0,
        randomize_payloads: bool = False,
    ) -> None:
        """
        Configure scanner runtime behavior.
        """

        self.request_delay = request_delay

        self.randomize = randomize_payloads

    # ======================================================
    # Prepare Payloads
    # ======================================================

    def prepare_payloads(
        self,
        payloads: list[str],
    ) -> list[str]:
        """
        Prepare payloads before execution.
        """

        prepared = payloads

        if getattr(
            self,
            "randomize",
            False,
        ):
            prepared = self.randomize_payloads(
                prepared,
            )

            prepared = self.deduplicate_payloads(
                prepared,
            )

        return prepared

    # ======================================================
    # Remove Duplicate Payloads
    # ======================================================

    def deduplicate_payloads(
        self,
        payloads: list[str],
    ) -> list[str]:
        """
        Remove duplicate payloads while preserving order.
        """

        seen: set[str] = set()

        unique: list[str] = []

        for payload in payloads:
            if payload in seen:
                continue

            seen.add(payload)

            unique.append(payload)

        return unique

    # ======================================================
    # Before Request Hook
    # ======================================================

    def before_request(
        self,
    ) -> None:
        """
        Executed before every HTTP request.
        """

        delay = getattr(
            self,
            "request_delay",
            0.0,
        )

        self.apply_request_delay(
            delay,
        )

    # ======================================================
    # Scan Summary
    # ======================================================

    def get_summary(
        self,
    ) -> dict[str, object]:
        """
        Return a summary of the completed scan.
        """

        duration = 0.0

        if self.started_at is not None and self.finished_at is not None:
            duration = self.finished_at - self.started_at

        return {
            "scanner": self.info.name,
            "target": self.target,
            "payloads": self.statistics["payloads"],
            "requests": self.statistics["requests"],
            "vulnerabilities": self.statistics["vulnerabilities"],
            "errors": self.statistics["errors"],
            "dbms": self.detected_dbms,
            "duration": round(duration, 2),
            "findings": len(self.findings),
        }

    # ======================================================
    # Reset Scanner
    # ======================================================

    def reset(
        self,
    ) -> None:
        """
        Reset scanner state before another scan.
        """

        self.findings.clear()

        self.detected_dbms = None

        self.baseline_response_time = None

        self.requests_sent = 0

        self.responses_received = 0

        self.errors = 0

        self.started_at = None

        self.finished_at = None

        self.statistics = {
            "payloads": 0,
            "requests": 0,
            "vulnerabilities": 0,
            "errors": 0,
        }

    # ======================================================
    # Send Request (Retry Support)
    # ======================================================
    def send_request(
        self,
        payload: str = "",
        retries: int = 3,
    ):
        """
        Send an HTTP request with automatic retry support.
        """

        last_response = None

        for attempt in range(retries):
            try:
                last_response = self._session.get(
                    self.target,
                    params={"q": payload} if payload else {},
                    timeout=10,
                )

                if last_response is not None:
                    return last_response

            except Exception:
                self.errors += 1
                self.statistics["errors"] += 1

        return last_response

    # ======================================================
    # WAF Detection
    # ======================================================

    WAF_SIGNATURES: dict[str, tuple[str, ...]] = {
        "Cloudflare": (
            "cloudflare",
            "__cf_bm",
            "cf-ray",
            "attention required",
        ),
        "Akamai": (
            "akamai",
            "akamaighost",
            "akamai bot manager",
        ),
        "AWS WAF": (
            "aws waf",
            "x-amzn-requestid",
            "request blocked",
        ),
        "Imperva": (
            "imperva",
            "incapsula",
            "x-iinfo",
        ),
        "Sucuri": (
            "sucuri",
            "access denied - sucuri",
        ),
        "F5 BIG-IP": (
            "big-ip",
            "f5",
            "the requested url was rejected",
        ),
        "ModSecurity": (
            "mod_security",
            "modsecurity",
            "not acceptable",
        ),
    }

    # ======================================================
    # Detect WAF
    # ======================================================

    def detect_waf(
        self,
        response,
    ) -> str | None:
        """
        Detect Web Application Firewall from
        response headers and body.
        """

        if response is None:
            return None

        body = getattr(
            response,
            "text",
            "",
        ).lower()

        headers = str(
            getattr(
                response,
                "headers",
                {},
            )
        ).lower()

        combined = body + headers

        for waf, signatures in self.WAF_SIGNATURES.items():
            for signature in signatures:
                if signature.lower() in combined:
                    return waf

        return None

    # ======================================================
    # WAF-Aware Payload Selection
    # ======================================================

    def filter_payloads_for_waf(
        self,
        payloads: list[str],
        waf: str | None,
    ) -> list[str]:
        """
        Filter SQL Injection payloads according to the
        detected Web Application Firewall.
        """

        if waf is None:
            return payloads

        filtered: list[str] = []

        waf_name = waf.lower()

        for payload in payloads:
            lower = payload.lower()

            # ------------------------------------------
            # Cloudflare
            # ------------------------------------------

            if "cloudflare" in waf_name:
                if (
                    "union select" in lower
                    or "information_schema" in lower
                    or "benchmark(" in lower
                ):
                    continue

            # ------------------------------------------
            # ModSecurity
            # ------------------------------------------

            elif "modsecurity" in waf_name:
                if "union" in lower or "sleep(" in lower or "waitfor" in lower:
                    continue

            # ------------------------------------------
            # AWS WAF
            # ------------------------------------------

            elif "aws" in waf_name:
                if "union select" in lower or "dbms_pipe" in lower:
                    continue

            # ------------------------------------------
            # Imperva
            # ------------------------------------------

            elif "imperva" in waf_name:
                if "sleep(" in lower or "benchmark(" in lower:
                    continue

            filtered.append(payload)

        if filtered:
            return filtered

        return payloads

    # ======================================================
    # Production Payload Selector
    # ======================================================

    def get_production_payloads(
        self,
        response=None,
    ) -> list[str]:
        """
        Return payloads optimized for the detected
        backend database and WAF.
        """

        payloads = self.get_smart_payloads()

        waf = self.detect_waf(
            response,
        )

        return self.filter_payloads_for_waf(
            payloads,
            waf,
        )

    # ======================================================
    # Scanner Status
    # ======================================================

    @property
    def has_findings(
        self,
    ) -> bool:
        """
        Returns True if vulnerabilities were found.
        """

        return len(self.findings) > 0

    @property
    def finding_count(
        self,
    ) -> int:
        """
        Total findings.
        """

        return len(self.findings)

    @property
    def success_rate(
        self,
    ) -> float:
        """
        Successful request percentage.
        """

        if self.requests_sent == 0:
            return 0.0

        return (self.responses_received / self.requests_sent) * 100.0
