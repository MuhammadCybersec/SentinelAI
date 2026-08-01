"""
===========================================================
Project : Sentinel AI
Module  : Error-Based SQL Injection Detector
File ID : SCANNER-ERROR-DETECTOR-001
Version : 1.0.0
===========================================================

Description:
Detects Error-Based SQL Injection vulnerabilities.
Identifies DBMS from error messages.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.modules.scanner.modules.error_payloads import ErrorPayloadGenerator

logger = logging.getLogger(__name__)


class ErrorDetector:
    """
    Detects Error-Based SQL Injection vulnerabilities.
    """

    # ============================================================
    # DBMS Error Signatures
    # ============================================================

    DBMS_SIGNATURES = {
        "MySQL": [
            r"You have an error in your SQL syntax",
            r"Warning: mysql",
            r"MySQL server version",
            r"mysqli_",
            r"SQL syntax",
            r"MariaDB",
            r"MySQL",
        ],
        "PostgreSQL": [
            r"PostgreSQL",
            r"pg_query",
            r"pg_exec",
            r"PG::SyntaxError",
            r"ERROR:",
            r"FATAL:",
        ],
        "MSSQL": [
            r"Microsoft SQL Server",
            r"SQL Server",
            r"Unclosed quotation mark",
            r"ODBC SQL Server Driver",
            r"SQLServerException",
            r"System.Data.SqlClient",
        ],
        "Oracle": [
            r"ORA-[0-9]{5}",
            r"Oracle Database",
            r"Oracle error",
            r"OCIError",
            r"ORA-",
        ],
    }

    def __init__(self, target: str):
        self.target = target
        self.parameter: str = "category"
        self.payload_gen = ErrorPayloadGenerator()
        self.dbms: str | None = None
        self.is_error_vulnerable: bool = False
        self.error_payload: str | None = None
        self.error_response: Any | None = None

        self.statistics = {
            "requests": 0,
            "errors": 0,
        }

    def detect(self) -> tuple[bool, str | None]:
        """
        Detect if Error-Based SQL Injection is possible.

        Returns:
            Tuple of (is_vulnerable, dbms)
        """
        logger.info("[ErrorDetector] Detecting Error-Based SQLi...")

        # Test single quote
        payload = self.payload_gen.get_single_quote_payload()
        response = self._send_request(payload)

        if response and self._has_sql_error(response.body):
            dbms = self._detect_dbms(response.body)
            self.dbms = dbms
            self.is_error_vulnerable = True
            self.error_payload = payload
            self.error_response = response
            logger.info(f"[ErrorDetector] ✅ Error-Based SQLi detected (DBMS: {dbms})")
            return True, dbms

        # Test double quote
        payload = self.payload_gen.get_double_quote_payload()
        response = self._send_request(payload)

        if response and self._has_sql_error(response.body):
            dbms = self._detect_dbms(response.body)
            self.dbms = dbms
            self.is_error_vulnerable = True
            self.error_payload = payload
            self.error_response = response
            logger.info(f"[ErrorDetector] ✅ Error-Based SQLi detected (DBMS: {dbms})")
            return True, dbms

        logger.info("[ErrorDetector] ❌ Error-Based SQLi not detected")
        return False, None

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
            return response

        except Exception as e:
            logger.debug(f"[ErrorDetector] Request failed: {e}")
            return None

    def _has_sql_error(self, body: str) -> bool:
        """Check if response contains SQL error."""
        body_lower = body.lower()
        error_patterns = [
            "sql",
            "syntax",
            "error",
            "mysql",
            "postgresql",
            "oracle",
            "ora-",
            "sql server",
            "microsoft",
            "unclosed",
            "quotation",
            "warning",
        ]
        for pattern in error_patterns:
            if pattern in body_lower:
                return True
        return False

    def _detect_dbms(self, body: str) -> str:
        """Detect DBMS from error message."""
        for dbms, signatures in self.DBMS_SIGNATURES.items():
            for signature in signatures:
                if re.search(signature, body, re.IGNORECASE):
                    return dbms
        return "Unknown"


def create_error_detector(target: str) -> ErrorDetector:
    """Factory function for ErrorDetector."""
    return ErrorDetector(target)
