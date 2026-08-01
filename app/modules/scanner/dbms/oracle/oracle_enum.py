# app/modules/scanner/dbms/oracle/oracle_enum.py

"""
Main Oracle Enumeration module.
"""

import logging
from typing import Any

import requests

from ...common.html_parser import HTMLParser
from ...common.payload_builder import PayloadBuilder
from ...common.regex_utils import RegexUtils
from ...common.response_diff import ResponseDiff
from .login import OracleLogin
from .payloads import OraclePayloads
from .scorer import OracleScorer


class OracleEnum:
    """
    Oracle Enumeration Module for SentinelAI.

    This module performs comprehensive Oracle SQL injection enumeration
    following a 11-phase workflow.
    """

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: logging.Logger | None = None,
    ):
        """
        Initialize the Oracle Enumeration module.

        Args:
            session: Requests session for HTTP requests
            base_url: Target base URL
            logger: Optional logger instance
        """
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

        # Core components
        self.html_parser = HTMLParser()
        self.regex_utils = RegexUtils()
        self.response_diff = ResponseDiff()
        self.payload_builder = PayloadBuilder()
        self.oracle_payloads = OraclePayloads()
        self.scorer = OracleScorer()
        self.login = OracleLogin(session, base_url, logger)

        # State variables
        self.dbms_type = None
        self.column_count = 0
        self.visible_columns = []
        self.all_tables = []
        self.user_table = None
        self.table_columns = []
        self.username_column = None
        self.password_column = None
        self.credentials = []
        self.administrator = None

        self.logger.info("[OracleEnum] Module initialized")
        self.logger.info(f"[OracleEnum] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger if none provided."""
        logger = logging.getLogger("OracleEnum")
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

    def _send_request(
        self, url: str, params: dict | None = None
    ) -> requests.Response | None:
        """
        Send HTTP request with error handling.

        Args:
            url: Request URL
            params: Query parameters

        Returns:
            Optional[Response]: Response object or None
        """
        try:
            response = self.session.get(url, params=params, timeout=10)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            self.logger.error(f"[OracleEnum] Request failed: {e!s}")
            return None

    # ==================================================
    # PHASE 1: Oracle Detection
    # ==================================================

    def detect_oracle(self, injection_point: str | None = None) -> bool:
        """
        Phase 1: Detect if the target DBMS is Oracle.

        Args:
            injection_point: Optional specific injection point

        Returns:
            bool: True if Oracle is detected, False otherwise
        """
        self.logger.info(
            "[OracleEnum] =================================================="
        )
        self.logger.info("[OracleEnum] PHASE 1: Oracle Detection")
        self.logger.info(
            "[OracleEnum] =================================================="
        )

        try:
            # Use UnionSQLi's DBMS detection
            from ...union_sqli import UnionSQLi

            union_sqli = UnionSQLi(self.session, self.base_url, self.logger)

            self.logger.info("[OracleEnum] Detecting DBMS type...")
            dbms = union_sqli.detect_dbms(injection_point)

            self.dbms_type = dbms
            self.logger.info(f"[OracleEnum] Detected DBMS: {dbms}")

            # Check if Oracle is detected
            is_oracle = dbms and "oracle" in dbms.lower()

            if is_oracle:
                self.logger.info("[OracleEnum] ✓ Oracle database confirmed")
                self.logger.info(
                    "[OracleEnum] Step 1 complete: Oracle detected successfully"
                )
            else:
                self.logger.error(f"[OracleEnum] ✗ Expected Oracle but found: {dbms}")
                self.logger.error("[OracleEnum] Stopping execution - DBMS mismatch")

            return is_oracle

        except Exception as e:
            self.logger.error(f"[OracleEnum] Error during Oracle detection: {e!s}")
            return False

    def run_phase_1(self, injection_point: str | None = None) -> bool:
        """
        Convenience method to run Phase 1 only.

        Args:
            injection_point: Optional specific injection point

        Returns:
            bool: True if Oracle is detected
        """
        return self.detect_oracle(injection_point)

    # ==================================================
    # PHASE 2: Find UNION Column Count
    # ==================================================

    def find_column_count(self, injection_point: str, max_columns: int = 30) -> int:
        """
        Phase 2: Automatically discover the UNION column count.

        Args:
            injection_point: Parameter name to inject into
            max_columns: Maximum columns to test

        Returns:
            int: Column count (0 if not found)
        """
        self.logger.info(
            "[OracleEnum] =================================================="
        )
        self.logger.info("[OracleEnum] PHASE 2: Find UNION Column Count")
        self.logger.info(
            "[OracleEnum] =================================================="
        )

        # Will be implemented in Phase 2
        self.logger.info("[OracleEnum] Phase 2 coming soon...")
        return 0

    # ==================================================
    # FULL EXECUTION
    # ==================================================

    def run_full_enumeration(self, injection_point: str) -> dict[str, Any]:
        """
        Run the complete Oracle enumeration workflow.

        Args:
            injection_point: Parameter name to inject into

        Returns:
            Dict: Complete results
        """
        self.logger.info("[OracleEnum] Starting full Oracle enumeration")
        self.logger.info(f"[OracleEnum] Target: {self.base_url}")
        self.logger.info(f"[OracleEnum] Injection point: {injection_point}")

        results = {
            "success": False,
            "dbms": None,
            "column_count": 0,
            "user_table": None,
            "credentials": [],
            "administrator": None,
            "lab_solved": False,
        }

        # Phase 1: Oracle Detection
        if not self.run_phase_1(injection_point):
            return results

        results["dbms"] = self.dbms_type

        # Phase 2: Find Column Count
        column_count = self.find_column_count(injection_point)
        if column_count == 0:
            self.logger.error("[OracleEnum] Failed to find column count, stopping")
            return results

        results["column_count"] = column_count
        self.column_count = column_count

        # TODO: Continue with remaining phases

        results["success"] = True
        return results
