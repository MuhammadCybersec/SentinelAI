"""
===========================================================
Project : Sentinel AI
Module  : Blind SQL Injection Manager
File ID : SCANNER-BLIND-SQLI-001
Version : 1.0.0
===========================================================

Description:
Blind SQL Injection manager.
Automatically detects and exploits Blind SQLi vulnerabilities.
Supports Boolean and Time-based techniques.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.modules.scanner.modules.blind_extractor import BlindExtractor

logger = logging.getLogger(__name__)


@dataclass
class BlindFinding:
    """Blind SQL Injection finding."""

    vulnerable: bool = False
    url: str = ""
    parameter: str = ""
    technique: str = ""  # "boolean" or "time"
    dbms: str = ""
    database: str = ""
    version: str = ""
    user: str = ""
    tables: list[str] = field(default_factory=list)
    columns: dict[str, list[str]] = field(default_factory=dict)
    credentials: list[dict[str, str]] = field(default_factory=list)
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


class BlindSQLiScanner:
    """
    Blind SQL Injection scanner.
    Automatically detects and exploits Blind SQLi vulnerabilities.
    """

    def __init__(self, target: str):
        self.target = target
        self.parameter: str = "category"
        self.findings: list[BlindFinding] = []
        self.statistics = {
            "requests": 0,
            "findings": 0,
        }

    def scan(self) -> list[BlindFinding]:
        """
        Execute Blind SQL Injection scan.

        Returns:
            List of BlindFinding objects
        """
        logger.info(f"[BlindSQLi] Scanning {self.target} for Blind SQLi...")

        self.findings.clear()

        # Step 1: Extract data using Blind SQLi
        extractor = BlindExtractor(self.target)
        extracted = extractor.extract()

        if extracted.get("database") or extracted.get("tables"):
            finding = BlindFinding(
                vulnerable=True,
                url=self.target,
                parameter=self.parameter,
                technique=extractor.technique or "unknown",
                dbms=extractor.dbms or "Unknown",
                database=extracted.get("database", ""),
                version=extracted.get("version", ""),
                user=extracted.get("user", ""),
                tables=extracted.get("tables", []),
                columns=extracted.get("columns", {}),
                credentials=extracted.get("credentials", []),
                confidence=0.9,
                evidence=[
                    f"DBMS: {extractor.dbms or 'Unknown'}",
                    f"Database: {extracted.get('database', 'Unknown')}",
                    f"Tables found: {len(extracted.get('tables', []))}",
                    f"Credentials: {len(extracted.get('credentials', []))}",
                ],
            )
            self.findings.append(finding)
            self.statistics["findings"] = 1

            logger.info(
                f"[BlindSQLi] ✅ Blind SQLi confirmed: {extractor.technique}-based"
            )
            logger.info(
                f"[BlindSQLi]   Database: {extracted.get('database', 'Unknown')}"
            )
            logger.info(f"[BlindSQLi]   Tables: {extracted.get('tables', [])}")

        return self.findings


# ============================================================
# Integration with SQL Injection Manager
# ============================================================


class SQLInjectionManager:
    """
    Manages SQL Injection detection and exploitation.
    Automatically switches between UNION and Blind techniques.
    """

    def __init__(self, target: str):
        self.target = target
        self.union_scanner = None
        self.blind_scanner = None
        self.result = None

    def scan(self) -> dict[str, Any]:
        """
        Execute SQL Injection scan.
        Tries UNION first, falls back to Blind.

        Returns:
            Scan result
        """
        logger.info(f"[SQLiManager] Scanning {self.target}...")

        # Step 1: Try UNION SQL Injection
        try:
            from app.modules.scanner.modules.union_sqli import UnionSQLiScanner

            self.union_scanner = UnionSQLiScanner(self.target)
            findings = self.union_scanner.scan()

            if findings:
                logger.info("[SQLiManager] ✅ UNION SQLi found")
                return {"type": "union", "findings": findings}

        except Exception as e:
            logger.debug(f"[SQLiManager] UNION SQLi failed: {e}")

        # Step 2: Try Blind SQL Injection
        logger.info("[SQLiManager] Trying Blind SQLi...")
        self.blind_scanner = BlindSQLiScanner(self.target)
        findings = self.blind_scanner.scan()

        if findings:
            logger.info("[SQLiManager] ✅ Blind SQLi found")
            return {"type": "blind", "findings": findings}

        logger.info("[SQLiManager] ❌ No SQL injection found")
        return {"type": "none", "findings": []}
