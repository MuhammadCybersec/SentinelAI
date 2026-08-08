"""
SQL Injection Finding Model
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Optional


@dataclass(slots=True)
class SQLFinding:
    """
    SQL Injection finding with full vulnerability metadata.
    """

    # Core finding data
    vulnerable: bool = False
    url: str = ""
    parameter: str = ""
    payload: str = ""
    technique: str = ""
    dbms: str = ""
    evidence: List[str] = field(default_factory=list)

    # Vulnerability Metadata
    title: str = "SQL Injection Vulnerability Detected"
    description: str = ""
    severity: str = "High"
    cwe: str = "CWE-89"
    owasp: str = "OWASP Top 10 2021 - A03: Injection"
    cvss: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (8.2)"
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    confidence: float = 0.0
    line_number: int = 0
    file_path: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    # Scanner context
    scanner_name: str = "sqli"
    vulnerability_type: str = "sql_injection"
    method: str = "GET"
    status_code: int = 0
    response_time: float = 0.0
    tags: List[str] = field(default_factory=list)
    scan_id: Optional[str] = None
    raw_response: Optional[str] = None
    scanner_version: Optional[str] = None

    # Legacy/backward compatibility
    vulnerable: bool = True
