"""
===========================================================
Project : Sentinel AI
Module  : Recon Result Model
File ID : CORE-RECONRESULT-001
Version : 1.0.0
===========================================================
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReconResult:
    """
    Central data model for all reconnaissance results.

    Every recon module reads from or writes to this object.
    """

    # ======================================================
    # Target Information
    # ======================================================

    target: str = ""
    final_url: str = ""
    hostname: str = ""
    ip_address: str = ""

    # ======================================================
    # HTTP
    # ======================================================

    status_code: int | None = None
    title: str = ""
    server: str = ""

    headers: dict[str, str] = field(default_factory=dict)

    # ======================================================
    # DNS
    # ======================================================

    dns_records: dict[str, list[str]] = field(default_factory=dict)

    # ======================================================
    # Ports
    # ======================================================

    open_ports: list[int] = field(default_factory=list)

    # ======================================================
    # WAF
    # ======================================================

    waf: dict[str, Any] = field(default_factory=dict)

    # ======================================================
    # Technologies
    # ======================================================

    technologies: list[str] = field(default_factory=list)

    # ======================================================
    # JavaScript
    # ======================================================

    javascript_files: list[str] = field(default_factory=list)

    javascript_endpoints: list[str] = field(default_factory=list)

    javascript_secrets: list[str] = field(default_factory=list)

    # ======================================================
    # API Discovery
    # ======================================================

    api_endpoints: list[str] = field(default_factory=list)

    # ======================================================
    # Wayback
    # ======================================================

    wayback_urls: list[str] = field(default_factory=list)

    interesting_urls: list[str] = field(default_factory=list)

    # ======================================================
    # Parameters
    # ======================================================

    parameters: list[str] = field(default_factory=list)

    high_value_parameters: list[str] = field(default_factory=list)

    # ======================================================
    # Risk
    # ======================================================

    risk_scores: list[dict[str, Any]] = field(default_factory=list)

    # ======================================================
    # Errors
    # ======================================================

    errors: list[str] = field(default_factory=list)

    # ======================================================
    # Helpers
    # ======================================================

    def add_error(self, message: str) -> None:
        """Add an error to the report."""

        self.errors.append(message)

    def has_errors(self) -> bool:
        """Return True if any module produced errors."""

        return len(self.errors) > 0

    def to_dict(self) -> dict[str, Any]:
        """Convert ReconResult into a dictionary."""

        return self.__dict__
