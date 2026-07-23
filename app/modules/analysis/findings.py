"""
===========================================================
Project : Sentinel AI
Module  : Finding Model
File ID : ANALYSIS-FINDING-001
Version : 1.0.0
===========================================================

Description:
Standard Finding object used across the entire
Analysis Engine.

Every analyzer converts its output into this format.

===========================================================
"""

from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field

# ===========================================================
# ANALYSIS-FINDING-001
# Finding Model
# ===========================================================


@dataclass(slots=True)
class Finding:
    """
    Represents a standardized security finding.
    """

    # -------------------------------------------------------
    # Finding ID
    # Example:
    # HDR-001
    # JS-001
    # API-002
    # -------------------------------------------------------

    id: str

    # -------------------------------------------------------
    # Finding Title
    # -------------------------------------------------------

    title: str

    # -------------------------------------------------------
    # Severity
    # Critical
    # High
    # Medium
    # Low
    # Info
    # -------------------------------------------------------

    severity: str

    # -------------------------------------------------------
    # CVSS Score
    # -------------------------------------------------------

    cvss: float

    # -------------------------------------------------------
    # Source Module
    # -------------------------------------------------------

    module: str

    # -------------------------------------------------------
    # Target URL
    # -------------------------------------------------------

    target: str

    # -------------------------------------------------------
    # Description
    # -------------------------------------------------------

    description: str

    # -------------------------------------------------------
    # Security Impact
    # -------------------------------------------------------

    impact: str

    # -------------------------------------------------------
    # Recommendation
    # -------------------------------------------------------

    recommendation: str

    # -------------------------------------------------------
    # References
    # -------------------------------------------------------

    references: list[str] = field(default_factory=list)

    # -------------------------------------------------------
    # Evidence
    # -------------------------------------------------------

    evidence: str = ""

    # -------------------------------------------------------
    # Confidence
    # High / Medium / Low
    # -------------------------------------------------------

    confidence: str = "High"

    # -------------------------------------------------------
    # CWE
    # -------------------------------------------------------

    cwe: str | None = None

    # -------------------------------------------------------
    # OWASP
    # -------------------------------------------------------

    owasp: str | None = None

    # -------------------------------------------------------
    # CVE
    # -------------------------------------------------------

    cve: str | None = None

    # =======================================================
    # Convert Finding To Dictionary
    # =======================================================

    def to_dict(self) -> dict:
        """
        Convert finding into dictionary.
        """

        return asdict(self)


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    finding = Finding(
        id="HDR-001",
        title="Missing Content Security Policy",
        severity="Medium",
        cvss=5.3,
        module="headers",
        target="https://bugcrowd.com",
        description="Content-Security-Policy header is missing.",
        impact="May increase the risk of Cross Site Scripting (XSS).",
        recommendation=("Configure a strict Content-Security-Policy header."),
        references=[
            "https://owasp.org/www-project-secure-headers/",
        ],
        evidence="Response header 'Content-Security-Policy' not found.",
        confidence="High",
        cwe="CWE-693",
        owasp="A05:2021 Security Misconfiguration",
        cve=None,
    )

    print("=" * 60)
    print("Finding Test")
    print("=" * 60)

    print(finding.to_dict())
