"""
===========================================================
Project : Sentinel AI
Module  : Risk Score Engine
File ID : ANALYSIS-RISK-001
Version : 1.0.0
===========================================================

Description:
Calculates overall security risk score based on
analysis findings.

===========================================================
"""

from __future__ import annotations

from collections import Counter

from app.modules.analysis.findings import Finding


class RiskScore:
    """
    Calculates project risk score.
    """

    # =======================================================
    # Severity Weights
    # =======================================================

    SEVERITY_WEIGHTS = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
        "Info": 0,
    }

    # =======================================================
    # Constructor
    # =======================================================

    def __init__(self):

        self.score = 0

        self.counter = Counter()

    # =======================================================
    # Count Findings
    # =======================================================

    def _count_findings(
        self,
        findings: list[Finding],
    ) -> None:
        """
        Count findings by severity.
        """

        self.counter.clear()

        for finding in findings:
            self.counter[finding.severity] += 1

    # =======================================================
    # Calculate Score
    # =======================================================

    def _calculate_score(
        self,
    ) -> int:
        """
        Calculate weighted score.
        """

        score = 0

        for severity, weight in self.SEVERITY_WEIGHTS.items():
            score += (
                self.counter.get(
                    severity,
                    0,
                )
                * weight
            )

        score = min(score, 100)

        self.score = score

        return score

    # =======================================================
    # Risk Level
    # =======================================================

    def _risk_level(
        self,
    ) -> str:
        """
        Convert score into risk level.
        """

        if self.score >= 90:
            return "Critical"

        if self.score >= 70:
            return "High"

        if self.score >= 40:
            return "Medium"

        if self.score >= 10:
            return "Low"

        return "Informational"

    # =======================================================
    # Calculate Risk
    # =======================================================

    def calculate(
        self,
        findings: list[Finding],
    ) -> dict:
        """
        Calculate overall project risk.

        Returns:
            Dictionary containing score,
            severity statistics and risk level.
        """

        self._count_findings(findings)

        score = self._calculate_score()

        return {
            "score": score,
            "risk_level": self._risk_level(),
            "total_findings": len(findings),
            "critical": self.counter.get("Critical", 0),
            "high": self.counter.get("High", 0),
            "medium": self.counter.get("Medium", 0),
            "low": self.counter.get("Low", 0),
            "info": self.counter.get("Info", 0),
        }


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    sample_findings = [
        Finding(
            id="HDR-001",
            title="Missing CSP",
            severity="Medium",
            cvss=5.3,
            module="headers",
            target="https://bugcrowd.com",
            description="",
            impact="",
            recommendation="",
            references=[],
            evidence="Content-Security-Policy missing",
            confidence="High",
            cwe="CWE-693",
            owasp="A05:2021",
        ),
        Finding(
            id="JS-001",
            title="JavaScript Secret",
            severity="High",
            cvss=8.2,
            module="js_secrets",
            target="https://bugcrowd.com",
            description="",
            impact="",
            recommendation="",
            references=[],
            evidence="Google API Key",
            confidence="High",
            cwe="CWE-798",
            owasp="A02:2021",
        ),
        Finding(
            id="API-001",
            title="API Endpoint",
            severity="Info",
            cvss=0.0,
            module="api",
            target="https://bugcrowd.com",
            description="",
            impact="",
            recommendation="",
            references=[],
            evidence="/api/v1/users",
            confidence="High",
            cwe=None,
            owasp=None,
        ),
        Finding(
            id="SQLI-001",
            title="SQL Injection",
            severity="Critical",
            cvss=9.8,
            module="scanner",
            target="https://bugcrowd.com",
            description="",
            impact="",
            recommendation="",
            references=[],
            evidence="id=1' OR 1=1--",
            confidence="Confirmed",
            cwe="CWE-89",
            owasp="A03:2021",
        ),
    ]

    engine = RiskScore()

    result = engine.calculate(sample_findings)

    print()

    print("=" * 60)

    print("Risk Score")

    print("=" * 60)

    print()

    print(f"Overall Score : {result['score']}/100")

    print(f"Risk Level    : {result['risk_level']}")

    print()

    print(f"Critical : {result['critical']}")

    print(f"High     : {result['high']}")

    print(f"Medium   : {result['medium']}")

    print(f"Low      : {result['low']}")

    print(f"Info     : {result['info']}")

    print()

    print(f"Total Findings : {result['total_findings']}")
