"""
===========================================================
Project : Sentinel AI
Module  : Statistics Engine
File ID : DASHBOARD-STAT-001
Version : 1.0.0
===========================================================

Description:
Calculate dashboard statistics from findings.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class StatisticsEngine:
    """
    Dashboard statistics engine.
    """

    # =====================================================
    # Total Findings
    # =====================================================

    def total(
        self,
        findings: list[Finding],
    ) -> int:

        return len(findings)

    # =====================================================
    # Severity Distribution
    # =====================================================

    def severity_distribution(
        self,
        findings: list[Finding],
    ) -> dict:

        stats = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
        }

        for finding in findings:

            severity = finding.severity

            if severity in stats:

                stats[severity] += 1

        return stats

    # =====================================================
    # Status Distribution
    # =====================================================

    def status_distribution(
        self,
        findings: list[Finding],
    ) -> dict:

        stats = {}

        for finding in findings:

            status = finding.status

            stats[status] = (
                stats.get(
                    status,
                    0,
                )
                + 1
            )

        return stats

    # =====================================================
    # Module Distribution
    # =====================================================

    def module_distribution(
        self,
        findings: list[Finding],
    ) -> dict:

        stats = {}

        for finding in findings:

            module = finding.module

            stats[module] = (
                stats.get(
                    module,
                    0,
                )
                + 1
            )

        return stats

    # =====================================================
    # Average CVSS
    # =====================================================

    def average_cvss(
        self,
        findings: list[Finding],
    ) -> float:

        if not findings:

            return 0.0

        total = sum(finding.cvss or 0 for finding in findings)

        return round(
            total / len(findings),
            2,
        )
        # =====================================================

    # Risk Score
    # =====================================================

    def risk_score(
        self,
        findings: list[Finding],
    ) -> float:

        weights = {
            "Critical": 10,
            "High": 7,
            "Medium": 5,
            "Low": 2,
            "Info": 1,
        }

        score = 0

        for finding in findings:

            score += weights.get(
                finding.severity,
                0,
            )

        return round(score, 2)

    # =====================================================
    # Top Modules
    # =====================================================

    def top_modules(
        self,
        findings: list[Finding],
        limit: int = 5,
    ) -> list[tuple[str, int]]:

        modules = self.module_distribution(
            findings,
        )

        return sorted(
            modules.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:limit]

    # =====================================================
    # Executive Summary
    # =====================================================

    def executive_summary(
        self,
        findings: list[Finding],
    ) -> dict:

        severity = self.severity_distribution(
            findings,
        )

        return {
            "total": self.total(
                findings,
            ),
            "critical": severity["Critical"],
            "high": severity["High"],
            "medium": severity["Medium"],
            "low": severity["Low"],
            "info": severity["Info"],
            "average_cvss": self.average_cvss(
                findings,
            ),
            "risk_score": self.risk_score(
                findings,
            ),
        }

    # =====================================================
    # Full Statistics
    # =====================================================

    def generate(
        self,
        findings: list[Finding],
    ) -> dict:

        return {
            "total": self.total(
                findings,
            ),
            "severity": self.severity_distribution(
                findings,
            ),
            "status": self.status_distribution(
                findings,
            ),
            "modules": self.module_distribution(
                findings,
            ),
            "average_cvss": self.average_cvss(
                findings,
            ),
            "risk_score": self.risk_score(
                findings,
            ),
            "top_modules": self.top_modules(
                findings,
            ),
            "summary": self.executive_summary(
                findings,
            ),
        }


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    findings = [
        Finding(
            project_id="demo",
            title="Missing CSP",
            severity="Medium",
            status="Open",
            module="headers",
            cvss=5.3,
        ),
        Finding(
            project_id="demo",
            title="Sensitive API Key",
            severity="High",
            status="Open",
            module="javascript",
            cvss=8.5,
        ),
        Finding(
            project_id="demo",
            title="Missing X-Frame-Options",
            severity="Medium",
            status="Fixed",
            module="headers",
            cvss=5.0,
        ),
    ]

    engine = StatisticsEngine()

    print("=" * 60)
    print("Statistics Engine Test")
    print("=" * 60)

    print()

    print(engine.generate(findings))
