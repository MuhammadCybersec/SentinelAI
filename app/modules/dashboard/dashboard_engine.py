"""
===========================================================
Project : Sentinel AI
Module  : Dashboard Engine
File ID : DASHBOARD-ENGINE-001
Version : 1.0.0
===========================================================

Description:
Build dashboard data from findings.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding
from app.modules.dashboard.statistics_engine import (
    StatisticsEngine,
)


class DashboardEngine:
    """
    Dashboard data engine.
    """

    def __init__(self) -> None:

        self.statistics = StatisticsEngine()

    # =====================================================
    # Executive Dashboard
    # =====================================================

    def executive_dashboard(
        self,
        findings: list[Finding],
    ) -> dict:

        return {
            "summary": self.statistics.executive_summary(
                findings,
            ),
            "severity": self.statistics.severity_distribution(
                findings,
            ),
            "status": self.statistics.status_distribution(
                findings,
            ),
            "modules": self.statistics.module_distribution(
                findings,
            ),
        }

    # =====================================================
    # Technical Dashboard
    # =====================================================

    def technical_dashboard(
        self,
        findings: list[Finding],
    ) -> dict:

        return {
            "statistics": self.statistics.generate(
                findings,
            ),
            "findings": findings,
        }

    # =====================================================
    # Risk Dashboard
    # =====================================================

    def risk_dashboard(
        self,
        findings: list[Finding],
    ) -> dict:

        return {
            "risk_score": self.statistics.risk_score(
                findings,
            ),
            "average_cvss": self.statistics.average_cvss(
                findings,
            ),
            "top_modules": self.statistics.top_modules(
                findings,
            ),
        }
        # =====================================================

    # Health Score
    # =====================================================

    def health_score(
        self,
        findings: list[Finding],
    ) -> int:
        """
        Calculate overall security health score (0-100).
        """

        risk = self.statistics.risk_score(
            findings,
        )

        score = max(
            0,
            100 - int(risk),
        )

        return score

    # =====================================================
    # Project Overview
    # =====================================================

    def project_overview(
        self,
        findings: list[Finding],
    ) -> dict:

        return {
            "health_score": self.health_score(
                findings,
            ),
            "risk_score": self.statistics.risk_score(
                findings,
            ),
            "average_cvss": self.statistics.average_cvss(
                findings,
            ),
            "total_findings": self.statistics.total(
                findings,
            ),
        }

    # =====================================================
    # Complete Dashboard
    # =====================================================

    def generate(
        self,
        findings: list[Finding],
    ) -> dict:

        return {
            "overview": self.project_overview(
                findings,
            ),
            "executive": self.executive_dashboard(
                findings,
            ),
            "technical": self.technical_dashboard(
                findings,
            ),
            "risk": self.risk_dashboard(
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
            title="Missing CSP Header",
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
            severity="Low",
            status="Fixed",
            module="headers",
            cvss=3.2,
        ),
    ]

    engine = DashboardEngine()

    dashboard = engine.generate(
        findings,
    )

    print("=" * 60)
    print("Dashboard Engine Test")
    print("=" * 60)

    print()

    for section, data in dashboard.items():
        print("-" * 60)

        print(section.upper())

        print(data)

        print()
