"""
===========================================================
Project : Sentinel AI
Module  : Analysis Engine
File ID : ANALYSIS-ENGINE-001
Version : 1.0.0
===========================================================

Description:
Combines Analyzer, Risk Score and Recommendation
Engine into one complete analysis pipeline.

===========================================================
"""

from __future__ import annotations

from app.modules.analysis.analyzer import Analyzer
from app.modules.analysis.risk_score import RiskScore
from app.modules.analysis.recommendation import (
    RecommendationEngine,
)


class AnalysisEngine:
    """
    Main analysis engine.
    """

    # ======================================================
    # Constructor
    # ======================================================

    def __init__(self) -> None:

        self.analyzer = Analyzer()

        self.risk_engine = RiskScore()

        self.recommendation_engine = RecommendationEngine()

    # ======================================================
    # Analyze Recon Results
    # ======================================================

    def analyze(
        self,
        target: str,
        recon_results: dict,
    ) -> dict:
        """
        Execute complete analysis.

        Args:
            target:
                Target URL

            recon_results:
                Output produced by ReconEngine

        Returns:
            Complete analysis report.
        """

        # ---------------------------------------------
        # Analyzer
        # ---------------------------------------------

        findings = self.analyzer.analyze(
            recon_results,
        )

        # ---------------------------------------------
        # Risk Score
        # ---------------------------------------------

        risk = self.risk_engine.calculate(
            findings,
        )

        # ---------------------------------------------
        # Recommendations
        # ---------------------------------------------

        recommendations = self.recommendation_engine.generate(
            findings,
        )

        # ---------------------------------------------
        # Final Analysis Report
        # ---------------------------------------------

        report = {
            "target": target,
            "summary": risk,
            "findings": findings,
            "recommendations": recommendations,
        }

        return report


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    sample_results = {
        "headers": {
            "missing": [
                "Content-Security-Policy",
                "X-Frame-Options",
            ],
        },
        "waf": {
            "detected": True,
            "name": "Fastly",
        },
        "js_secrets": [
            {
                "type": "Google API Key",
                "value": "AIzaXXXXXXXXXXXXXXXXXXXXXXXX",
                "source": "main.js",
            }
        ],
        "api": [
            "https://example.com/api/v1/users",
        ],
        "parameters": [
            {
                "parameter": "id",
                "url": "https://example.com?id=1",
            },
            {
                "parameter": "redirect",
                "url": "https://example.com/login?redirect=dashboard",
            },
        ],
        "technology": {
            "Server": "nginx",
        },
    }

    engine = AnalysisEngine()

    report = engine.analyze(
        target="https://bugcrowd.com",
        recon_results=sample_results,
    )

    print()

    print("=" * 60)

    print("Analysis Engine")

    print("=" * 60)

    print()

    print("Target:")

    print(report["target"])

    print()

    print("Summary")

    print("-" * 60)

    summary = report["summary"]

    print(f"Score          : {summary['score']}/100")

    print(f"Risk Level     : {summary['risk_level']}")

    print(f"Total Findings : {summary['total_findings']}")

    print()

    print("Findings")

    print("-" * 60)

    for finding in report["findings"]:

        print(f"[{finding.severity}] {finding.title}")

    print()

    print("Recommendations")

    print("-" * 60)

    for recommendation in report["recommendations"]:

        print(f"{recommendation['priority']:15}" f"{recommendation['title']}")
