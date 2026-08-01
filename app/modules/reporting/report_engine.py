"""
===========================================================
Project : Sentinel AI
Module  : Report Engine
File ID : REPORT-ENGINE-001
Version : 1.0.0
===========================================================

Description:
Main reporting engine responsible for building
security reports from analysis results.

===========================================================
"""

from __future__ import annotations

from app.modules.reporting.ai_report import AIReport
from app.modules.reporting.html_report import HTMLReport
from app.modules.reporting.pdf_report import PDFReport


class ReportEngine:
    """
    Main reporting engine.
    """

    # ======================================================
    # Constructor
    # ======================================================

    def __init__(self) -> None:

        self.html = HTMLReport()

        self.pdf = PDFReport()

        self.ai = AIReport()

    # ======================================================
    # Build Reports
    # ======================================================

    def build(
        self,
        analysis: dict,
    ) -> dict:
        """
        Build every available report.
        """

        reports = {
            "html": self.html.generate(
                analysis,
            ),
            "pdf": self.pdf.generate(
                analysis,
            ),
            "ai": self.ai.generate(
                analysis,
            ),
        }
        return reports


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    sample_analysis = {
        "target": "https://bugcrowd.com",
        "summary": {
            "score": 67,
            "risk_level": "High",
            "total_findings": 8,
        },
        "findings": [
            {
                "title": "Missing Content Security Policy",
                "severity": "Medium",
            },
            {
                "title": "Sensitive Secret Found in JavaScript",
                "severity": "High",
            },
            {
                "title": "API Endpoint Discovered",
                "severity": "Info",
            },
        ],
        "recommendations": [
            {
                "title": "Configure Content Security Policy",
                "priority": "Medium",
            },
            {
                "title": "Remove API Keys from JavaScript",
                "priority": "High",
            },
        ],
    }

    engine = ReportEngine()

    reports = engine.build(sample_analysis)

    print()

    print("=" * 60)

    print("Report Engine")

    print("=" * 60)

    print()

    print("Available Reports")

    print("-" * 60)

    for name in reports:
        print(f"✔ {name}")

    print()

    print("HTML Report")

    print("-" * 60)

    print(reports["html"])

    print()

    print("PDF Report")

    print("-" * 60)

    print(reports["pdf"])

    print()

    print("AI Report")

    print("-" * 60)

    print(reports["ai"])
