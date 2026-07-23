"""
===========================================================
Project : Sentinel AI
Module  : Report Export Engine
File ID : REPORT-EXPORT-001
Version : 1.0.0
===========================================================

Description:
Exports all generated reports into a single directory.

===========================================================
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from app.modules.reporting.ai_report import AIReport
from app.modules.reporting.html_report import HTMLReport
from app.modules.reporting.pdf_report import PDFReport


class ExportEngine:
    """
    Export all reports.
    """

    def __init__(self) -> None:

        self.html = HTMLReport()
        self.pdf = PDFReport()
        self.ai = AIReport()

    # ======================================================
    # Export Reports
    # ======================================================

    def export(
        self,
        analysis: dict,
        output_directory: str = "reports",
    ) -> dict:
        """
        Export HTML, PDF and AI reports.

        Returns:
            Dictionary containing generated files.
        """

        target = (
            analysis.get("target", "unknown")
            .replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        report_directory = Path(output_directory) / f"{target}_{timestamp}"

        report_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ==================================================
        # Output Files
        # ==================================================

        html_file = report_directory / "report.html"

        pdf_file = report_directory / "report.pdf"

        ai_file = report_directory / "ai_report.txt"

        # ==================================================
        # Generate Reports
        # ==================================================

        html_content = self.html.generate(
            analysis,
        )

        pdf_output = self.pdf.generate(
            analysis,
            str(pdf_file),
        )

        ai_content = self.ai.generate(
            analysis,
        )
        # ==================================================
        # Save HTML Report
        # ==================================================

        html_file.write_text(
            html_content,
            encoding="utf-8",
        )

        # ==================================================
        # Save AI Report
        # ==================================================

        ai_file.write_text(
            ai_content,
            encoding="utf-8",
        )

        # ==================================================
        # Export Summary
        # ==================================================

        return {
            "directory": str(report_directory),
            "html": str(html_file),
            "pdf": str(pdf_output),
            "ai": str(ai_file),
        }


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    exporter = ExportEngine()

    sample = {
        "target": "https://bugcrowd.com",
        "summary": {
            "score": 68,
            "risk_level": "High",
            "total_findings": 3,
        },
        "findings": [
            {
                "severity": "High",
                "title": "Sensitive Secret Found in JavaScript",
                "evidence": "AIzaXXXXXXXXXXXXXXXX",
            },
            {
                "severity": "Medium",
                "title": "Missing Content Security Policy",
                "evidence": "Header Missing",
            },
            {
                "severity": "Info",
                "title": "Technology Identified",
                "evidence": "Server: nginx",
            },
        ],
        "recommendations": [
            {
                "priority": "High",
                "recommendation": "Remove exposed secrets from JavaScript.",
            },
            {
                "priority": "Medium",
                "recommendation": "Configure Content Security Policy.",
            },
            {
                "priority": "Medium",
                "recommendation": "Review exposed API endpoints.",
            },
        ],
    }

    result = exporter.export(sample)

    print()

    print("=" * 60)

    print("Export Complete")

    print("=" * 60)

    print()

    for key, value in result.items():

        print(f"{key:<12}: {value}")
