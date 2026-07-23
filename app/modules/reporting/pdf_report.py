"""
===========================================================
Project : Sentinel AI
Module  : PDF Report
File ID : REPORT-PDF-001
Version : 1.0.0
===========================================================

Description:
Generates a professional PDF security report.

===========================================================
"""

from __future__ import annotations

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
)


class PDFReport:
    """
    Generates PDF reports.
    """

    # ======================================================
    # Generate PDF
    # ======================================================

    def generate(
        self,
        analysis: dict,
        output_file: str = "sentinel_report.pdf",
    ) -> str:
        """
        Generate PDF report.

        Returns:
            Output filename.
        """

        styles = getSampleStyleSheet()

        document = SimpleDocTemplate(
            output_file,
        )

        story = []

        # ==================================================
        # Title
        # ==================================================

        story.append(
            Paragraph(
                "Sentinel AI Security Report",
                styles["Title"],
            )
        )

        story.append(
            Spacer(
                1,
                20,
            )
        )

        # ==================================================
        # Target
        # ==================================================

        story.append(
            Paragraph(
                f"<b>Target:</b> {analysis.get('target','Unknown')}",
                styles["Normal"],
            )
        )

        story.append(
            Spacer(
                1,
                12,
            )
        )

        # ==================================================
        # Summary
        # ==================================================

        summary = analysis.get(
            "summary",
            {},
        )

        story.append(
            Paragraph(
                "<b>Executive Summary</b>",
                styles["Heading2"],
            )
        )

        story.append(
            Paragraph(
                f"Risk Score : {summary.get('score',0)}/100",
                styles["Normal"],
            )
        )

        story.append(
            Paragraph(
                f"Risk Level : {summary.get('risk_level','Unknown')}",
                styles["Normal"],
            )
        )

        story.append(
            Paragraph(
                f"Total Findings : {summary.get('total_findings',0)}",
                styles["Normal"],
            )
        )

        story.append(
            Spacer(
                1,
                20,
            )
        )
        # ==================================================
        # Findings
        # ==================================================

        findings = analysis.get(
            "findings",
            [],
        )

        story.append(
            Paragraph(
                "<b>Findings</b>",
                styles["Heading2"],
            )
        )

        story.append(
            Spacer(
                1,
                10,
            )
        )

        for finding in findings:

            if hasattr(finding, "title"):

                title = finding.title
                severity = finding.severity
                evidence = finding.evidence

            else:

                title = finding.get("title", "Unknown")
                severity = finding.get("severity", "Info")
                evidence = finding.get("evidence", "")

            story.append(
                Paragraph(
                    f"<b>[{severity}]</b> {title}",
                    styles["Normal"],
                )
            )

            if evidence:

                story.append(
                    Paragraph(
                        f"Evidence: {evidence}",
                        styles["Normal"],
                    )
                )

            story.append(
                Spacer(
                    1,
                    8,
                )
            )

        # ==================================================
        # Recommendations
        # ==================================================

        recommendations = analysis.get(
            "recommendations",
            [],
        )

        story.append(
            Paragraph(
                "<b>Recommendations</b>",
                styles["Heading2"],
            )
        )

        story.append(
            Spacer(
                1,
                10,
            )
        )

        for item in recommendations:

            recommendation = item.get(
                "recommendation",
                item.get("title", ""),
            )

            priority = item.get(
                "priority",
                "Unknown",
            )

            story.append(
                Paragraph(
                    f"<b>{priority}</b>: {recommendation}",
                    styles["Normal"],
                )
            )

        story.append(
            Spacer(
                1,
                20,
            )
        )

        # ==================================================
        # Footer
        # ==================================================

        story.append(
            Paragraph(
                "Generated by Sentinel AI",
                styles["Italic"],
            )
        )

        # ==================================================
        # Build PDF
        # ==================================================

        document.build(story)

        return output_file


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":

    report = PDFReport()

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
                "evidence": "nginx",
            },
        ],
        "recommendations": [
            {
                "priority": "High",
                "recommendation": "Remove secrets from JavaScript.",
            },
            {
                "priority": "Medium",
                "recommendation": "Configure Content Security Policy.",
            },
        ],
    }

    output = report.generate(sample)

    print()

    print("=" * 60)

    print("PDF Report")

    print("=" * 60)

    print()

    print(f"Generated Successfully: {output}")
