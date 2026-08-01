"""
===========================================================
Project : Sentinel AI
Module  : PDF Report
File ID : REPORT-PDF-001
Version : 1.1.0
===========================================================

Description:
Generates a professional PDF security report.

===========================================================
"""

from __future__ import annotations

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
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
                f"<b>Target:</b> {analysis.get('target', 'Unknown')}",
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
                f"Risk Score : {summary.get('score', 0)}/100",
                styles["Normal"],
            )
        )

        story.append(
            Paragraph(
                f"Risk Level : {summary.get('risk_level', 'Unknown')}",
                styles["Normal"],
            )
        )

        story.append(
            Paragraph(
                f"Total Findings : {summary.get('total_findings', 0)}",
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
                title = getattr(finding, "title", "Unknown")
                severity = getattr(finding, "severity", "Info")
                evidence = getattr(finding, "evidence", "")

                url = getattr(finding, "url", "N/A")
                payload = getattr(finding, "payload", "N/A")
                cwe = getattr(finding, "cwe", "N/A")
                cvss = getattr(finding, "cvss", "N/A")

            else:
                title = finding.get("title", "Unknown")
                severity = finding.get("severity", "Info")
                evidence = finding.get("evidence", "")

                url = finding.get("url", "N/A")
                payload = finding.get("payload", "N/A")
                cwe = finding.get("cwe", "N/A")
                cvss = finding.get("cvss", "N/A")

            story.append(
                Paragraph(
                    f"<b>[{severity}]</b> {title}",
                    styles["Normal"],
                )
            )

            story.append(
                Paragraph(
                    f"<b>URL:</b> {url}",
                    styles["Normal"],
                )
            )

            story.append(
                Paragraph(
                    f"<b>Payload:</b> {payload}",
                    styles["Normal"],
                )
            )

            story.append(
                Paragraph(
                    f"<b>CWE:</b> {cwe}",
                    styles["Normal"],
                )
            )

            story.append(
                Paragraph(
                    f"<b>CVSS:</b> {cvss}",
                    styles["Normal"],
                )
            )

            if evidence:
                story.append(
                    Paragraph(
                        f"<b>Evidence:</b> {evidence}",
                        styles["Normal"],
                    )
                )

            story.append(
                Spacer(
                    1,
                    10,
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
