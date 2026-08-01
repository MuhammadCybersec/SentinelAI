"""
===========================================================
Project : Sentinel AI
Module  : AI Report Generator
File ID : REPORT-AI-001
Version : 1.0.0
===========================================================

Description:
Generates an AI-style executive security report from
analysis results.

===========================================================
"""

from __future__ import annotations


class AIReport:
    """
    Generates an AI-style security assessment report.
    """

    # ======================================================
    # Generate AI Report
    # ======================================================

    def generate(
        self,
        analysis: dict,
    ) -> str:
        """
        Generate AI report.

        Returns:
            Markdown text.
        """

        summary = analysis.get(
            "summary",
            {},
        )

        findings = analysis.get(
            "findings",
            [],
        )

        report = []

        # ==================================================
        # Header
        # ==================================================

        report.append("=" * 60)
        report.append("Sentinel AI Executive Security Report")
        report.append("=" * 60)
        report.append("")

        report.append(f"Target : {analysis.get('target', 'Unknown')}")

        report.append(f"Overall Risk : {summary.get('risk_level', 'Unknown')}")

        report.append(f"Risk Score : {summary.get('score', 0)}/100")

        report.append(f"Total Findings : {summary.get('total_findings', 0)}")

        report.append("")

        # ==================================================
        # Executive Summary
        # ==================================================

        report.append("Executive Summary")
        report.append("-" * 60)

        if summary.get("score", 0) >= 80:
            report.append(
                "The assessment identified multiple high-risk "
                "security issues requiring immediate attention."
            )

        elif summary.get("score", 0) >= 60:
            report.append(
                "The assessment identified several security "
                "weaknesses that should be addressed soon."
            )

        elif summary.get("score", 0) >= 30:
            report.append(
                "The target contains a limited number of "
                "security findings with moderate impact."
            )

        else:
            report.append(
                "No significant security weaknesses were "
                "identified during reconnaissance."
            )

        report.append("")
        # ==================================================
        # Critical Findings
        # ==================================================

        report.append("Critical Findings")
        report.append("-" * 60)

        if not findings:
            report.append("No findings detected.")

        else:
            for finding in findings:
                if hasattr(finding, "severity"):
                    severity = finding.severity
                    title = finding.title

                else:
                    severity = finding.get(
                        "severity",
                        "Info",
                    )

                    title = finding.get(
                        "title",
                        "Unknown Finding",
                    )

                report.append(f"[{severity}] {title}")

        report.append("")

        # ==================================================
        # Priority Actions
        # ==================================================

        report.append("Priority Actions")
        report.append("-" * 60)

        recommendations = analysis.get(
            "recommendations",
            [],
        )

        if recommendations:
            for index, item in enumerate(
                recommendations,
                start=1,
            ):
                recommendation = item.get(
                    "recommendation",
                    item.get(
                        "title",
                        "No recommendation available.",
                    ),
                )

                report.append(f"{index}. {recommendation}")

        else:
            report.append("No recommendations available.")

        report.append("")

        # ==================================================
        # Final Verdict
        # ==================================================

        report.append("Final Verdict")
        report.append("-" * 60)

        score = summary.get(
            "score",
            0,
        )

        if score >= 80:
            verdict = "High Risk - Immediate remediation is recommended."

        elif score >= 60:
            verdict = "Moderate Risk - Address findings as a priority."

        elif score >= 30:
            verdict = "Low Risk - Continue improving the security posture."

        else:
            verdict = "Minimal Risk - No major security concerns identified."

        report.append(verdict)

        report.append("")
        report.append("=" * 60)
        report.append("Generated by Sentinel AI")
        report.append("=" * 60)

        return "\n".join(report)


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    report = AIReport()

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
            },
            {
                "severity": "Medium",
                "title": "Missing Content Security Policy",
            },
            {
                "severity": "Info",
                "title": "Technology Identified",
            },
        ],
        "recommendations": [
            {
                "recommendation": "Remove exposed secrets from JavaScript.",
            },
            {
                "recommendation": "Configure a strict Content Security Policy.",
            },
            {
                "recommendation": "Review exposed API endpoints.",
            },
        ],
    }

    output = report.generate(sample)

    print()

    print(output)
