"""
===========================================================
Project : Sentinel AI
Module  : Recommendation Engine
File ID : ANALYSIS-RECOMMENDATION-001
Version : 1.0.0
===========================================================

Description:
Generates remediation recommendations for
security findings.

===========================================================
"""

from __future__ import annotations

from app.modules.analysis.findings import Finding


class RecommendationEngine:
    """
    Generates recommendations for findings.
    """

    # =======================================================
    # Priority Mapping
    # =======================================================

    PRIORITY = {
        "Critical": "Immediate",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Info": "Informational",
    }

    # =======================================================
    # Estimated Fix Time
    # =======================================================

    FIX_TIME = {
        "Critical": "Immediately",
        "High": "1 Day",
        "Medium": "3 Days",
        "Low": "1 Week",
        "Info": "Optional",
    }

    # =======================================================
    # Security Categories
    # =======================================================

    CATEGORY = {
        "headers": "Secure Headers",
        "waf": "Web Application Firewall",
        "technology": "Technology Stack",
        "js_secrets": "Secrets Management",
        "api": "API Security",
        "parameters": "Input Validation",
        "crawler": "Attack Surface",
        "wayback": "Historical Exposure",
        "javascript": "Client Side Security",
    }

    # =======================================================
    # Constructor
    # =======================================================

    def __init__(self):

        pass

    # =======================================================
    # Build Recommendation
    # =======================================================

    def _build(
        self,
        finding: Finding,
    ) -> dict:
        """
        Build recommendation for a single finding.
        """

        return {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "priority": self.PRIORITY.get(
                finding.severity,
                "Unknown",
            ),
            "estimated_fix_time": self.FIX_TIME.get(
                finding.severity,
                "Unknown",
            ),
            "category": self.CATEGORY.get(
                finding.module,
                "General Security",
            ),
            "recommendation": finding.recommendation,
            "references": finding.references,
            "confidence": finding.confidence,
            "module": finding.module,
            "target": finding.target,
        }
        # =======================================================

    # Generate Recommendations
    # =======================================================

    def generate(
        self,
        findings: list[Finding],
    ) -> list[dict]:
        """
        Generate recommendations for all findings.
        """

        recommendations: list[dict] = []

        for finding in findings:
            recommendations.append(self._build(finding))

        return recommendations


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    sample_findings = [
        Finding(
            id="HDR-001",
            title="Missing Content Security Policy",
            severity="Medium",
            cvss=5.3,
            module="headers",
            target="https://bugcrowd.com",
            description="",
            impact="",
            recommendation="Configure a strict Content-Security-Policy header.",
            references=[
                "https://owasp.org/www-project-secure-headers/",
            ],
            evidence="Header missing",
            confidence="High",
            cwe="CWE-693",
            owasp="A05:2021",
        ),
        Finding(
            id="JS-001",
            title="Sensitive Secret Found in JavaScript",
            severity="High",
            cvss=8.2,
            module="js_secrets",
            target="https://bugcrowd.com",
            description="",
            impact="",
            recommendation="Remove secrets from client-side JavaScript.",
            references=[
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
            ],
            evidence="Google API Key",
            confidence="High",
            cwe="CWE-798",
            owasp="A02:2021",
        ),
        Finding(
            id="API-001",
            title="API Endpoint Discovered",
            severity="Info",
            cvss=0.0,
            module="api",
            target="https://bugcrowd.com",
            description="",
            impact="",
            recommendation="Review authentication and authorization.",
            references=[
                "https://owasp.org/API-Security/",
            ],
            evidence="/api/v1/users",
            confidence="High",
            cwe=None,
            owasp=None,
        ),
    ]

    engine = RecommendationEngine()

    recommendations = engine.generate(sample_findings)

    print()

    print("=" * 60)

    print("Recommendations")

    print("=" * 60)

    print()

    print(f"Total Recommendations : {len(recommendations)}")

    print()

    for item in recommendations:
        print("-" * 60)

        print(f"Finding      : {item['title']}")

        print(f"Severity     : {item['severity']}")

        print(f"Priority     : {item['priority']}")

        print(f"Category     : {item['category']}")

        print(f"Fix Time     : {item['estimated_fix_time']}")

        print("Recommendation:")

        print(f"  {item['recommendation']}")

        print()

        if item["references"]:
            print("References:")

            for ref in item["references"]:
                print(f"  - {ref}")

        else:
            print("References: None")

        print()
