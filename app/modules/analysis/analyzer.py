"""
===========================================================
Project : Sentinel AI
Module  : Analysis Engine
File ID : ANALYSIS-ENGINE-001
Version : 1.0.0
===========================================================

Description:
Converts Recon Engine results into standardized
Finding objects.

===========================================================
"""

from __future__ import annotations

from app.modules.analysis.findings import Finding
from app.modules.analysis.templates import TEMPLATE_DATABASE


class Analyzer:
    """
    Converts reconnaissance results into Findings.
    """

    def __init__(self) -> None:

        self.findings: list[Finding] = []

    # =======================================================
    # Create Finding
    # =======================================================

    def _create_finding(
        self,
        template_id: str,
        target: str,
        evidence: str,
    ) -> None:
        """
        Create Finding from template.
        """

        template = TEMPLATE_DATABASE.get(template_id)

        if template is None:
            return

        finding = Finding(
            id=template["id"],
            title=template["title"],
            severity=template["severity"],
            cvss=template["cvss"],
            module=template["module"],
            target=target,
            description=template["description"],
            impact=template["impact"],
            recommendation=template["recommendation"],
            references=template["references"],
            evidence=evidence,
            confidence="High",
            cwe=template.get("cwe"),
            owasp=template.get("owasp"),
            cve=None,
        )

        self.findings.append(finding)

    # =======================================================
    # Headers Analyzer
    # =======================================================

    def analyze_headers(
        self,
        target: str,
        headers: dict,
    ) -> None:
        """
        Analyze HTTP security headers.
        """

        if not headers:
            return

        missing = headers.get(
            "missing_headers",
            [],
        )

        mapping = {
            "Content-Security-Policy": "HDR-001",
            "X-Frame-Options": "HDR-002",
            "X-Content-Type-Options": "HDR-003",
            "Referrer-Policy": "HDR-004",
            "Permissions-Policy": "HDR-005",
        }

        for header in missing:
            template = mapping.get(header)

            if template:
                self._create_finding(
                    template_id=template,
                    target=target,
                    evidence=f"Missing Header: {header}",
                )

    # =======================================================
    # WAF Analyzer
    # =======================================================

    def analyze_waf(
        self,
        target: str,
        waf: dict,
    ) -> None:
        """
        Analyze Web Application Firewall.
        """

        if not waf:
            return

        detected = waf.get(
            "detected",
            False,
        )

        if detected:
            vendor = waf.get(
                "vendor",
                "Unknown",
            )

            self._create_finding(
                template_id="WAF-001",
                target=target,
                evidence=f"WAF Detected ({vendor})",
            )

        else:
            self._create_finding(
                template_id="WAF-002",
                target=target,
                evidence="No WAF Detected",
            )

    # =======================================================
    # JavaScript Secrets
    # =======================================================

    def analyze_js_secrets(
        self,
        target: str,
        secrets: list,
    ) -> None:
        """
        Analyze JavaScript secrets.
        """

        if not secrets:
            return

        for secret in secrets:
            secret_type = secret.get(
                "type",
                "Unknown",
            )

            value = secret.get(
                "value",
                "",
            )

            source = secret.get(
                "source",
                "",
            )

            self._create_finding(
                template_id="JS-001",
                target=target,
                evidence=(f"{secret_type}\n{value}\n{source}"),
            )

    # =======================================================
    # API Analyzer
    # =======================================================

    def analyze_api(
        self,
        target: str,
        apis: list,
    ) -> None:
        """
        Analyze discovered API endpoints.
        """

        if not apis:
            return

        for api in apis:
            if isinstance(api, dict):
                endpoint = api.get("url", "")
            else:
                endpoint = str(api)

            self._create_finding(
                template_id="API-001",
                target=target,
                evidence=endpoint,
            )

    # =======================================================
    # Parameter Analyzer
    # =======================================================

    def analyze_parameters(
        self,
        target: str,
        parameters: dict,
    ) -> None:
        """
        Analyze discovered parameters.
        """

        if not parameters:
            return

        for parameter, urls in parameters.items():
            evidence = parameter

            if urls:
                evidence += "\n"

                evidence += "\n".join(urls)

            self._create_finding(
                template_id="PARAM-001",
                target=target,
                evidence=evidence,
            )

    # =======================================================
    # Technology Analyzer
    # =======================================================

    def analyze_technology(
        self,
        target: str,
        technologies: dict,
    ) -> None:
        """
        Analyze detected technologies.
        """

        if not technologies:
            return

        for name, value in technologies.items():
            self._create_finding(
                template_id="TECH-001",
                target=target,
                evidence=f"{name}: {value}",
            )

    # =======================================================
    # Main Analyzer
    # =======================================================

    def analyze(
        self,
        recon_results: dict,
    ) -> list[Finding]:
        """
        Analyze complete Recon Engine output.
        """

        self.findings.clear()

        target = recon_results.get(
            "target",
            "",
        )

        self.analyze_headers(
            target,
            recon_results.get(
                "headers",
                {},
            ),
        )

        self.analyze_waf(
            target,
            recon_results.get(
                "waf",
                {},
            ),
        )

        self.analyze_js_secrets(
            target,
            recon_results.get(
                "js_secrets",
                [],
            ),
        )

        self.analyze_api(
            target,
            recon_results.get(
                "api",
                [],
            ),
        )

        self.analyze_parameters(
            target,
            recon_results.get(
                "parameters",
                {},
            ),
        )

        self.analyze_technology(
            target,
            recon_results.get(
                "technology",
                {},
            ),
        )

        return self.findings


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    analyzer = Analyzer()

    sample = {
        "target": "https://bugcrowd.com",
        "headers": {
            "missing_headers": [
                "Content-Security-Policy",
                "X-Frame-Options",
            ]
        },
        "waf": {
            "detected": True,
            "vendor": "Fastly",
        },
        "technology": {
            "Server": "nginx",
        },
        "js_secrets": [
            {
                "type": "Google API Key",
                "value": "AIzaXXXXXXXXXXXXXXXXXXXXXXXX",
                "source": "main.js",
            }
        ],
        "parameters": {
            "id": [
                "https://example.com?id=1",
            ],
            "redirect": [
                "https://example.com/login?redirect=dashboard",
            ],
        },
        "api": [
            {
                "url": "https://example.com/api/v1/users",
            }
        ],
    }

    findings = analyzer.analyze(sample)

    print()

    print("=" * 60)

    print("Analysis Engine")

    print("=" * 60)

    print()

    print(f"Total Findings : {len(findings)}")

    print()

    for finding in findings:
        print(f"[{finding.severity}] {finding.title}")

        print(f"Evidence : {finding.evidence}")

        print()
