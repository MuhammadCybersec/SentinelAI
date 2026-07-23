"""
===========================================================
Project : Sentinel AI
Module  : XSS Scanner
File ID : SCANNER-XSS-001
Version : 1.0.0
===========================================================

Description:
Cross-Site Scripting (XSS) Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class XSSScanner:
    """
    Detect Cross-Site Scripting vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Cross Site Scripting"

        self.severity = "High"

    # =====================================================
    # Scan
    # =====================================================

    def scan(
        self,
        project_id: str,
        url: str,
    ) -> Finding | None:
        """
        Scan a single URL.

        Returns
        -------
        Finding
            Vulnerability if detected.

        None
            No vulnerability found.
        """

        print(f"[XSS] Scanning -> {url}")

        # -------------------------------------------------
        # Placeholder
        # Real payload testing will be added later.
        # -------------------------------------------------

        vulnerable = False

        if not vulnerable:

            return None

        # -------------------------------------------------
        # Create Finding
        # -------------------------------------------------

        return Finding(
            project_id=project_id,
            title="Cross Site Scripting (XSS)",
            description=("Potential reflected " "Cross Site Scripting detected."),
            severity=self.severity,
            cvss=6.5,
            status="Open",
            module="XSS Scanner",
            target=url,
            url=url,
            parameter="",
            payload="",
            evidence="",
            recommendation=("Validate and encode " "all untrusted input."),
            reference=("https://owasp.org/www-community/attacks/xss/"),
            cwe="CWE-79",
            owasp="A03:2021 Injection",
            cve="",
        )

    # =====================================================
    # Scanner Information
    # =====================================================

    def info(
        self,
    ) -> dict:

        return {
            "name": self.name,
            "severity": self.severity,
            "type": "Active Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":

    scanner = XSSScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com",
    )

    print()

    if result is None:

        print("No XSS Found")

    else:

        print(result)
