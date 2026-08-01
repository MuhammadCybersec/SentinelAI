"""
===========================================================
Project : Sentinel AI
Module  : Clickjacking Scanner
File ID : SCANNER-CLICKJACKING-001
Version : 1.0.0
===========================================================

Description:
Clickjacking Vulnerability Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class ClickjackingScanner:
    """
    Detect Clickjacking vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Clickjacking"

        self.severity = "Medium"

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
        """

        print(f"[Clickjacking] Scanning -> {url}")

        # -------------------------------------------------
        # Future:
        # Request page
        # Check X-Frame-Options
        # Check CSP frame-ancestors
        # Detect framing protection
        # -------------------------------------------------

        vulnerable = False

        if not vulnerable:
            return None

        return Finding(
            project_id=project_id,
            title="Clickjacking",
            description=("Potential Clickjacking vulnerability detected."),
            severity=self.severity,
            cvss=4.3,
            status="Open",
            module="Clickjacking Scanner",
            target=url,
            url=url,
            parameter="",
            payload="",
            evidence="",
            recommendation=(
                "Configure X-Frame-Options or Content-Security-Policy frame-ancestors."
            ),
            reference=("https://owasp.org/www-community/attacks/Clickjacking"),
            cwe="CWE-1021",
            owasp="A05:2021 Security Misconfiguration",
            cve="",
        )

    # =====================================================
    # Scanner Information
    # =====================================================

    def info(self) -> dict:

        return {
            "name": self.name,
            "severity": self.severity,
            "type": "Passive Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    scanner = ClickjackingScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com",
    )

    print()

    if result is None:
        print("No Clickjacking Found")

    else:
        print(result)
