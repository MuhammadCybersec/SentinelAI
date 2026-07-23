"""
===========================================================
Project : Sentinel AI
Module  : CSRF Scanner
File ID : SCANNER-CSRF-001
Version : 1.0.0
===========================================================

Description:
Cross-Site Request Forgery (CSRF) Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class CSRFScanner:
    """
    Detect Cross-Site Request Forgery vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Cross-Site Request Forgery"

        self.severity = "Medium"

        self.test_methods = [
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ]

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

        print(f"[CSRF] Scanning -> {url}")

        vulnerable = False

        tested_method = ""

        for method in self.test_methods:

            # -------------------------------------------------
            # Future:
            # Detect state-changing forms
            # Verify CSRF token existence
            # Verify SameSite cookie protection
            # Attempt forged request
            # -------------------------------------------------

            if False:

                vulnerable = True

                tested_method = method

                break

        if not vulnerable:

            return None

        return Finding(
            project_id=project_id,
            title="Cross-Site Request Forgery",
            description=("Potential CSRF vulnerability detected."),
            severity=self.severity,
            cvss=6.5,
            status="Open",
            module="CSRF Scanner",
            target=url,
            url=url,
            parameter="",
            payload=tested_method,
            evidence="",
            recommendation=(
                "Use anti-CSRF tokens, SameSite cookies "
                "and Origin/Referer validation."
            ),
            reference=("https://owasp.org/www-community/attacks/csrf"),
            cwe="CWE-352",
            owasp="A01:2021 Broken Access Control",
            cve="",
        )

    # =====================================================
    # Scanner Information
    # =====================================================

    def info(self) -> dict:

        return {
            "name": self.name,
            "severity": self.severity,
            "payloads": len(self.test_methods),
            "type": "Active Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":

    scanner = CSRFScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/account/update",
    )

    print()

    if result is None:

        print("No CSRF Found")

    else:

        print(result)
