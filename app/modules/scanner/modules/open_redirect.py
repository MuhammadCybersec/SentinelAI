"""
===========================================================
Project : Sentinel AI
Module  : Open Redirect Scanner
File ID : SCANNER-OPENREDIRECT-001
Version : 1.0.0
===========================================================

Description:
Open Redirect Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class OpenRedirectScanner:
    """
    Detect Open Redirect vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Open Redirect"

        self.severity = "Medium"

        self.payloads = [
            "https://google.com",
            "https://example.com",
            "//google.com",
            "//example.com",
            "https://evil.com",
            "//evil.com",
            "/\\google.com",
            "////google.com",
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

        print(f"[Open Redirect] Scanning -> {url}")

        vulnerable = False

        detected_payload = ""

        for payload in self.payloads:

            # -------------------------------------------------
            # Future:
            # Inject redirect payload
            # Send request
            # Check Location header
            # Detect external redirect
            # -------------------------------------------------

            if False:

                vulnerable = True

                detected_payload = payload

                break

        if not vulnerable:

            return None

        return Finding(
            project_id=project_id,
            title="Open Redirect",
            description=("Potential Open Redirect vulnerability detected."),
            severity=self.severity,
            cvss=6.1,
            status="Open",
            module="Open Redirect Scanner",
            target=url,
            url=url,
            parameter="",
            payload=detected_payload,
            evidence="",
            recommendation=("Validate redirect destinations using an allowlist."),
            reference=(
                "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"
            ),
            cwe="CWE-601",
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
            "payloads": len(self.payloads),
            "type": "Active Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":

    scanner = OpenRedirectScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/redirect?next=/home",
    )

    print()

    if result is None:

        print("No Open Redirect Found")

    else:

        print(result)
