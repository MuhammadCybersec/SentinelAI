"""
===========================================================
Project : Sentinel AI
Module  : IDOR Scanner
File ID : SCANNER-IDOR-001
Version : 1.0.0
===========================================================

Description:
Insecure Direct Object Reference (IDOR) Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class IDORScanner:
    """
    Detect Insecure Direct Object Reference vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Insecure Direct Object Reference"

        self.severity = "High"

        self.test_values = [
            "1",
            "2",
            "3",
            "10",
            "100",
            "9999",
            "admin",
            "test",
            "guest",
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

        print(f"[IDOR] Scanning -> {url}")

        vulnerable = False

        tested_value = ""

        for value in self.test_values:
            # -------------------------------------------------
            # Future:
            # Replace object identifiers
            # Send request
            # Compare authorization
            # Detect unauthorized access
            # -------------------------------------------------

            if False:
                vulnerable = True

                tested_value = value

                break

        if not vulnerable:
            return None

        return Finding(
            project_id=project_id,
            title="Insecure Direct Object Reference (IDOR)",
            description=("Potential IDOR vulnerability detected."),
            severity=self.severity,
            cvss=8.1,
            status="Open",
            module="IDOR Scanner",
            target=url,
            url=url,
            parameter="",
            payload=tested_value,
            evidence="",
            recommendation=(
                "Implement proper authorization checks for every object request."
            ),
            reference=(
                "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet"
            ),
            cwe="CWE-639",
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
            "payloads": len(self.test_values),
            "type": "Active Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    scanner = IDORScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/user?id=1",
    )

    print()

    if result is None:
        print("No IDOR Found")

    else:
        print(result)
