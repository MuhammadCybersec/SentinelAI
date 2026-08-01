"""
===========================================================
Project : Sentinel AI
Module  : SQL Injection Scanner
File ID : SCANNER-SQLI-001
Version : 1.0.0
===========================================================

Description:
SQL Injection Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding
from app.modules.scanner.payload.sql_payloads import (
    get_payloads,
)


class SQLiScanner:
    """
    Detect SQL Injection vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "SQL Injection"

        self.severity = "Critical"

        self.payloads = get_payloads()

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

        print(f"[SQLi] Scanning -> {url}")

        # -------------------------------------------------
        # Placeholder
        # Real HTTP requests will be implemented later.
        # -------------------------------------------------

        vulnerable = False

        detected_payload = ""

        for payload in self.payloads:
            # Future:
            # Inject payload into parameters
            # Send request
            # Compare responses

            if False:
                vulnerable = True

                detected_payload = payload

                break

        if not vulnerable:
            return None

        # -------------------------------------------------
        # Create Finding
        # -------------------------------------------------

        return Finding(
            project_id=project_id,
            title="SQL Injection",
            description=("Potential SQL Injection vulnerability detected."),
            severity=self.severity,
            cvss=9.8,
            status="Open",
            module="SQLi Scanner",
            target=url,
            url=url,
            parameter="",
            payload=detected_payload,
            evidence="",
            recommendation=("Use parameterized queries and prepared statements."),
            reference=("https://owasp.org/www-community/attacks/SQL_Injection"),
            cwe="CWE-89",
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
            "payloads": len(self.payloads),
            "type": "Active Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    scanner = SQLiScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/login.php?id=1",
    )

    print()

    if result is None:
        print("No SQL Injection Found")

    else:
        print(result)
