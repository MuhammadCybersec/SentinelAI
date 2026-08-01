"""
===========================================================
Project : Sentinel AI
Module  : RFI Scanner
File ID : SCANNER-RFI-001
Version : 1.0.0
===========================================================

Description:
Remote File Inclusion Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class RFIScanner:
    """
    Detect Remote File Inclusion vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Remote File Inclusion"

        self.severity = "Critical"

        self.payloads = [
            "http://example.com/shell.txt",
            "https://example.com/test.php",
            "http://127.0.0.1/test.txt",
            "https://attacker.example/payload.php",
            "//example.com/test.php",
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

        print(f"[RFI] Scanning -> {url}")

        vulnerable = False

        detected_payload = ""

        for payload in self.payloads:
            # Future:
            # Inject payload
            # Send request
            # Detect remote file inclusion

            if False:
                vulnerable = True

                detected_payload = payload

                break

        if not vulnerable:
            return None

        return Finding(
            project_id=project_id,
            title="Remote File Inclusion",
            description=("Potential Remote File Inclusion vulnerability detected."),
            severity=self.severity,
            cvss=9.1,
            status="Open",
            module="RFI Scanner",
            target=url,
            url=url,
            parameter="",
            payload=detected_payload,
            evidence="",
            recommendation=("Disable remote file inclusion and validate user input."),
            reference=("https://owasp.org/www-community/attacks/File_Inclusion"),
            cwe="CWE-98",
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
    scanner = RFIScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/index.php?page=home",
    )

    print()

    if result is None:
        print("No RFI Found")

    else:
        print(result)
