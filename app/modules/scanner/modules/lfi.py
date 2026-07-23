"""
===========================================================
Project : Sentinel AI
Module  : LFI Scanner
File ID : SCANNER-LFI-001
Version : 1.0.0
===========================================================

Description:
Local File Inclusion Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class LFIScanner:
    """
    Detect Local File Inclusion vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Local File Inclusion"

        self.severity = "High"

        self.payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../../proc/self/environ",
            "../../../../etc/hosts",
            "../../../../boot.ini",
        ]

    # =====================================================
    # Scan
    # =====================================================

    def scan(
        self,
        project_id: str,
        url: str,
    ) -> Finding | None:

        print(f"[LFI] Scanning -> {url}")

        vulnerable = False

        detected_payload = ""

        for payload in self.payloads:

            # Future:
            # Inject payload
            # Send request
            # Detect file disclosure

            if False:

                vulnerable = True

                detected_payload = payload

                break

        if not vulnerable:

            return None

        return Finding(
            project_id=project_id,
            title="Local File Inclusion",
            description=("Potential Local File Inclusion vulnerability detected."),
            severity=self.severity,
            cvss=8.6,
            status="Open",
            module="LFI Scanner",
            target=url,
            url=url,
            parameter="",
            payload=detected_payload,
            evidence="",
            recommendation=("Validate file paths and prevent directory traversal."),
            reference=("https://owasp.org/www-community/attacks/Path_Traversal"),
            cwe="CWE-22",
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

    scanner = LFIScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/index.php?page=home",
    )

    print()

    if result is None:

        print("No LFI Found")

    else:

        print(result)
