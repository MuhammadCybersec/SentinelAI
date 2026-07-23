"""
===========================================================
Project : Sentinel AI
Module  : SSRF Scanner
File ID : SCANNER-SSRF-001
Version : 1.0.0
===========================================================

Description:
Server-Side Request Forgery Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class SSRFScanner:
    """
    Detect Server-Side Request Forgery vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Server-Side Request Forgery"

        self.severity = "High"

        self.payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/",
            "http://0.0.0.0/",
            "http://[::1]/",
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

        print(f"[SSRF] Scanning -> {url}")

        vulnerable = False

        detected_payload = ""

        for payload in self.payloads:

            # Future:
            # Inject payload
            # Send request
            # Detect SSRF behavior

            if False:

                vulnerable = True

                detected_payload = payload

                break

        if not vulnerable:

            return None

        return Finding(
            project_id=project_id,
            title="Server-Side Request Forgery",
            description=("Potential SSRF vulnerability detected."),
            severity=self.severity,
            cvss=8.8,
            status="Open",
            module="SSRF Scanner",
            target=url,
            url=url,
            parameter="",
            payload=detected_payload,
            evidence="",
            recommendation=("Validate and whitelist outgoing requests."),
            reference=(
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
            ),
            cwe="CWE-918",
            owasp="A10:2021 SSRF",
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

    scanner = SSRFScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/fetch?url=test",
    )

    print()

    if result is None:

        print("No SSRF Found")

    else:

        print(result)
