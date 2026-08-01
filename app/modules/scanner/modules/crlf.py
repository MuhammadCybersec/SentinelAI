"""
===========================================================
Project : Sentinel AI
Module  : CRLF Injection Scanner
File ID : SCANNER-CRLF-001
Version : 1.0.0
===========================================================

Description:
CRLF Injection Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class CRLFScanner:
    """
    Detect CRLF Injection vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "CRLF Injection"

        self.severity = "Medium"

        self.payloads = [
            "%0d%0aSet-Cookie:sentinel=1",
            "%0D%0ALocation:https://example.com",
            "%0d%0aContent-Length:0",
            "%0d%0aX-Test:SentinelAI",
            "%0d%0aX-Injected:true",
            "%0d%0aContent-Type:text/html",
            "\r\nSet-Cookie:sentinel=1",
            "\r\nX-Test:Injected",
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

        print(f"[CRLF] Scanning -> {url}")

        vulnerable = False

        detected_payload = ""

        for payload in self.payloads:
            # -------------------------------------------------
            # Future:
            # Inject payload
            # Send HTTP request
            # Detect injected headers
            # -------------------------------------------------

            if False:
                vulnerable = True

                detected_payload = payload

                break

        if not vulnerable:
            return None

        return Finding(
            project_id=project_id,
            title="CRLF Injection",
            description=("Potential CRLF Injection vulnerability detected."),
            severity=self.severity,
            cvss=6.5,
            status="Open",
            module="CRLF Scanner",
            target=url,
            url=url,
            parameter="",
            payload=detected_payload,
            evidence="",
            recommendation=(
                "Validate and encode user input before using it in HTTP headers."
            ),
            reference=(
                "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"
            ),
            cwe="CWE-113",
            owasp="A03:2021 Injection",
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
    scanner = CRLFScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/search?q=test",
    )

    print()

    if result is None:
        print("No CRLF Injection Found")

    else:
        print(result)
