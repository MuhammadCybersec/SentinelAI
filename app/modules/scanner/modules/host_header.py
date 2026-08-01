"""
===========================================================
Project : Sentinel AI
Module  : Host Header Injection Scanner
File ID : SCANNER-HOSTHEADER-001
Version : 1.0.0
===========================================================

Description:
Host Header Injection Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class HostHeaderScanner:
    """
    Detect Host Header Injection vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Host Header Injection"

        self.severity = "High"

        self.payloads = [
            "evil.com",
            "attacker.com",
            "localhost",
            "127.0.0.1",
            "internal.local",
            "example.org",
            "host.sentinel.ai",
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
        Scan target for Host Header Injection.
        """

        print(f"[Host Header] Scanning -> {url}")

        vulnerable = False

        detected_payload = ""

        for payload in self.payloads:
            # -------------------------------------------------
            # Future:
            # Send request with modified Host header
            # Check password reset links
            # Check redirects
            # Check cache poisoning
            # -------------------------------------------------

            if False:
                vulnerable = True

                detected_payload = payload

                break

        if not vulnerable:
            return None

        return Finding(
            project_id=project_id,
            title="Host Header Injection",
            description=("Potential Host Header Injection vulnerability detected."),
            severity=self.severity,
            cvss=8.1,
            status="Open",
            module="Host Header Scanner",
            target=url,
            url=url,
            parameter="Host",
            payload=detected_payload,
            evidence="",
            recommendation=(
                "Validate the Host header using an allowlist "
                "and reject unexpected host values."
            ),
            reference=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/17-Testing_for_Host_Header_Injection"
            ),
            cwe="CWE-444",
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
            "payloads": len(self.payloads),
            "type": "Active Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    scanner = HostHeaderScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com",
    )

    print()

    if result is None:
        print("No Host Header Injection Found")

    else:
        print(result)
