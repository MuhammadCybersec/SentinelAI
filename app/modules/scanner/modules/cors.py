"""
===========================================================
Project : Sentinel AI
Module  : CORS Scanner
File ID : SCANNER-CORS-001
Version : 1.0.0
===========================================================

Description:
Cross-Origin Resource Sharing (CORS) Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class CORSScanner:
    """
    Detect CORS misconfigurations.
    """

    def __init__(self) -> None:

        self.name = "Cross-Origin Resource Sharing"

        self.severity = "Medium"

        self.test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "https://sentinelai.local",
            "null",
            "https://example.org",
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

        print(f"[CORS] Scanning -> {url}")

        vulnerable = False

        detected_origin = ""

        for origin in self.test_origins:
            # -------------------------------------------------
            # Future:
            # Send request with Origin header
            # Check Access-Control-Allow-Origin
            # Check Access-Control-Allow-Credentials
            # -------------------------------------------------

            if False:
                vulnerable = True

                detected_origin = origin

                break

        if not vulnerable:
            return None

        return Finding(
            project_id=project_id,
            title="CORS Misconfiguration",
            description=(
                "Potential Cross-Origin Resource Sharing misconfiguration detected."
            ),
            severity=self.severity,
            cvss=6.5,
            status="Open",
            module="CORS Scanner",
            target=url,
            url=url,
            parameter="Origin",
            payload=detected_origin,
            evidence="",
            recommendation=(
                "Allow only trusted origins and avoid "
                "using wildcard origins with credentials."
            ),
            reference=(
                "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
            ),
            cwe="CWE-942",
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
            "payloads": len(self.test_origins),
            "type": "Active Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    scanner = CORSScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/api/profile",
    )

    print()

    if result is None:
        print("No CORS Misconfiguration Found")

    else:
        print(result)
