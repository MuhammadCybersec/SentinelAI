"""
===========================================================
Project : Sentinel AI
Module  : JWT Scanner
File ID : SCANNER-JWT-001
Version : 1.0.0
===========================================================

Description:
JSON Web Token Security Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class JWTScanner:
    """
    Detect JWT security misconfigurations.
    """

    def __init__(self) -> None:

        self.name = "JSON Web Token"

        self.severity = "High"

        self.test_cases = [
            "alg=none",
            "Expired Token",
            "Invalid Signature",
            "Modified Payload",
            "Weak Secret",
            "Missing Signature",
            "HS256 -> RS256 Confusion",
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
        Scan JWT implementation.
        """

        print(f"[JWT] Scanning -> {url}")

        vulnerable = False

        detected_case = ""

        for test in self.test_cases:

            # -------------------------------------------------
            # Future:
            # Decode JWT
            # Modify algorithm/header
            # Test signature validation
            # Check expiration
            # Verify weak secrets
            # -------------------------------------------------

            if False:

                vulnerable = True

                detected_case = test

                break

        if not vulnerable:

            return None

        return Finding(
            project_id=project_id,
            title="JWT Misconfiguration",
            description=("Potential JWT security vulnerability detected."),
            severity=self.severity,
            cvss=8.2,
            status="Open",
            module="JWT Scanner",
            target=url,
            url=url,
            parameter="Authorization",
            payload=detected_case,
            evidence="",
            recommendation=(
                "Reject 'alg=none', verify signatures, "
                "use strong secrets, validate issuer, "
                "audience and expiration."
            ),
            reference=(
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Testing_JSON_Web_Tokens"
            ),
            cwe="CWE-347",
            owasp="A07:2021 Identification and Authentication Failures",
            cve="",
        )

    # =====================================================
    # Scanner Information
    # =====================================================

    def info(self) -> dict:

        return {
            "name": self.name,
            "severity": self.severity,
            "payloads": len(self.test_cases),
            "type": "Active Scanner",
        }


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":

    scanner = JWTScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/api/login",
    )

    print()

    if result is None:

        print("No JWT Vulnerability Found")

    else:

        print(result)
