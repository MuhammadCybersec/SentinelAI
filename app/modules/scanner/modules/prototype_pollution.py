"""
===========================================================
Project : Sentinel AI
Module  : Prototype Pollution Scanner
File ID : SCANNER-PROTOTYPE-001
Version : 1.0.0
===========================================================

Description:
JavaScript Prototype Pollution Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class PrototypePollutionScanner:
    """
    Detect Prototype Pollution vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Prototype Pollution"

        self.severity = "High"

        self.payloads = [
            "__proto__[isAdmin]=true",
            "__proto__.isAdmin=true",
            "constructor.prototype.isAdmin=true",
            "__proto__[polluted]=true",
            "__proto__[test]=SentinelAI",
            "constructor[prototype][admin]=true",
            "__proto__[role]=administrator",
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
        Scan target for Prototype Pollution.
        """

        print(f"[Prototype Pollution] Scanning -> {url}")

        vulnerable = False

        detected_payload = ""

        for payload in self.payloads:
            # -------------------------------------------------
            # Future:
            # Inject payload into JSON/body/query
            # Send HTTP request
            # Detect prototype modification
            # Verify inherited properties
            # -------------------------------------------------

            if False:
                vulnerable = True

                detected_payload = payload

                break

        if not vulnerable:
            return None

        return Finding(
            project_id=project_id,
            title="Prototype Pollution",
            description=(
                "Potential JavaScript Prototype Pollution vulnerability detected."
            ),
            severity=self.severity,
            cvss=8.8,
            status="Open",
            module="Prototype Pollution Scanner",
            target=url,
            url=url,
            parameter="__proto__",
            payload=detected_payload,
            evidence="",
            recommendation=(
                "Block dangerous object properties such as "
                "__proto__, constructor and prototype. "
                "Validate all user-controlled JSON input."
            ),
            reference=(
                "https://owasp.org/www-community/vulnerabilities/Prototype_Pollution"
            ),
            cwe="CWE-1321",
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
    scanner = PrototypePollutionScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/api/users",
    )

    print()

    if result is None:
        print("No Prototype Pollution Found")

    else:
        print(result)
