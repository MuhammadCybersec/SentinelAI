"""
===========================================================
Project : Sentinel AI
Module  : Command Injection Scanner
File ID : SCANNER-CMD-001
Version : 1.0.0
===========================================================

Description:
Operating System Command Injection Scanner.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding


class CommandInjectionScanner:
    """
    Detect OS Command Injection vulnerabilities.
    """

    def __init__(self) -> None:

        self.name = "Command Injection"

        self.severity = "Critical"

        self.payloads = [
            ";id",
            "& whoami",
            "&& whoami",
            "| whoami",
            "; cat /etc/passwd",
            "; ping -c 3 127.0.0.1",
            "`whoami`",
            "$(whoami)",
            "; dir",
            "& dir",
            "&& dir",
            "| dir",
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

        print(f"[CMD] Scanning -> {url}")

        vulnerable = False

        detected_payload = ""

        for payload in self.payloads:

            # -------------------------------------------------
            # Future:
            # Inject payload
            # Send HTTP request
            # Detect command execution
            # -------------------------------------------------

            if False:

                vulnerable = True

                detected_payload = payload

                break

        if not vulnerable:

            return None

        return Finding(
            project_id=project_id,
            title="Operating System Command Injection",
            description=("Potential OS Command Injection vulnerability detected."),
            severity=self.severity,
            cvss=9.8,
            status="Open",
            module="Command Injection Scanner",
            target=url,
            url=url,
            parameter="",
            payload=detected_payload,
            evidence="",
            recommendation=(
                "Avoid executing system commands using user input. "
                "Use allowlists and parameterized APIs."
            ),
            reference=("https://owasp.org/www-community/attacks/Command_Injection"),
            cwe="CWE-78",
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

    scanner = CommandInjectionScanner()

    result = scanner.scan(
        project_id="demo-project",
        url="https://example.com/ping?host=127.0.0.1",
    )

    print()

    if result is None:

        print("No Command Injection Found")

    else:

        print(result)
