"""
Test Error-Based SQLi on Oracle.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.error_sqli import ErrorSQLiScanner


def test_oracle_error_sqli():
    """Test Error-Based SQLi on Oracle."""
    TARGET = "https://0a7a003c04dc3613813cd9bc0095009a.web-security-academy.net/filter?category=Corporate+gifts"

    print("=" * 60)
    print("Testing Error-Based SQLi on Oracle")
    print("=" * 60)

    scanner = ErrorSQLiScanner(TARGET)
    scanner.parameter = "category"
    findings = scanner.scan()

    print(f"\nFindings: {len(findings)}")
    for f in findings:
        print(f"  DBMS: {f.dbms}")
        print(f"  Database: {f.database}")
        print(f"  Version: {f.version}")
        print(f"  Tables: {f.tables}")
        print(f"  Credentials: {f.credentials}")


if __name__ == "__main__":
    test_oracle_error_sqli()
