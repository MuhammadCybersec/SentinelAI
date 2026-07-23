"""
PortSwigger Error-Based SQL Injection lab tests.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.error_sqli import ErrorSQLiScanner, SQLInjectionManager


def test_error_sqli_lab():
    """Test Error-Based SQLi on a PortSwigger lab."""
    # Replace with actual lab URL
    TARGET = "https://0aXX....web-security-academy.net/filter?category=Gifts"

    print("=" * 60)
    print("PortSwigger Error-Based SQLi Lab")
    print("=" * 60)

    scanner = ErrorSQLiScanner(TARGET)
    scanner.parameter = "category"
    findings = scanner.scan()

    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"Findings: {len(findings)}")

    for f in findings:
        print(f"\n  ✅ Vulnerability Found!")
        print(f"  DBMS: {f.dbms}")
        print(f"  Database: {f.database}")
        print(f"  Version: {f.version}")
        print(f"  Tables: {f.tables}")
        print(f"  Credentials: {f.credentials}")


def test_sqli_manager_decision_flow():
    """Test SQLiManager decision flow."""
    TARGET = "https://0aXX....web-security-academy.net/filter?category=Gifts"

    print("=" * 60)
    print("SQLiManager Decision Flow Test")
    print("=" * 60)

    manager = SQLInjectionManager(TARGET)
    result = manager.scan()

    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"Type: {result.get('type', 'unknown')}")
    print(f"Findings: {len(result.get('findings', []))}")


if __name__ == "__main__":
    # Uncomment and set URLs to run tests
    # test_error_sqli_lab()
    # test_sqli_manager_decision_flow()
    print("Set the target URL and uncomment the desired test to run.")
