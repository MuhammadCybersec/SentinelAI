"""
PortSwigger Lab #3: SQL injection attack, querying the database type and version on Oracle
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.union_sqli import UnionSQLiScanner

# ============================================================
# Configuration
# ============================================================

# LAB #3 URL (Oracle version)
TARGET = "https://0acf00b004a325828048088a00600043.web-security-academy.net/filter?category=Gifts"

# ============================================================
# Run Test
# ============================================================


def main():
    print("=" * 60)
    print("PortSwigger Lab #3: Oracle Version Extraction")
    print("=" * 60)

    scanner = UnionSQLiScanner(TARGET)
    scanner.parameter = "category"
    findings = scanner.scan()

    print(f"\n{'=' * 60}")
    print("RESULTS")
    print(f"{'=' * 60}")
    print(f"Findings: {len(findings)}")

    for f in findings:
        print("\n  ✅ Vulnerability Found!")
        print(f"  DBMS: {f.dbms}")
        print(f"  Column Count: {f.column_count}")
        print(f"  Payload: {f.payload}")

        for row in f.extracted_data:
            for key, value in row.items():
                print(f"    {key}: {value}")

    if not findings:
        print("\n  ❌ No vulnerabilities found.")


if __name__ == "__main__":
    main()
