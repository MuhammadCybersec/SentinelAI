"""
PortSwigger Lab #7: UNION Attack
SQL injection UNION attack, retrieving data from other tables
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.union_sqli import UnionSQLiScanner

# ============================================================
# Configuration
# ============================================================

# LAB #7 URL (category parameter)
TARGET = "https://0ade003d04dd5a878031589c00d5007a.web-security-academy.net/login"

# ============================================================
# Run Test
# ============================================================


def main():
    print("=" * 60)
    print("PortSwigger Lab #7: UNION Attack")
    print("=" * 60)

    scanner = UnionSQLiScanner(TARGET)
    scanner.parameter = "category"  # Force category parameter
    findings = scanner.scan()

    print(f"\n{'='*60}")
    print("RESULTS")
    print(f"{'='*60}")
    print(f"Findings: {len(findings)}")

    for f in findings:
        print(f"\n  ✅ Vulnerability Found!")
        print(f"  Payload: {f.payload}")
        print(f"  Column Count: {f.column_count}")
        print(f"  Visible Columns: {f.visible_columns}")
        print(f"  Confidence: {f.confidence * 100:.0f}%")
        print(f"  Extracted Data: {len(f.extracted_data)} rows")

        for row in f.extracted_data:
            print(f"    Username: {row.get('username', 'N/A')}")
            print(f"    Password: {row.get('password', 'N/A')}")

        print(f"  Evidence:")
        for evidence in f.evidence:
            print(f"    - {evidence}")

    if not findings:
        print("\n  ❌ No vulnerabilities found.")
        print("  Check:")
        print("    1. Lab URL is correct")
        print("    2. Lab is active (not expired)")
        print(f"    3. Current URL: {TARGET}")


if __name__ == "__main__":
    main()
