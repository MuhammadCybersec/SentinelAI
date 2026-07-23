"""
Test DBMS detection with confidence scoring.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.union_sqli import UnionSQLiScanner


def test_oracle_detection():
    """Test Oracle DBMS detection."""
    urls = [
        "https://0a7a003c04dc3613813cd9bc0095009a.web-security-academy.net/filter?category=Corporate+gifts",
        "https://0aXX....web-security-academy.net/filter?category=Gifts",
    ]

    for url in urls:
        print(f"\n{'='*60}")
        print(f"Testing Oracle detection on: {url[:50]}...")
        print(f"{'='*60}")

        scanner = UnionSQLiScanner(url)
        scanner.parameter = "category"
        dbms = scanner._detect_dbms()

        print(f"\n✅ Detected: {dbms}")
        print(f"✅ Confidence: {getattr(scanner, 'detection_confidence', 0):.0%}")

        assert dbms == "Oracle", f"Expected Oracle, got {dbms}"


def test_mysql_detection():
    """Test MySQL DBMS detection."""
    urls = [
        "https://0aXX....web-security-academy.net/filter?category=Gifts",
    ]

    for url in urls:
        print(f"\n{'='*60}")
        print(f"Testing MySQL detection on: {url[:50]}...")
        print(f"{'='*60}")

        scanner = UnionSQLiScanner(url)
        scanner.parameter = "category"
        dbms = scanner._detect_dbms()

        print(f"\n✅ Detected: {dbms}")
        print(f"✅ Confidence: {getattr(scanner, 'detection_confidence', 0):.0%}")

        assert dbms == "MySQL", f"Expected MySQL, got {dbms}"


if __name__ == "__main__":
    print("=" * 60)
    print("DBMS Detection Tests")
    print("=" * 60)

    # Uncomment and set URLs to run tests
    # test_oracle_detection()
    # test_mysql_detection()
