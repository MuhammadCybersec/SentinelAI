"""
PortSwigger Lab #2 Test
SQL injection vulnerability allowing login bypass
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.login_bypass import LoginBypassScanner

# ============================================================
# Configuration
# ============================================================

# NAYA LAB URL YAHAN PASTE KAREIN
TARGET = "https://0a0b00bd0421d9e0818ade5a00ce0096.web-security-academy.net/login"

# ============================================================
# Run Test
# ============================================================


def main():
    print("=" * 60)
    print("PortSwigger Lab #2: Login Bypass")
    print("=" * 60)

    scanner = LoginBypassScanner(TARGET)
    findings = scanner.scan()

    print(f"\n{'=' * 60}")
    print("RESULTS")
    print(f"{'=' * 60}")
    print(f"Findings: {len(findings)}")

    for f in findings:
        print("\n  ✅ Vulnerability Found!")
        print(f"  Username: {f.username_payload}")
        print(f"  Password: {f.password_payload}")
        print(f"  Confidence: {f.confidence * 100:.0f}%")
        print(f"  Signals: {', '.join(f.success_signals)}")
        print("  Evidence:")
        for evidence in f.evidence:
            print(f"    - {evidence}")

    if not findings:
        print("\n  ❌ No vulnerabilities found.")
        print("  Check:")
        print("    1. Lab URL is correct")
        print("    2. Lab is active (not expired)")
        print("    3. Login page is accessible")


if __name__ == "__main__":
    main()
