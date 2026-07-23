"""
PortSwigger Lab 6 test script.
SQL injection UNION attack, retrieving data from other tables.
Uses ONLY UNION-based SQL Injection.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.modules.scanner.modules.lab6_handler import solve_lab6


def main():
    """Run Lab 6 test."""
    # ============================================================
    # Configuration - REPLACE WITH YOUR LAB URL
    # ============================================================
    TARGET = "https://0a7a003c04dc3613813cd9bc0095009a.web-security-academy.net/filter?category=Corporate+gifts"

    print("=" * 60)
    print("PortSwigger Lab 6: UNION Attack - Retrieving Data from Other Tables")
    print("=" * 60)
    print(f"Target: {TARGET}")
    print("=" * 60)

    start_time = time.time()

    # ============================================================
    # Run Lab 6 solution (UNION-based only)
    # ============================================================
    print("\n[Engine] Selected: UNION-Based SQL Injection")
    print("[Engine] This is a UNION-based Oracle Lab\n")

    result = solve_lab6(TARGET)

    elapsed = time.time() - start_time

    # ============================================================
    # Display Results
    # ============================================================
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    print(f"\n✅ Scan Type: {result.get('scan_type', 'union')}")
    print(f"✅ DBMS: {result.get('dbms', 'Unknown')}")
    print(f"✅ Parameter: {result.get('parameter', 'unknown')}")
    print(f"✅ Credentials Found: {len(result.get('credentials', []))}")

    if result.get("credentials"):
        print("\n🔑 Extracted Credentials:")
        for cred in result["credentials"]:
            print(f"  Username: {cred.get('username')}")
            print(f"  Password: {cred.get('password')}")

    print(f"\n🔐 Login Success: {result.get('login_success', False)}")
    print(f"🎯 Lab Completed: {result.get('lab_completed', False)}")

    print(f"\n⏱️ Time: {elapsed:.2f} seconds")

    print("\n" + "=" * 60)

    if result.get("lab_completed"):
        print("✅ LAB 6 SOLVED!")
    else:
        print("❌ Lab 6 not solved. Check:")
        print("  1. Lab URL is correct (not expired)")
        print("  2. Lab is accessible")
        print("  3. Check extracted credentials manually")

    print("=" * 60)


if __name__ == "__main__":
    main()
