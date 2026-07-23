# test_phase1.py
#!/usr/bin/env python
"""
Phase 1 test runner for Oracle detection.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import unittest
import logging

# Disable logging during tests
logging.disable(logging.CRITICAL)

# Import test cases
from tests.test_oracle_detection import (
    TestOracleDetectionPayloads,
    TestOracleEnumDetection,
    TestOracleEnumIntegration,
)


def run_tests():
    """Run all Phase 1 tests."""
    print("\n" + "=" * 60)
    print("SENTINELAI - PHASE 1 TESTS")
    print("Oracle Database Detection")
    print("=" * 60 + "\n")

    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestOracleDetectionPayloads)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestOracleEnumDetection))
    suite.addTests(
        unittest.TestLoader().loadTestsFromTestCase(TestOracleEnumIntegration)
    )

    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 60)
    print("TEST RESULTS SUMMARY")
    print("=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60 + "\n")

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
