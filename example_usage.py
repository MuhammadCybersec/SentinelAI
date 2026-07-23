# example_usage.py
#!/usr/bin/env python
"""
Example usage of Oracle detection module.
"""

import logging
import requests
from app.modules.scanner.oracle_enum import OracleEnum


def main():
    """Example of using Oracle detection."""

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Target configuration
    target_url = "http://localhost:8080/lab?id=1"
    injection_point = "id"

    # Create session
    session = requests.Session()

    # Initialize Oracle detection
    oracle = OracleEnum(session, target_url)

    # Run detection
    print("\n" + "=" * 60)
    print("STARTING ORACLE DETECTION")
    print("=" * 60)

    result = oracle.detect(injection_point)

    # Display results
    print("\n" + "=" * 60)
    print("DETECTION RESULTS")
    print("=" * 60)
    print(f"Oracle Detected: {result.is_oracle}")
    print(f"Total Score: {result.score}")
    print(f"Threshold: {result.threshold}")
    print(f"Reason: {result.reason}")
    print("\nIndicators:")
    for indicator, score in result.indicators.items():
        print(f"  - {indicator}: +{score}")
    print("=" * 60 + "\n")

    return result.is_oracle


if __name__ == "__main__":
    main()
