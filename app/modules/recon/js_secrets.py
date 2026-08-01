"""
===========================================================
Project : Sentinel AI
Module  : JavaScript Secrets Detection
File ID : RECON-JS-003
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

import re

from app.tools.http_client import http

SECRET_PATTERNS: dict[str, str] = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "GitHub Token": r"ghp_[A-Za-z0-9]{36,}",
    "Slack Token": r"xox[baprs]-[A-Za-z0-9-]+",
    "Stripe Live Key": r"sk_live_[A-Za-z0-9]+",
    "Stripe Publishable Key": r"pk_live_[A-Za-z0-9]+",
    "Bearer Token": r"Bearer\s+[A-Za-z0-9\-._=]+",
    "JWT Token": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "Firebase URL": r"https://[A-Za-z0-9\-]+\.firebaseio\.com",
    "MongoDB URI": r"mongodb(?:\+srv)?://[^\"'\s]+",
}


def discover_js_secrets(js_files: list[str]) -> list[dict]:
    """
    Scan JavaScript files for exposed secrets.
    """

    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for js in js_files:
        response = http.get(js)

        if response is None:
            continue

        if response.status_code != 200:
            continue

        content = response.text

        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)

            for secret in matches:
                key = (secret_type, secret)

                if key in seen:
                    continue

                seen.add(key)

                findings.append(
                    {
                        "type": secret_type,
                        "value": secret[:80],
                        "source": js,
                    }
                )

    return findings


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":
    from app.modules.recon.javascript import discover_javascript

    js_files = discover_javascript("https://bugcrowd.com")

    secrets = discover_js_secrets(js_files)

    print("-" * 60)
    print("JavaScript Secrets")
    print("-" * 60)

    print()

    print("JavaScript Files :", len(js_files))
    print("Secrets Found    :", len(secrets))

    print()

    for secret in secrets:
        print(secret["type"])
        print("Value :", secret["value"])
        print("Source:", secret["source"])
        print()
