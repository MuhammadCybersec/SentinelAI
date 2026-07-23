"""
===========================================================
Project : Sentinel AI
Module  : Risk Scoring
File ID : RECON-RISK-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

HIGH_RISK_KEYWORDS = {
    "admin",
    "administrator",
    "login",
    "signin",
    "auth",
    "oauth",
    "token",
    "jwt",
    "api",
    "graphql",
    "debug",
    "config",
    ".env",
    "backup",
    "db",
    "database",
    "console",
    "manage",
    "upload",
    "shell",
    "internal",
}


MEDIUM_RISK_KEYWORDS = {
    "user",
    "users",
    "account",
    "profile",
    "password",
    "reset",
    "register",
    "search",
    "export",
    "import",
    "download",
    "private",
    "dashboard",
    "settings",
    "dev",
    "test",
}


def calculate_score(url: str) -> tuple[int, str]:
    """
    Calculate risk score for a URL.
    """

    url_lower = url.lower()

    score = 0

    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in url_lower:
            score += 30

    for keyword in MEDIUM_RISK_KEYWORDS:
        if keyword in url_lower:
            score += 15

    if "?" in url:
        score += 10

    if "=" in url:
        score += 5

    if score >= 60:
        severity = "Critical"

    elif score >= 40:
        severity = "High"

    elif score >= 20:
        severity = "Medium"

    else:
        severity = "Low"

    return score, severity


def score_urls(urls: list[str]) -> list[dict]:
    """
    Score a list of URLs.
    """

    findings: list[dict] = []

    for url in urls:

        score, severity = calculate_score(url)

        findings.append(
            {
                "url": url,
                "score": score,
                "severity": severity,
            }
        )

    findings.sort(
        key=lambda item: item["score"],
        reverse=True,
    )

    return findings


# ============================================================
# Temporary Test
# ============================================================

if __name__ == "__main__":

    TEST_URLS = [
        "https://example.com/",
        "https://example.com/admin",
        "https://example.com/login",
        "https://example.com/graphql",
        "https://example.com/api/v1/users",
        "https://example.com/debug",
        "https://example.com/.env",
        "https://example.com/search?q=test",
        "https://example.com/download?id=5",
    ]

    results = score_urls(TEST_URLS)

    print("-" * 60)
    print("Risk Scoring")
    print("-" * 60)
    print()

    for item in results:

        print(f"[{item['severity']:^8}] {item['score']:>3}  {item['url']}")
