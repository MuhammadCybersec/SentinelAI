"""
===========================================================
Project : Sentinel AI
Module  : Interesting URL Detector
File ID : RECON-INTERESTINGURLS-001
Version : 1.0.0
===========================================================
"""

from urllib.parse import urlparse

# ======================================================
# Interesting Keywords
# ======================================================

INTERESTING_KEYWORDS = (
    "admin",
    "administrator",
    "login",
    "signin",
    "logout",
    "register",
    "signup",
    "dashboard",
    "panel",
    "console",
    "api",
    "graphql",
    "swagger",
    "openapi",
    "upload",
    "uploads",
    "download",
    "backup",
    "config",
    ".env",
    "debug",
    "test",
    "dev",
    "staging",
    "internal",
    "private",
    "auth",
    "oauth",
    "token",
    "callback",
    "reset",
    "forgot",
    "password",
)


def find_interesting_urls(urls: list[str]) -> list[str]:
    """
    Find interesting URLs from Wayback or crawler results.

    Args:
        urls: List of URLs.

    Returns:
        Sorted list of interesting URLs.
    """

    interesting: set[str] = set()

    for url in urls:
        try:
            parsed = urlparse(url)

            path = parsed.path.lower()

        except Exception:
            continue

        for keyword in INTERESTING_KEYWORDS:
            if keyword in path:
                interesting.add(url)

                break

    return sorted(interesting)


# ======================================================
# Temporary Test
# ======================================================

if __name__ == "__main__":
    sample_urls = [
        "https://bugcrowd.com/login",
        "https://bugcrowd.com/blog",
        "https://bugcrowd.com/api/v1/users",
        "https://bugcrowd.com/graphql",
        "https://bugcrowd.com/admin",
        "https://bugcrowd.com/images/logo.png",
    ]

    results = find_interesting_urls(sample_urls)

    print(f"Interesting URLs: {len(results)}\n")

    for url in results:
        print(url)
