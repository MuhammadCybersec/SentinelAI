"""
===========================================================
Project : Sentinel AI
Module  : URL Normalizer
File ID : RECON-URLNORMALIZER-001
Version : 1.0.0
===========================================================
"""

import re
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url: str) -> str:
    """
    Normalize a URL for reconnaissance.

    Features
    --------
    - Lowercase hostname
    - Remove default ports (:80 / :443)
    - Remove duplicate slashes
    - Remove trailing slash
    - Remove URL fragment (#...)
    - Preserve query parameters
    """

    if not url:
        return ""

    try:
        parts = urlsplit(url)

    except Exception:
        return url

    # ======================================================
    # Hostname
    # ======================================================

    hostname = (parts.hostname or "").lower()

    # ======================================================
    # Port
    # ======================================================

    port = parts.port

    if (
        port is None
        or (parts.scheme == "http" and port == 80)
        or (parts.scheme == "https" and port == 443)
    ):
        netloc = hostname

    else:
        netloc = f"{hostname}:{port}"

    # ======================================================
    # Path
    # ======================================================

    path = re.sub(r"/{2,}", "/", parts.path)

    if path.endswith("/") and path != "/":
        path = path[:-1]

    if path == "/":
        path = ""

    # ======================================================
    # Rebuild URL
    # ======================================================

    normalized = urlunsplit(
        (
            parts.scheme.lower(),
            netloc,
            path,
            parts.query,
            "",
        )
    )

    return normalized
