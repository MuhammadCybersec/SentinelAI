"""
===========================================================
Project : Sentinel AI
Module  : HTTP Client
File ID : TOOL-HTTP-001
Version : 1.0.0
===========================================================
"""

from __future__ import annotations

import random
from typing import Optional

import requests
from requests import Response, Session

DEFAULT_TIMEOUT = 20


USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/138.0.0.0 Safari/537.36"
    ),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) " "Firefox/140.0"),
    (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/138.0.0.0 Safari/537.36"
    ),
]


class HTTPClient:
    """
    Shared HTTP client for all SentinelAI modules.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        verify_ssl: bool = True,
    ) -> None:

        self.timeout = timeout

        self.session: Session = requests.Session()

        self.session.verify = verify_ssl

        self.session.headers.update(
            {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "*/*",
                "Connection": "keep-alive",
            }
        )

    # =====================================================
    # GET
    # =====================================================

    def get(
        self,
        url: str,
        **kwargs,
    ) -> Optional[Response]:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)

        try:

            return self.session.get(
                url,
                **kwargs,
            )

        except requests.RequestException:

            return None

    # =====================================================
    # POST
    # =====================================================

    def post(
        self,
        url: str,
        **kwargs,
    ) -> Optional[Response]:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)

        try:

            return self.session.post(
                url,
                **kwargs,
            )

        except requests.RequestException:

            return None

    # =====================================================
    # HEAD
    # =====================================================

    def head(
        self,
        url: str,
        **kwargs,
    ) -> Optional[Response]:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)

        try:

            return self.session.head(
                url,
                **kwargs,
            )

        except requests.RequestException:

            return None

    # =====================================================
    # Close
    # =====================================================

    def close(self) -> None:

        self.session.close()


# =========================================================
# Singleton
# =========================================================

http = HTTPClient()

# Temporary test
if __name__ == "__main__":

    response = http.get("https://bugcrowd.com")

    if response:

        print(response.status_code)
        print(response.url)

    else:

        print("Request Failed")
