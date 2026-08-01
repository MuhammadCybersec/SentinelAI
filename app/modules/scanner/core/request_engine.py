"""
===========================================================
Project : Sentinel AI
Module  : Request Engine
File ID : SCANNER-CORE-REQUEST-001
Version : 2.0.0
===========================================================

Description:
Production HTTP Request Engine.

Provides:

• HTTP Session Management
• Browser-like Requests
• HTTP/2 Ready
• Proxy Support
• Retry Support
• SSL Control
• Cookie Persistence
• Response Normalization

===========================================================
"""

from __future__ import annotations

import json
import logging
import random
import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx

# ===========================================================
# Constants
# ===========================================================

DEFAULT_TIMEOUT = 20.0

DEFAULT_RETRIES = 3

DEFAULT_VERIFY_SSL = True

DEFAULT_FOLLOW_REDIRECTS = True


# ===========================================================
# Browser User Agents
# ===========================================================

USER_AGENTS = [
    (
        "Mozilla/5.0 "
        "(Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/138.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 "
        "(X11; Linux x86_64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/138.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 "
        "(Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) "
        "Version/18 Safari/605.1.15"
    ),
]


# ===========================================================
# Default Headers
# ===========================================================

DEFAULT_HEADERS = {
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    "Accept-Encoding": ("gzip, deflate, br"),
    "Accept-Language": ("en-US,en;q=0.9"),
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
}


# ===========================================================
# Sentinel Response
# ===========================================================


@dataclass(slots=True)
class ResponseData:
    """
    Normalized HTTP response.
    """

    status_code: int

    url: str

    body: str

    headers: dict[str, str]

    cookies: dict[str, str]

    elapsed: float

    content_length: int

    content_type: str

    server: str

    title: str

    payload: str = ""


# ===========================================================
# Request Engine
# ===========================================================


class RequestEngine:
    """
    SentinelAI HTTP Engine.

    Shared by every scanner.

    XSS

    SQLi

    SSRF

    LFI

    JWT

    IDOR

    etc...
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        verify_ssl: bool = DEFAULT_VERIFY_SSL,
        follow_redirects: bool = DEFAULT_FOLLOW_REDIRECTS,
        proxy: str | None = None,
    ) -> None:

        self.logger = logging.getLogger(
            self.__class__.__name__,
        )

        self.timeout = timeout

        self.retries = retries

        self.verify_ssl = verify_ssl

        self.follow_redirects = follow_redirects

        self.proxy = proxy

        self.session: httpx.Client | None = None

        self.request_count = 0

        self.response_count = 0

        self.error_count = 0

        self.before_request_hook = None

        self.after_request_hook = None

    # ===========================================================

    # Random User Agent
    # ===========================================================

    def random_user_agent(
        self,
    ) -> str:
        """
        Return a random browser User-Agent.
        """

        return random.choice(
            USER_AGENTS,
        )

    # ===========================================================
    # Build Headers
    # ===========================================================

    def build_headers(
        self,
        headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """
        Build browser-like headers.
        """

        request_headers = DEFAULT_HEADERS.copy()

        request_headers["User-Agent"] = self.random_user_agent()

        if headers:
            request_headers.update(
                headers,
            )

        return request_headers

    # ===========================================================
    # Create Session
    # ===========================================================

    def create_session(
        self,
    ) -> httpx.Client:
        """
        Create reusable HTTP client.
        """

        if self.session is not None:
            return self.session

        self.logger.debug(
            "Creating HTTP session.",
        )

        client_args: dict[str, Any] = {
            "timeout": self.timeout,
            "verify": self.verify_ssl,
            "follow_redirects": self.follow_redirects,
            "headers": self.build_headers(),
            "http2": False,
        }

        if self.proxy is not None:
            client_args["proxy"] = self.proxy

            self.logger.debug(
                "Using proxy: %s",
                self.proxy,
            )

        self.session = httpx.Client(
            **client_args,
        )

        self.logger.debug(
            "HTTP session created successfully.",
        )

        return self.session

    # ===========================================================
    # Get Session
    # ===========================================================

    def get_session(
        self,
    ) -> httpx.Client:
        """
        Return active session.
        """

        if self.session is None:
            return self.create_session()

        return self.session

    # ===========================================================
    # Close Session
    # ===========================================================

    def close(
        self,
    ) -> None:
        """
        Close HTTP session.
        """

        if self.session is not None:
            self.session.close()

            self.session = None

    # ===========================================================

    # GET
    # ===========================================================

    def get(
        self,
        url: str,
        **kwargs: Any,
    ) -> ResponseData:

        return self.send(
            method="GET",
            url=url,
            **kwargs,
        )

    # ===========================================================
    # POST
    # ===========================================================

    def post(
        self,
        url: str,
        **kwargs: Any,
    ) -> ResponseData:

        return self.send(
            method="POST",
            url=url,
            **kwargs,
        )

    # ===========================================================
    # PUT
    # ===========================================================

    def put(
        self,
        url: str,
        **kwargs: Any,
    ) -> ResponseData:

        return self.send(
            method="PUT",
            url=url,
            **kwargs,
        )

    # ===========================================================
    # PATCH
    # ===========================================================

    def patch(
        self,
        url: str,
        **kwargs: Any,
    ) -> ResponseData:

        return self.send(
            method="PATCH",
            url=url,
            **kwargs,
        )

    # ===========================================================
    # DELETE
    # ===========================================================

    def delete(
        self,
        url: str,
        **kwargs: Any,
    ) -> ResponseData:

        return self.send(
            method="DELETE",
            url=url,
            **kwargs,
        )

    # ===========================================================
    # HEAD
    # ===========================================================

    def head(
        self,
        url: str,
        **kwargs: Any,
    ) -> ResponseData:

        return self.send(
            method="HEAD",
            url=url,
            **kwargs,
        )

    # ===========================================================
    # OPTIONS
    # ===========================================================

    def options(
        self,
        url: str,
        **kwargs: Any,
    ) -> ResponseData:

        return self.send(
            method="OPTIONS",
            url=url,
            **kwargs,
        )

    # ===========================================================

    # Generic Sender
    # ===========================================================

    def send(
        self,
        method: str,
        url: str,
        payload: str = "",
        **kwargs: Any,
    ) -> ResponseData:
        """
        Execute HTTP request with payload support.
        """

        # --------------------------------------------------
        # Payload ko query parameter mein convert karein (GET)
        # with proper URL encoding
        # --------------------------------------------------
        if payload and method.upper() == "GET":
            # Payload ko URL encode karein
            encoded_payload = urllib.parse.quote(payload, safe="")

            # URL mein payload add karein - FIXED: Tuple use kiya
            if url.endswith(("&", "?", "/")):
                url = f"{url}{encoded_payload}"
            else:
                url = f"{url}&{encoded_payload}"

        # --------------------------------------------------
        # Payload ko data mein convert karein (POST/PUT/PATCH)
        # --------------------------------------------------
        elif payload and method.upper() in ["POST", "PUT", "PATCH"]:
            kwargs["data"] = payload

        # --------------------------------------------------
        # Payload ko kwargs se remove karein
        # --------------------------------------------------
        kwargs.pop("payload", None)

        # --------------------------------------------------
        # Session aur headers prepare karein
        # --------------------------------------------------
        session = self.get_session()
        if session is None:
            raise RuntimeError("Failed to create HTTP session")

        headers = kwargs.pop("headers", None)
        headers = self.build_headers(headers)

        if self.before_request_hook:
            self.before_request_hook(
                method,
                url,
                headers,
                kwargs,
            )

        last_error: Exception | None = None

        for attempt in range(self.retries):
            try:
                self.request_count += 1

                response = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    **kwargs,
                )

                self.response_count += 1

                if self.after_request_hook:
                    self.after_request_hook(
                        response,
                    )
                    return self._normalize_response(
                        response,
                        payload,
                    )

            except (
                httpx.TimeoutException,
                httpx.ConnectError,
                httpx.NetworkError,
                httpx.HTTPError,
            ) as exc:
                last_error = exc
                self.error_count += 1

        if last_error is not None:
            raise last_error

        raise RuntimeError("Unknown request failure.")

    # ===========================================================

    # Normalize Response
    # ===========================================================

    def _normalize_response(
        self,
        response: httpx.Response,
        payload: str = "",
    ) -> ResponseData:
        """
        Convert httpx.Response into Sentinel ResponseData.
        """

        try:
            body = response.text
        except (httpx.DecodingError, httpx.StreamError, AttributeError):
            body = ""

        # -------------------------------------------------------
        # Title
        # -------------------------------------------------------

        title = ""

        try:
            lower = body.lower()
            start = lower.find("<title>")
            end = lower.find("</title>")
            if start != -1 and end != -1:
                title = body[start + 7 : end].strip()
        except (AttributeError, TypeError, ValueError):
            title = ""

        # -------------------------------------------------------
        # Headers
        # -------------------------------------------------------

        headers = dict(
            response.headers,
        )

        # -------------------------------------------------------
        # Cookies
        # -------------------------------------------------------

        cookies = dict(
            response.cookies,
        )

        # -------------------------------------------------------
        # Server
        # -------------------------------------------------------

        server = headers.get(
            "server",
            "",
        )

        # -------------------------------------------------------
        # Content Type
        # -------------------------------------------------------

        content_type = headers.get(
            "content-type",
            "",
        )

        # -------------------------------------------------------
        # Length
        # -------------------------------------------------------

        try:
            content_length = len(
                response.content,
            )
        except (AttributeError, TypeError):
            content_length = len(
                body,
            )

        # -------------------------------------------------------
        # Elapsed
        # -------------------------------------------------------

        try:
            elapsed = response.elapsed.total_seconds()
        except (AttributeError, TypeError):
            elapsed = 0.0

        # -------------------------------------------------------
        # Return
        # -------------------------------------------------------

        return ResponseData(
            status_code=response.status_code,
            url=str(
                response.url,
            ),
            body=body,
            headers=headers,
            cookies=cookies,
            elapsed=elapsed,
            content_length=content_length,
            content_type=content_type,
            server=server,
            title=title,
            payload=payload,
        )

    # ===========================================================
    # JSON Request
    # ===========================================================

    def get_json(
        self,
        url: str,
        **kwargs: Any,
    ) -> dict[str, Any]:

        response = self.get(
            url,
            **kwargs,
        )

        try:
            return json.loads(
                response.body,
            )
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}

    # ===========================================================
    # Form Request
    # ===========================================================

    def post_form(
        self,
        url: str,
        data: dict[str, Any],
        **kwargs: Any,
    ) -> ResponseData:

        return self.post(
            url,
            data=data,
            **kwargs,
        )

    # ===========================================================
    # JSON POST
    # ===========================================================

    def post_json(
        self,
        url: str,
        data: dict[str, Any],
        **kwargs: Any,
    ) -> ResponseData:

        return self.post(
            url,
            json=data,
            **kwargs,
        )

    # ===========================================================
    # Multipart Upload
    # ===========================================================

    def upload_file(
        self,
        url: str,
        files: Any,
        **kwargs: Any,
    ) -> ResponseData:

        return self.post(
            url,
            files=files,
            **kwargs,
        )

    # ===========================================================
    # Set Cookies
    # ===========================================================

    def set_cookie(
        self,
        name: str,
        value: str,
    ) -> None:

        session = self.get_session()

        session.cookies.set(
            name,
            value,
        )

    # ===========================================================
    # Clear Cookies
    # ===========================================================

    def clear_cookies(
        self,
    ) -> None:

        session = self.get_session()

        session.cookies.clear()

    # ===========================================================
    # Authorization Header
    # ===========================================================

    def bearer_headers(
        self,
        token: str,
    ) -> dict[str, str]:

        return {"Authorization": f"Bearer {token}"}

    # ===========================================================
    # Basic Authentication
    # ===========================================================

    def basic_auth(
        self,
        username: str,
        password: str,
    ) -> httpx.BasicAuth:

        return httpx.BasicAuth(
            username,
            password,
        )

    # ===========================================================
    # Statistics
    # ===========================================================

    def statistics(
        self,
    ) -> dict[str, int]:

        return {
            "requests": self.request_count,
            "responses": self.response_count,
            "errors": self.error_count,
        }

    # ===========================================================
    # Reset Statistics
    # ===========================================================

    def reset_statistics(
        self,
    ) -> None:
        """
        Reset request engine counters.
        """

        self.request_count = 0

        self.response_count = 0

        self.error_count = 0
