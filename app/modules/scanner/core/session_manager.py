"""
===========================================================
Project : Sentinel AI
Module  : Session Manager
File ID : SCANNER-CORE-SESSION-001
Version : 1.1.0
===========================================================

Description:
Manages HTTP sessions, cookies, and state persistence.
Pure session management — no vulnerability detection.

Responsibilities:
- Cookie jar management
- Session persistence
- Header preservation
- Redirect handling
- Session state tracking
- Session statistics
- Authentication state tracking
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class SessionState:
    """Represents a session state."""

    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    session_id: Optional[str] = None
    is_authenticated: bool = False
    last_response_url: str = ""
    redirect_count: int = 0
    login_timestamp: Optional[float] = None


class SessionManager:
    """
    Manages HTTP sessions and cookies.
    No vulnerability detection — pure session management.
    """

    def __init__(self):
        self._state = SessionState()
        self._history: List[Dict[str, str]] = []

    def update_from_response(self, response) -> None:
        """
        Update session state from HTTP response.

        Args:
            response: HTTP response object
        """
        if response is None:
            return

        # Update cookies
        if hasattr(response, "cookies"):
            if hasattr(response.cookies, "items"):
                self._state.cookies.update(dict(response.cookies.items()))
            else:
                self._state.cookies.update(dict(response.cookies))

        # Update headers
        if hasattr(response, "headers"):
            headers = dict(response.headers)
            self._state.headers.update(headers)

            # Check for session cookie
            set_cookie = headers.get("set-cookie", headers.get("Set-Cookie", ""))
            if set_cookie:
                self._extract_session_id(set_cookie)

        # Track redirects
        if hasattr(response, "history"):
            self._state.redirect_count = len(response.history)

        # Store last URL
        if hasattr(response, "url"):
            self._state.last_response_url = response.url

        # Record history
        self._history.append(
            {
                "url": self._state.last_response_url,
                "status": getattr(response, "status_code", 0),
                "session_id": self._state.session_id,
            }
        )

    def _extract_session_id(self, set_cookie: str) -> None:
        """Extract session ID from Set-Cookie header."""
        session_patterns = [
            "session",
            "sid",
            "jsessionid",
            "phpsessid",
            "sessionid",
            "ssid",
            "auth",
            "token",
            "access_token",
        ]

        for pattern in session_patterns:
            match = re.search(rf"{pattern}=([^;]+)", set_cookie, re.I)
            if match:
                self._state.session_id = match.group(1)
                self._state.is_authenticated = True
                break

    def get_cookies(self) -> Dict[str, str]:
        """Get all cookies."""
        return dict(self._state.cookies)

    def get_headers(self) -> Dict[str, str]:
        """Get all headers."""
        return dict(self._state.headers)

    def get_session_id(self) -> Optional[str]:
        """Get session ID if available."""
        return self._state.session_id

    def is_authenticated(self) -> bool:
        """Check if session is authenticated."""
        return self._state.is_authenticated

    def get_redirect_count(self) -> int:
        """Get number of redirects in current session."""
        return self._state.redirect_count

    def get_history(self) -> List[Dict[str, str]]:
        """Get session history."""
        return self._history.copy()

    def reset(self) -> None:
        """Reset session state."""
        self._state = SessionState()
        self._history = []

    def add_cookie(self, name: str, value: str) -> None:
        """Add a cookie to the session."""
        self._state.cookies[name] = value

    def add_header(self, name: str, value: str) -> None:
        """Add a header to the session."""
        self._state.headers[name] = value

    def set_authenticated(self, authenticated: bool = True) -> None:
        """Set authentication state."""
        self._state.is_authenticated = authenticated


def create_session_manager() -> SessionManager:
    """Create a SessionManager instance."""
    return SessionManager()
