"""
===========================================================
Project : Sentinel AI
Module  : Login Manager (Post Exploitation)
File ID : SCANNER-LOGIN-MANAGER-001
Version : 1.0.0
===========================================================

Description:
Handles automatic login using extracted credentials.
Part of Post Exploitation Engine.

Features:
- Auto-discover login page
- CSRF token extraction
- Session management
- Multi-signal authentication verification
- Confidence scoring
- Session storage for future modules
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urljoin, urlparse

from app.modules.scanner.core.request_engine import RequestEngine, ResponseData
from app.modules.scanner.core.session_manager import SessionManager

logger = logging.getLogger(__name__)


@dataclass
class LoginResult:
    """Result of a login attempt."""

    success: bool = False
    confidence: float = 0.0
    session_cookies: Dict[str, str] = field(default_factory=dict)
    redirect_url: str = ""
    evidence: List[str] = field(default_factory=list)
    error_message: str = ""
    is_authenticated: bool = False


class LoginManager:
    """
    Handles automatic login with extracted credentials.
    Post Exploitation module for SentinelAI.
    """

    # Common login paths to try
    LOGIN_PATHS = [
        "/login",
        "/Login",
        "/log-in",
        "/sign-in",
        "/signin",
        "/auth/login",
        "/auth/signin",
        "/account/login",
        "/user/login",
        "/admin/login",
        "/member/login",
        "/portal/login",
        "/login.php",
        "/login.html",
        "/login.jsp",
        "/login.do",
        "/login.action",
        "/login?action=login",
        "/?login=1",
        "/?login=true",
        "/?action=login",
    ]

    # Success indicators for verification
    SUCCESS_KEYWORDS = [
        "logout",
        "log out",
        "sign out",
        "signout",
        "my account",
        "my-account",
        "myaccount",
        "dashboard",
        "admin",
        "administrator",
        "welcome",
        "welcome back",
        "profile",
        "user profile",
        "account settings",
        "sessions",
        "active sessions",
        "admin panel",
        "control panel",
        "you are logged in",
        "logged in",
        "not solved",
        "solved",
    ]

    # Failure indicators
    FAILURE_KEYWORDS = [
        "invalid",
        "incorrect",
        "wrong",
        "error",
        "failed",
        "try again",
        "invalid username",
        "invalid password",
        "incorrect password",
        "login failed",
        "authentication failed",
        "access denied",
    ]

    def __init__(self, request_engine: Optional[RequestEngine] = None) -> None:
        """
        Initialize LoginManager with optional RequestEngine.

        Args:
            request_engine: Existing RequestEngine for session reuse
        """
        self.request_engine = request_engine or RequestEngine()
        self.session_manager = SessionManager()
        self.login_url: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.csrf_field: Optional[str] = None
        self.hidden_fields: Dict[str, str] = {}

    def login(
        self, base_url: str, username: str, password: str, max_attempts: int = 3
    ) -> LoginResult:
        """
        Perform automatic login with credentials.

        Args:
            base_url: Base target URL
            username: Username to login with
            password: Password to login with
            max_attempts: Maximum retry attempts

        Returns:
            LoginResult with success status and evidence
        """
        logger.info(f"🔐 Starting login attempt for user: {username}")

        # Step 1: Discover login page
        login_url = self._discover_login_page(base_url)
        if not login_url:
            return LoginResult(
                success=False,
                error_message="Login page not found",
                evidence=["Could not discover login page"],
            )

        self.login_url = login_url
        logger.info(f"  ✅ Login page discovered: {login_url}")

        # Step 2: Fetch login page and extract CSRF
        fetch_result = self._fetch_login_page(login_url)
        if not fetch_result:
            return LoginResult(
                success=False,
                error_message="Could not fetch login page",
                evidence=["Login page fetch failed"],
            )

        # Step 3: Build login payload
        login_data = self._build_login_payload(username, password)

        # Step 4: Submit login request
        for attempt in range(max_attempts):
            logger.info(f"  🔄 Login attempt {attempt + 1}/{max_attempts}")
            response = self._submit_login(login_url, login_data)

            if response is None:
                continue

            # Step 5: Verify authentication
            result = self._verify_login_response(response)

            if result.success:
                logger.info(
                    f"  ✅ Login successful (confidence: {result.confidence:.0%})"
                )
                return result

        return LoginResult(
            success=False,
            error_message="All login attempts failed",
            evidence=["Max attempts reached without success"],
        )

    def _discover_login_page(self, base_url: str) -> Optional[str]:
        """
        Discover login page by testing common paths.

        Args:
            base_url: Base target URL

        Returns:
            Login page URL or None
        """
        # Parse base URL to get root
        parsed = urlparse(base_url)
        root_url = f"{parsed.scheme}://{parsed.netloc}"

        # Try each login path
        for path in self.LOGIN_PATHS:
            test_url = urljoin(root_url, path)
            try:
                response = self.request_engine.send(
                    method="GET",
                    url=test_url,
                )
                if response and response.status_code == 200:
                    # Check if it's a login page (contains login form)
                    if self._is_login_page(response.body):
                        logger.debug(f"  🔍 Found login page at: {test_url}")
                        return test_url
            except Exception as e:
                logger.debug(f"  ⚠️ Failed to test {test_url}: {e}")
                continue

        # Fallback: try /login on the base URL
        if "/filter" in base_url or "/product" in base_url:
            base_root = base_url.split("/")[0] + "//" + base_url.split("/")[2]
            fallback_url = urljoin(base_root, "/login")
            try:
                response = self.request_engine.send(
                    method="GET",
                    url=fallback_url,
                )
                if response and response.status_code == 200:
                    if self._is_login_page(response.body):
                        logger.debug(
                            f"  🔍 Found login page at fallback: {fallback_url}"
                        )
                        return fallback_url
            except Exception:
                pass

        return None

    def _is_login_page(self, html: str) -> bool:
        """
        Check if HTML contains a login form.

        Args:
            html: HTML content

        Returns:
            True if login page, False otherwise
        """
        html_lower = html.lower()
        # Check for login form
        if "<form" in html_lower and "login" in html_lower:
            return True
        if "<form" in html_lower and "password" in html_lower:
            return True
        if "username" in html_lower and "password" in html_lower:
            if "login" in html_lower or "sign" in html_lower:
                return True
        return False

    def _fetch_login_page(self, login_url: str) -> bool:
        """
        Fetch login page and extract CSRF token.

        Args:
            login_url: Login page URL

        Returns:
            True if successful, False otherwise
        """
        try:
            response = self.request_engine.send(
                method="GET",
                url=login_url,
            )

            if response is None or response.status_code != 200:
                return False

            # Update session
            self.session_manager.update_from_response(response)

            # Extract CSRF token
            self._extract_csrf(response.body)

            return True

        except Exception as e:
            logger.error(f"  ❌ Failed to fetch login page: {e}")
            return False

    def _extract_csrf(self, html: str) -> None:
        """
        Extract CSRF token from HTML.

        Args:
            html: HTML content
        """
        self.csrf_token = None
        self.csrf_field = None
        self.hidden_fields = {}

        # Common CSRF token names
        csrf_patterns = [
            r'<input[^>]*name=["\'](csrf|csrf_token|csrfmiddlewaretoken|authenticity_token|_token|token|xsrf|xsrf_token|csrf-token|__csrf|csrfToken|CSRFToken|form_token|security_token)["\'][^>]*value=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\'](csrf-token|csrf_token|csrf)["\'][^>]*content=["\']([^"\']+)["\']',
        ]

        for pattern in csrf_patterns:
            matches = re.findall(pattern, html, re.I)
            for match in matches:
                if len(match) == 2:
                    self.csrf_field = match[0]
                    self.csrf_token = match[1]
                    logger.debug(
                        f"  🔑 CSRF token found: {self.csrf_field}={self.csrf_token[:20]}..."
                    )
                    return

        # Extract all hidden fields
        hidden_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\'][^>]*>'
        matches = re.findall(hidden_pattern, html, re.I)
        for name, value in matches:
            self.hidden_fields[name] = value
            logger.debug(f"  📎 Hidden field: {name}={value[:20]}...")

    def _build_login_payload(self, username: str, password: str) -> Dict[str, str]:
        """
        Build login payload with credentials and CSRF token.

        Args:
            username: Username
            password: Password

        Returns:
            Dictionary of form data
        """
        data = {
            "username": username,
            "password": password,
        }

        # Add CSRF token if found
        if self.csrf_token and self.csrf_field:
            data[self.csrf_field] = self.csrf_token

        # Add all hidden fields
        for name, value in self.hidden_fields.items():
            if name not in data:
                data[name] = value

        return data

    def _submit_login(
        self, login_url: str, login_data: Dict[str, str]
    ) -> Optional[ResponseData]:
        """
        Submit login request.

        Args:
            login_url: Login URL
            login_data: Form data to submit

        Returns:
            ResponseData or None
        """
        try:
            response = self.request_engine.send(
                method="POST",
                url=login_url,
                data=login_data,
                cookies=self.session_manager.get_cookies(),
            )

            if response:
                self.session_manager.update_from_response(response)

            return response

        except Exception as e:
            logger.error(f"  ❌ Login submission failed: {e}")
            return None

    def _verify_login_response(self, response: ResponseData) -> LoginResult:
        """
        Verify if login was successful using multiple signals.

        Args:
            response: Login response

        Returns:
            LoginResult with verification details
        """
        if response is None:
            return LoginResult(success=False, confidence=0.0)

        confidence = 0.0
        evidence = []
        body = response.body.lower()
        headers = dict(response.headers) if hasattr(response, "headers") else {}
        cookies = dict(response.cookies) if hasattr(response, "cookies") else {}

        # ============================================================
        # Signal 1: HTTP Status Code
        # ============================================================
        if response.status_code in [301, 302, 303, 307, 308]:
            confidence += 0.25
            evidence.append(f"Redirect: {response.status_code}")

        # ============================================================
        # Signal 2: Session Cookie
        # ============================================================
        session_keywords = [
            "session",
            "sid",
            "jsessionid",
            "phpsessid",
            "sessionid",
            "ssid",
        ]
        has_session_cookie = False
        for keyword in session_keywords:
            for cookie_name in cookies.keys():
                if keyword in cookie_name.lower():
                    has_session_cookie = True
                    confidence += 0.30
                    evidence.append(f"Session cookie: {cookie_name}")
                    break
            if has_session_cookie:
                break

        # Check Set-Cookie header
        if not has_session_cookie:
            set_cookie = headers.get("set-cookie", headers.get("Set-Cookie", ""))
            for keyword in session_keywords:
                if keyword in set_cookie.lower():
                    has_session_cookie = True
                    confidence += 0.30
                    evidence.append("Session cookie in Set-Cookie header")
                    break

        # ============================================================
        # Signal 3: Success Keywords
        # ============================================================
        for keyword in self.SUCCESS_KEYWORDS:
            if keyword in body:
                confidence += 0.20
                evidence.append(f"Success keyword: '{keyword}'")
                break

        # ============================================================
        # Signal 4: No Failure Keywords
        # ============================================================
        has_failure = False
        for keyword in self.FAILURE_KEYWORDS:
            if keyword in body:
                has_failure = True
                evidence.append(f"Failure keyword: '{keyword}'")
                break

        if not has_failure and confidence > 0.3:
            confidence += 0.15
            evidence.append("No failure keywords detected")

        # ============================================================
        # Signal 5: URL changed from login
        # ============================================================
        current_url = getattr(response, "url", "")
        if self.login_url and current_url != self.login_url:
            confidence += 0.10
            evidence.append(f"Redirected from login: {current_url}")

        # ============================================================
        # Determine success
        # ============================================================
        is_success = confidence >= 0.6

        if not is_success and has_session_cookie:
            # Session cookie alone might indicate success
            is_success = True
            confidence = max(confidence, 0.6)

        # ============================================================
        # Store session if successful
        # ============================================================
        if is_success:
            # Update session manager with authentication state
            self.session_manager.update_from_response(response)
            self.session_manager.add_cookie("_sentinelai_authenticated", "true")

        result = LoginResult(
            success=is_success,
            confidence=confidence,
            session_cookies=cookies,
            redirect_url=current_url,
            evidence=evidence,
            is_authenticated=is_success,
        )

        return result

    def get_authenticated_session(self) -> Dict[str, str]:
        """
        Get authenticated session cookies.

        Returns:
            Dictionary of session cookies
        """
        return self.session_manager.get_cookies()

    def is_authenticated(self) -> bool:
        """
        Check if the current session is authenticated.

        Returns:
            True if authenticated, False otherwise
        """
        return self.session_manager.is_authenticated()
