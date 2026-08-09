"""
Session Manager for Authentication
"""

import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from app.core.http_client import HTTPClient

logger = logging.getLogger(__name__)


class SessionManager:
    """Manage authenticated sessions for targets."""

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.session = requests.Session()
        self.authenticated = False
        self.auth_config: Dict[str, Any] = {}
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.csrf_token: Optional[str] = None

    def configure(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
        extra_fields: Optional[Dict[str, str]] = None,
        csrf_token_field: Optional[str] = None,
        success_indicator: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Configure authentication parameters."""
        self.auth_config = {
            "login_url": login_url,
            "username_field": username_field,
            "password_field": password_field,
            "username": username,
            "password": password,
            "extra_fields": extra_fields or {},
            "csrf_token_field": csrf_token_field,
            "success_indicator": success_indicator or "logout",
            "headers": headers or {},
        }
        if headers:
            self.headers.update(headers)

    def login(self) -> bool:
        """Perform login and establish session."""
        if not self.auth_config:
            logger.error("Session not configured")
            return False

        try:
            # Step 1: Fetch login page for CSRF token
            login_url = self.auth_config["login_url"]
            response = self.session.get(login_url, timeout=30)

            if response.status_code != 200:
                logger.error(f"Failed to fetch login page: {response.status_code}")
                return False

            # Step 2: Extract CSRF token if needed
            csrf_token = None
            csrf_field = self.auth_config.get("csrf_token_field")
            if csrf_field:
                csrf_token = self._extract_csrf_token(response.text, csrf_field)
                if not csrf_token:
                    logger.warning("CSRF token not found, continuing without it")

            # Step 3: Build login payload
            payload = {
                self.auth_config["username_field"]: self.auth_config["username"],
                self.auth_config["password_field"]: self.auth_config["password"],
            }
            if csrf_token and csrf_field:
                payload[csrf_field] = csrf_token
            if self.auth_config["extra_fields"]:
                payload.update(self.auth_config["extra_fields"])

            # Step 4: Submit login
            headers = self.headers.copy()
            headers.update(self.auth_config["headers"])

            response = self.session.post(
                login_url,
                data=payload,
                headers=headers,
                timeout=30,
                allow_redirects=True,
            )

            # Step 5: Verify login
            success_indicator = self.auth_config["success_indicator"]
            if success_indicator in response.text.lower():
                self.authenticated = True
                self.cookies = self.session.cookies.get_dict()
                logger.info("Authentication successful")
                return True
            else:
                logger.error("Authentication failed")
                self.authenticated = False
                return False

        except Exception as e:
            logger.error(f"Authentication error: {e}")
            self.authenticated = False
            return False

    def _extract_csrf_token(self, html: str, field_name: str) -> Optional[str]:
        """Extract CSRF token from HTML."""
        soup = BeautifulSoup(html, "html.parser")
        token_input = soup.find("input", {"name": field_name})
        if token_input:
            return token_input.get("value")

        # Fallback: regex
        pattern = (
            rf'<input[^>]*name=["\']{field_name}["\'][^>]*value=["\']([^"\']+)["\']'
        )
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

        return None

    def get_session(self) -> requests.Session:
        """Get authenticated session."""
        return self.session

    def get_cookies(self) -> Dict[str, str]:
        """Get session cookies."""
        return self.cookies

    def is_authenticated(self) -> bool:
        """Check if session is authenticated."""
        return self.authenticated

    def logout(self) -> None:
        """Logout and clear session."""
        self.session.close()
        self.session = requests.Session()
        self.authenticated = False
        self.cookies = {}
        logger.info("Logged out")

    def refresh(self) -> bool:
        """Refresh authentication."""
        if not self.auth_config:
            return False
        self.logout()
        return self.login()
