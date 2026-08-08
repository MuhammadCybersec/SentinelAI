"""
===========================================================
Project : Sentinel AI
Module  : Browser Login Manager
Version : 3.0.0
===========================================================
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


def get_root_url(url: str) -> str:
    """Extract root URL from any DVWA URL."""
    parsed = urlparse(url)
    path = parsed.path

    if "DVWA" in path or "dvwa" in path.lower():
        parts = path.split("/")
        dvwa_index = -1
        for i, part in enumerate(parts):
            if part.lower() == "dvwa":
                dvwa_index = i
                break

        if dvwa_index != -1:
            root_path = "/" + "/".join(parts[: dvwa_index + 1])
        else:
            root_path = "/DVWA"
    else:
        root_path = "/"
        if parsed.path:
            root_path = (
                "/" + parsed.path.split("/")[1]
                if parsed.path.startswith("/")
                else parsed.path
            )

    root_url = f"{parsed.scheme}://{parsed.netloc}{root_path}"

    if "//" in root_url.replace("://", ""):
        parts = root_url.split("/")
        scheme_netloc = parts[0] + "//" + parts[2]
        path_parts = [p for p in parts[3:] if p]
        root_url = scheme_netloc + "/" + "/".join(path_parts)

    return root_url


def dvwa_login(
    base_url: str, username: str = "admin", password: str = "password"
) -> requests.Session | None:
    """Login to DVWA and return authenticated session."""
    print("\n" + "=" * 60)
    print("DVWA Login")
    print("=" * 60)

    root_url = get_root_url(base_url)
    logger.debug(f"Root URL: {root_url}")

    session = requests.Session()
    login_url = f"{root_url}/login.php"

    try:
        response = session.get(login_url, timeout=20)
    except Exception as e:
        print(f"[ERROR] Failed to fetch login page: {e}")
        return None

    if response.status_code != 200:
        print(f"[ERROR] Login page returned {response.status_code}")
        return None

    # Extract CSRF token
    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input.get("value", "") if token_input else ""

    if not token:
        token_pattern = (
            r'<input[^>]*name=["\']user_token["\'][^>]*value=["\']([^"\']+)["\']'
        )
        token_match = re.search(token_pattern, response.text, re.IGNORECASE)
        if token_match:
            token = token_match.group(1)

    logger.debug(f"CSRF Token: {token[:20] if token else 'NOT FOUND'}...")

    payload = {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    }

    try:
        response = session.post(
            login_url,
            data=payload,
            timeout=20,
            allow_redirects=True,
        )
    except Exception as e:
        print(f"[ERROR] Login request failed: {e}")
        return None

    # Verify login - silent
    if "logout" in response.text.lower():
        print("[SUCCESS] ✅ Login verified")
        logger.debug(f"Session cookies: {session.cookies.get_dict()}")

        if set_dvwa_security_low(session, root_url):
            print("[INFO] Security level set to: LOW")

        print("=" * 60)
        return session

    # Check index.php
    try:
        index_response = session.get(f"{root_url}/index.php", timeout=10)
        if "logout" in index_response.text.lower():
            print("[SUCCESS] ✅ Login verified")
            logger.debug(f"Session cookies: {session.cookies.get_dict()}")

            if set_dvwa_security_low(session, root_url):
                print("[INFO] Security level set to: LOW")

            print("=" * 60)
            return session
    except Exception:
        pass

    print("[ERROR] ❌ Login verification failed")
    print("=" * 60)
    return None


def set_dvwa_security_low(session: requests.Session, root_url: str) -> bool:
    """Set DVWA security level to LOW."""
    security_url = f"{root_url}/security.php"

    try:
        response = session.get(security_url, timeout=10)
        if response.status_code != 200:
            logger.debug(f"Failed to fetch security.php: {response.status_code}")
            return False

        soup = BeautifulSoup(response.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        csrf_token = token_input.get("value", "") if token_input else ""

        if not csrf_token:
            token_pattern = (
                r'<input[^>]*name=["\']user_token["\'][^>]*value=["\']([^"\']+)["\']'
            )
            token_match = re.search(token_pattern, response.text, re.IGNORECASE)
            if token_match:
                csrf_token = token_match.group(1)

        if not csrf_token:
            logger.debug("Could not extract CSRF token")
            return False

        payload = {
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": csrf_token,
        }

        response = session.post(
            security_url,
            data=payload,
            timeout=10,
            allow_redirects=True,
        )

        verify_response = session.get(security_url, timeout=10)
        verify_text = verify_response.text.lower()

        if 'value="low" selected' in verify_text or "selected>low" in verify_text:
            return True
        elif 'value="low"' in verify_text:
            return True
        else:
            return False

    except Exception as e:
        logger.debug(f"Failed to set security level: {e}")
        return False


def verify_session(session: requests.Session, base_url: str) -> bool:
    """Verify if session is authenticated."""
    root_url = get_root_url(base_url)
    try:
        response = session.get(f"{root_url}/index.php", timeout=10)
        return "logout" in response.text.lower()
    except Exception:
        return False


def print_session_info(session: requests.Session) -> None:
    """Print session cookies (debug only)."""
    cookies = session.cookies.get_dict()
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Session cookies: {cookies}")


if __name__ == "__main__":
    session = dvwa_login("http://localhost/DVWA")
    if session:
        print("[SUCCESS] ✅ Login test passed!")
    else:
        print("[ERROR] ❌ Login test failed!")
