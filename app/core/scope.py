"""
Scope Enforcement Module
"""

import re
from typing import List, Optional
from urllib.parse import urlparse


class ScopeManager:
    """Manages scope for authorized targets."""

    def __init__(self):
        self.allowed_hosts: List[str] = []
        self.allowed_paths: List[str] = []
        self.blocked_hosts: List[str] = []
        self.blocked_paths: List[str] = []
        self._initialized = False

    def configure(
        self,
        target: str,
        allowed_hosts: Optional[List[str]] = None,
        blocked_hosts: Optional[List[str]] = None,
        allowed_paths: Optional[List[str]] = None,
        blocked_paths: Optional[List[str]] = None,
    ) -> None:
        """Configure scope from target and optional rules."""
        parsed = urlparse(target)
        host = parsed.netloc or target

        # Default: only target host is allowed
        self.allowed_hosts = [host]
        self.allowed_paths = allowed_paths or []
        self.blocked_hosts = blocked_hosts or []
        self.blocked_paths = blocked_paths or []
        self._initialized = True

    def is_allowed(self, url: str) -> bool:
        """Check if URL is in scope."""
        if not self._initialized:
            return True  # Allow if not configured (safe default for local)

        parsed = urlparse(url)
        host = parsed.netloc or url

        # Check blocked hosts
        for blocked in self.blocked_hosts:
            if blocked in host:
                return False

        # Check allowed hosts
        allowed = False
        for allowed_host in self.allowed_hosts:
            if allowed_host in host:
                allowed = True
                break

        if not allowed:
            return False

        # Check path restrictions
        if self.allowed_paths:
            path_allowed = False
            for path in self.allowed_paths:
                if parsed.path.startswith(path):
                    path_allowed = True
                    break
            if not path_allowed:
                return False

        # Check blocked paths
        for blocked in self.blocked_paths:
            if parsed.path.startswith(blocked):
                return False

        return True

    def is_out_of_scope(self, url: str) -> bool:
        """Check if URL is out of scope."""
        return not self.is_allowed(url)
