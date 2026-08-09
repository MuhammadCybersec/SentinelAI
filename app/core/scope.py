"""
Scope Enforcement Module
"""

import re
from typing import List, Optional, Set
from urllib.parse import urlparse


class ScopeRule:
    """Individual scope rule."""

    def __init__(self, pattern: str, rule_type: str = "allow"):
        self.pattern = pattern
        self.rule_type = rule_type  # allow, deny, exclude
        self._compiled = re.compile(pattern.replace("*", ".*"))

    def matches(self, url: str) -> bool:
        """Check if URL matches this rule."""
        return bool(self._compiled.search(url))


class ScopeManager:
    """Manages scope for authorized targets."""

    def __init__(self):
        self.target: Optional[str] = None
        self.allowed_hosts: Set[str] = set()
        self.allowed_paths: Set[str] = set()
        self.blocked_hosts: Set[str] = set()
        self.blocked_paths: Set[str] = set()
        self.rules: List[ScopeRule] = []
        self._initialized = False
        self._authorized = False

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

        self.target = target
        self.allowed_hosts = {host}
        self.allowed_paths = set(allowed_paths or [])
        self.blocked_hosts = set(blocked_hosts or [])
        self.blocked_paths = set(blocked_paths or [])

        # Create rules
        self.rules = []
        for h in self.allowed_hosts:
            self.rules.append(ScopeRule(h, "allow"))
        for h in self.blocked_hosts:
            self.rules.append(ScopeRule(h, "deny"))
        for p in self.allowed_paths:
            self.rules.append(ScopeRule(p, "allow"))
        for p in self.blocked_paths:
            self.rules.append(ScopeRule(p, "deny"))

        self._initialized = True

    def authorize(self) -> None:
        """Mark target as authorized for testing."""
        self._authorized = True

    def is_authorized(self) -> bool:
        """Check if target is authorized."""
        return self._authorized

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

    def get_scope_summary(self) -> dict:
        """Get scope summary."""
        return {
            "target": self.target,
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_paths": list(self.allowed_paths),
            "blocked_hosts": list(self.blocked_hosts),
            "blocked_paths": list(self.blocked_paths),
            "authorized": self._authorized,
            "initialized": self._initialized,
        }
