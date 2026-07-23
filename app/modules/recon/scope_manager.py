"""
===========================================================
Project : Sentinel AI
Module  : Scope Manager
File ID : RECON-SCOPE-001
Version : 2.0.0
===========================================================

Description

Production scope manager.

Features

• In Scope
• Out Of Scope
• Wildcards
• Subdomains
• URL Normalization
• Scope Validation

===========================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from app.modules.recon.url_normalizer import normalize_url

# ===========================================================
# Scope Rule
# ===========================================================


@dataclass(slots=True)
class ScopeRule:
    """
    Single scope rule.
    """

    pattern: str

    include: bool = True

    allow_subdomains: bool = True

    enabled: bool = True


# ===========================================================
# Scope Manager
# ===========================================================


class ScopeManager:
    """
    Manage Bug Bounty scope.
    """

    def __init__(self) -> None:

        self.in_scope: list[ScopeRule] = []

        self.out_of_scope: list[ScopeRule] = []

        self.allowed_hosts: set[str] = set()

        self.blocked_hosts: set[str] = set()

    # =======================================================
    # Normalize URL
    # =======================================================

    @staticmethod
    def normalize(
        url: str,
    ) -> str:
        """
        Normalize URL.
        """

        return normalize_url(url)

    # =======================================================
    # Extract Host
    # =======================================================

    @staticmethod
    def host(
        url: str,
    ) -> str:
        """
        Return hostname.
        """

        parsed = urlparse(url)

        return (parsed.hostname or "").lower()

    # =======================================================

    # Add In-Scope Rule
    # =======================================================

    def add_scope(
        self,
        pattern: str,
        allow_subdomains: bool = True,
    ) -> None:
        """
        Add an in-scope rule.
        """

        rule = ScopeRule(
            pattern=pattern.lower().strip(),
            include=True,
            allow_subdomains=allow_subdomains,
        )

        self.in_scope.append(rule)

    # =======================================================
    # Add Out-of-Scope Rule
    # =======================================================

    def add_out_of_scope(
        self,
        pattern: str,
        allow_subdomains: bool = True,
    ) -> None:
        """
        Add an out-of-scope rule.
        """

        rule = ScopeRule(
            pattern=pattern.lower().strip(),
            include=False,
            allow_subdomains=allow_subdomains,
        )

        self.out_of_scope.append(rule)

    # =======================================================
    # Allow Host
    # =======================================================

    def allow_host(
        self,
        host: str,
    ) -> None:
        """
        Allow a specific hostname.
        """

        self.allowed_hosts.add(host.lower().strip())

    # =======================================================
    # Block Host
    # =======================================================

    def block_host(
        self,
        host: str,
    ) -> None:
        """
        Block a specific hostname.
        """

        self.blocked_hosts.add(host.lower().strip())

    # =======================================================
    # Clear Scope
    # =======================================================

    def clear(
        self,
    ) -> None:
        """
        Remove all scope rules.
        """

        self.in_scope.clear()

        self.out_of_scope.clear()

        self.allowed_hosts.clear()

        self.blocked_hosts.clear()

    # =======================================================
    # Load Scope
    # =======================================================

    def load_scope(
        self,
        scope: list[dict],
    ) -> None:
        """
        Load scope rules from configuration.
        """

        self.clear()

        for item in scope:

            pattern = item.get("pattern", "")

            if not pattern:
                continue

            include = item.get(
                "include",
                True,
            )

            allow_subdomains = item.get(
                "allow_subdomains",
                True,
            )

            if include:

                self.add_scope(
                    pattern,
                    allow_subdomains,
                )

            else:

                self.add_out_of_scope(
                    pattern,
                    allow_subdomains,
                )
        # =======================================================

    # Host Match
    # =======================================================

    @staticmethod
    def _match_host(
        host: str,
        rule: ScopeRule,
    ) -> bool:
        """
        Match hostname against a scope rule.
        """

        pattern = rule.pattern.lower()

        # Wildcard (*.example.com)
        if pattern.startswith("*."):

            base = pattern[2:]

            return host == base or host.endswith("." + base)

        # Exact match
        if host == pattern:

            return True

        # Subdomains allowed
        if rule.allow_subdomains:

            return host.endswith("." + pattern)

        return False

    # =======================================================
    # Is Allowed
    # =======================================================

    def is_allowed(
        self,
        url: str,
    ) -> bool:
        """
        Check whether URL is inside scope.
        """

        host = self.host(url)

        if not host:

            return False

        # Explicitly blocked
        if host in self.blocked_hosts:

            return False

        # Explicitly allowed
        if host in self.allowed_hosts:

            return True

        # Out-of-scope rules
        for rule in self.out_of_scope:

            if rule.enabled and self._match_host(host, rule):
                return False

        # No in-scope rules means allow everything
        if not self.in_scope:

            return True

        # In-scope rules
        for rule in self.in_scope:

            if rule.enabled and self._match_host(host, rule):
                return True

        # Default deny
        return False
