"""
Active Testing Safety Gate
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from app.core.scope import ScopeManager

logger = logging.getLogger(__name__)


class TestingMode(Enum):
    """Testing modes."""

    PASSIVE = "passive"  # No active requests
    SAFE = "safe"  # Safe active requests (non-destructive)
    ACTIVE = "active"  # Full active testing


@dataclass
class SafetyGate:
    """Safety gate for active testing."""

    mode: TestingMode = TestingMode.PASSIVE
    authorized: bool = False
    target: Optional[str] = None
    scope_manager: Optional[ScopeManager] = None
    confirmed: bool = False

    def enable_active(self, target: str, scope_manager: ScopeManager) -> bool:
        """Enable active testing with confirmation."""
        self.target = target
        self.scope_manager = scope_manager
        self.confirmed = False
        self.authorized = True

        # Show warning
        print("\n" + "=" * 60)
        print("⚠️  ACTIVE TESTING WARNING")
        print("=" * 60)
        print(f"Target: {target}")
        print(f"Allowed Hosts: {scope_manager.allowed_hosts}")
        print(f"Blocked Hosts: {scope_manager.blocked_hosts}")
        print("=" * 60)
        print("\nActive testing will send requests to the target.")
        print("Only proceed if you have explicit authorization.")
        print("\nType 'YES' to confirm: ", end="")

        response = input().strip().upper()
        if response == "YES":
            self.confirmed = True
            self.mode = TestingMode.ACTIVE
            print("\n✅ Active testing enabled.")
            return True
        else:
            self.confirmed = False
            self.mode = TestingMode.PASSIVE
            print("\n❌ Active testing not enabled.")
            return False

    def enable_safe(self) -> None:
        """Enable safe active testing."""
        self.mode = TestingMode.SAFE
        self.authorized = True
        print("✅ Safe testing enabled.")

    def disable(self) -> None:
        """Disable active testing."""
        self.mode = TestingMode.PASSIVE
        self.authorized = False
        self.confirmed = False
        print("✅ Testing disabled.")

    def can_test(self) -> bool:
        """Check if active testing is allowed."""
        return (
            self.authorized
            and self.confirmed
            and self.mode in [TestingMode.SAFE, TestingMode.ACTIVE]
        )

    def can_test_url(self, url: str) -> bool:
        """Check if URL can be actively tested."""
        if not self.can_test():
            return False

        if self.scope_manager and not self.scope_manager.is_allowed(url):
            logger.warning(f"Out of scope: {url}")
            return False

        return True

    def get_status(self) -> dict:
        """Get safety gate status."""
        return {
            "mode": self.mode.value,
            "authorized": self.authorized,
            "confirmed": self.confirmed,
            "target": self.target,
            "can_test": self.can_test(),
        }
