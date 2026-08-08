"""
Rate Limiting Module
"""

import time
from collections import defaultdict
from typing import Dict, Optional


class RateLimiter:
    """Simple rate limiter for requests."""

    def __init__(self, requests_per_second: float = 1.0):
        self.requests_per_second = requests_per_second
        self._last_request_time: Dict[str, float] = defaultdict(float)
        self._enabled = True

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    def wait(self, key: str = "default") -> None:
        """Wait if needed to maintain rate limit."""
        if not self._enabled:
            return

        now = time.time()
        last = self._last_request_time[key]
        min_interval = 1.0 / self.requests_per_second

        if last and (now - last) < min_interval:
            sleep_time = min_interval - (now - last)
            time.sleep(sleep_time)

        self._last_request_time[key] = time.time()

    def reset(self) -> None:
        """Reset rate limiter state."""
        self._last_request_time.clear()
