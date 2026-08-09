"""
Endpoint Inventory - Normalized endpoint storage
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class Endpoint:
    """Normalized endpoint representation."""

    url: str
    method: str = "GET"
    path: str = ""
    host: str = ""
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    path_params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body_params: Dict[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None
    discovered_from: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "url": self.url,
            "method": self.method,
            "path": self.path,
            "host": self.host,
            "query_params": self.query_params,
            "path_params": self.path_params,
            "headers": self.headers,
            "body_params": self.body_params,
            "content_type": self.content_type,
            "discovered_from": self.discovered_from,
        }

    def get_fingerprint(self) -> str:
        """Get unique fingerprint for deduplication."""
        return f"{self.method}:{self.path}"


class EndpointInventory:
    """Store and manage discovered endpoints."""

    def __init__(self):
        self.endpoints: List[Endpoint] = []
        self._fingerprints: Set[str] = set()
        self._by_host: Dict[str, List[Endpoint]] = {}
        self._by_path: Dict[str, List[Endpoint]] = {}

    def add(self, endpoint: Endpoint) -> bool:
        """Add endpoint if not already present."""
        fingerprint = endpoint.get_fingerprint()
        if fingerprint in self._fingerprints:
            return False

        self.endpoints.append(endpoint)
        self._fingerprints.add(fingerprint)

        # Index by host
        if endpoint.host not in self._by_host:
            self._by_host[endpoint.host] = []
        self._by_host[endpoint.host].append(endpoint)

        # Index by path
        if endpoint.path not in self._by_path:
            self._by_path[endpoint.path] = []
        self._by_path[endpoint.path].append(endpoint)

        return True

    def get_all(self) -> List[Endpoint]:
        """Get all endpoints."""
        return self.endpoints

    def get_by_host(self, host: str) -> List[Endpoint]:
        """Get endpoints by host."""
        return self._by_host.get(host, [])

    def get_by_path(self, path: str) -> List[Endpoint]:
        """Get endpoints by path."""
        return self._by_path.get(path, [])

    def get_by_method(self, method: str) -> List[Endpoint]:
        """Get endpoints by HTTP method."""
        return [e for e in self.endpoints if e.method == method.upper()]

    def get_with_params(self) -> List[Endpoint]:
        """Get endpoints with parameters."""
        return [
            e
            for e in self.endpoints
            if e.query_params or e.body_params or e.path_params
        ]

    def count(self) -> int:
        """Get total endpoint count."""
        return len(self.endpoints)

    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "total": self.count(),
            "endpoints": [e.to_dict() for e in self.endpoints],
            "by_host": {
                host: [e.to_dict() for e in endpoints]
                for host, endpoints in self._by_host.items()
            },
        }

    @staticmethod
    def from_url(url: str, method: str = "GET") -> Endpoint:
        """Create Endpoint from URL."""
        parsed = urlparse(url)
        return Endpoint(
            url=url,
            method=method.upper(),
            path=parsed.path,
            host=parsed.netloc,
            query_params=parse_qs(parsed.query),
        )
