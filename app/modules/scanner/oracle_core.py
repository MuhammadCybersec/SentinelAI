from __future__ import annotations

import requests

from .oracle_core import OracleCore


class OracleEnum(OracleCore):
    """
    Shared base class for Oracle modules.

    This class stores common configuration and helper objects.
    Business logic should NOT live here.
    """

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        timeout: int = 10,
        **kwargs,
    ):
        super().__init__(
            session=session,
            base_url=base_url,
            timeout=timeout,
        )

        self.config = kwargs

    def get_session(self):
        return self.session

    def get_base_url(self):
        return self.base_url

    def get_timeout(self):
        return self.timeout
