"""
Oracle Detection module.
This module provides the detection layer for Oracle database detection.
"""

from __future__ import annotations

from typing import Any

import requests


class OracleDetection:
    """
    Base detection class for Oracle database detection.

    This class provides the foundation for Oracle detection functionality.
    It is designed to be extended by OracleEnum for full detection capabilities.
    """

    def __init__(
        self,
        waf_detector: Any = None,
        sqli_detector: Any = None,
        boolean_detector: Any = None,
        time_detector: Any = None,
        session: requests.Session | None = None,
        base_url: str | None = None,
        logger: Any = None,
    ) -> None:
        """
        Initialize OracleDetection base class.

        Args:
            waf_detector: WAF detector instance
            sqli_detector: SQL injection detector instance
            boolean_detector: Boolean blind detector instance
            time_detector: Time blind detector instance
            session: Requests session for HTTP requests
            base_url: Target base URL
            logger: Optional logger instance
        """
        self.waf_detector = waf_detector
        self.sqli_detector = sqli_detector
        self.boolean_detector = boolean_detector
        self.time_detector = time_detector
        self.session = session
        self.base_url = base_url
        self.logger = logger


class OracleEnum(OracleDetection):
    """
    Detection layer.

    Contains ONLY detection-related functionality.
    """

    def __init__(
        self,
        waf_detector: Any = None,
        sqli_detector: Any = None,
        boolean_detector: Any = None,
        time_detector: Any = None,
        session: requests.Session | None = None,
        base_url: str | None = None,
        logger: Any = None,
    ) -> None:
        """
        Initialize OracleEnum detection layer.

        Args:
            waf_detector: WAF detector instance
            sqli_detector: SQL injection detector instance
            boolean_detector: Boolean blind detector instance
            time_detector: Time blind detector instance
            session: Requests session for HTTP requests
            base_url: Target base URL
            logger: Optional logger instance
        """
        super().__init__(
            waf_detector=waf_detector,
            sqli_detector=sqli_detector,
            boolean_detector=boolean_detector,
            time_detector=time_detector,
            session=session,
            base_url=base_url,
            logger=logger,
        )
