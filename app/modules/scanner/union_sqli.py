# app/modules/scanner/union_sqli.py
"""
Union-based SQL injection detection and exploitation.
"""

import logging
import requests
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode


class UnionSQLi:
    """
    Handles HTTP requests for SQL injection testing.
    """

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize UnionSQLi module.

        Args:
            session: Requests session for HTTP requests
            base_url: Target base URL
            logger: Optional logger instance
        """
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("UnionSQLi")
        logger.setLevel(logging.DEBUG)
        if not logger.handlers:
            ch = logging.StreamHandler()
            ch.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            ch.setFormatter(formatter)
            logger.addHandler(ch)
        return logger

    def _build_url(
        self, injection_point: Optional[str] = None, payload: Optional[str] = None
    ) -> Tuple[str, Dict]:
        """
        Build URL with injection payload.

        Args:
            injection_point: Parameter name to inject into
            payload: SQL injection payload

        Returns:
            Tuple[str, Dict]: (URL, parameters)
        """
        parsed = urlparse(self.base_url)
        params = parse_qs(parsed.query)

        # Add injection if specified
        if injection_point and payload is not None:
            # Replace or add the injection point
            params[injection_point] = [payload]

        # Remove value list wrapping for proper URL encoding
        flat_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}

        return parsed._replace(query=urlencode(flat_params)).geturl(), params

    def send_request(
        self,
        injection_point: Optional[str] = None,
        payload: Optional[str] = None,
        params: Optional[Dict] = None,
    ) -> Optional[requests.Response]:
        """
        Send HTTP request with optional injection payload.

        Args:
            injection_point: Parameter name to inject into
            payload: SQL injection payload
            params: Additional query parameters

        Returns:
            Optional[requests.Response]: Response object or None on failure
        """
        try:
            if injection_point and payload is not None:
                url, _ = self._build_url(injection_point, payload)
            else:
                url = self.base_url

            # Add any additional params
            if params:
                url += (
                    "&" + urlencode(params) if "?" in url else "?" + urlencode(params)
                )

            self.logger.debug(f"[UnionSQLi] Sending request to: {url}")

            response = self.session.get(url, timeout=10, allow_redirects=True)
            response.raise_for_status()

            self.logger.debug(f"[UnionSQLi] Response status: {response.status_code}")
            self.logger.debug(f"[UnionSQLi] Response length: {len(response.text)}")

            return response

        except requests.RequestException as e:
            self.logger.error(f"[UnionSQLi] Request failed: {str(e)}")
            return None

    def get_baseline(
        self, injection_point: Optional[str] = None
    ) -> Optional[requests.Response]:
        """
        Get baseline response without injection.

        Args:
            injection_point: Parameter to exclude (optional)

        Returns:
            Optional[requests.Response]: Baseline response
        """
        return self.send_request(injection_point, None)

    def test_payload(
        self,
        injection_point: str,
        payload: str,
        baseline: Optional[requests.Response] = None,
    ) -> Dict[str, Any]:
        """
        Test a single payload and return response with metadata.

        Args:
            injection_point: Parameter to inject into
            payload: SQL injection payload
            baseline: Optional baseline response for comparison

        Returns:
            Dict: Response metadata
        """
        response = self.send_request(injection_point, payload)

        if response is None:
            return {"success": False, "response": None, "error": "Request failed"}

        result = {
            "success": True,
            "response": response,
            "status_code": response.status_code,
            "content_length": len(response.text),
            "url": response.url,
            "has_changed": False,
        }

        # Compare with baseline if provided
        if baseline:
            result["baseline_length"] = len(baseline.text)
            result["length_diff"] = len(response.text) - len(baseline.text)
            result["has_changed"] = response.text != baseline.text

        return result
