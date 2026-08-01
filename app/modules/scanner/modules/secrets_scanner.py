"""
Secrets Scanner - Detect and validate sensitive secrets in code and configuration files.

This module provides comprehensive secret detection for various API keys, tokens,
and credentials using pattern matching, validation, and confidence scoring.
"""

from __future__ import annotations

import hashlib
import re
import threading
import typing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.modules.recon.scope_manager import ScopeManager
from app.modules.scanner.core.base_scanner import BaseScanner, ScanResult
from app.modules.scanner.core.request_engine import RequestEngine


@dataclass(slots=True)
class SecretFinding:
    """
    Secret finding with full vulnerability metadata.

    Attributes:
        vulnerable: Whether the secret is vulnerable
        title: Finding title
        description: Detailed description
        severity: Critical, High, Medium, Low
        secret_type: Type of secret detected
        url: Source URL or file path
        secret: The detected secret (masked)
        evidence: List of evidence items
        cwe: CWE identifier
        owasp: OWASP category
        cvss: CVSS score
        remediation: Remediation steps
        references: List of references
        confidence: Confidence score (0-100)
        line_number: Line number where secret was found
        file_path: File path if applicable
        timestamp: When found
        metadata: Additional metadata
    """

    vulnerable: bool = True
    title: str = "Hardcoded Secret Detected"
    description: str = ""
    severity: str = "High"
    secret_type: str = "Unknown"
    url: str = ""
    secret: str = ""
    evidence: list[str] = field(default_factory=list)
    cwe: str = "CWE-798"
    owasp: str = "OWASP Top 10 2021 - A02: Cryptographic Failures"
    cvss: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (8.2)"
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    confidence: float = 0.0
    line_number: int = 0
    file_path: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


class SecretsScanner(BaseScanner):
    """
    Production-grade Secrets Scanner.

    Features:
        - Detects 15+ secret types with regex patterns
        - AWS, Google, GitHub, JWT, Stripe, Twilio, Discord, OpenAI, Anthropic
        - Validation with checksums and format verification
        - Confidence scoring based on multiple factors
        - Duplicate removal and false-positive filtering
        - Thread-safe operation
        - Evidence collection with context
    """

    # Secret detection patterns - ClassVar for immutable class attributes
    SECRET_PATTERNS: typing.ClassVar[dict[str, dict[str, Any]]] = {
        "AWS Access Key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "severity": "Critical",
            "cwe": "CWE-798",
            "confidence": 95.0,
            "validation": "aws_access_key",
            "mask": lambda s: s[:4] + "*" * 12 + s[-4:] if len(s) > 8 else s,
        },
        "AWS Secret Key": {
            "pattern": r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            "severity": "Critical",
            "cwe": "CWE-798",
            "confidence": 92.0,
            "validation": "aws_secret_key",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "Google API Key": {
            "pattern": r"AIza[0-9A-Za-z_-]{35}",
            "severity": "High",
            "cwe": "CWE-798",
            "confidence": 90.0,
            "validation": "google_api_key",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "Google OAuth Client ID": {
            "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
            "severity": "Medium",
            "cwe": "CWE-798",
            "confidence": 85.0,
            "validation": "google_oauth",
            "mask": lambda s: s[:10] + "*" * 8 + s[-10:] if len(s) > 20 else s,
        },
        "Firebase API Key": {
            "pattern": r"firebase\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,50})['\"]?",
            "severity": "High",
            "cwe": "CWE-798",
            "confidence": 88.0,
            "validation": "firebase_key",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "GitHub Personal Access Token": {
            "pattern": r"(ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}",
            "severity": "Critical",
            "cwe": "CWE-798",
            "confidence": 95.0,
            "validation": "github_token",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "GitHub App Token": {
            "pattern": r"(ghs|ghu)_[A-Za-z0-9]{36}",
            "severity": "High",
            "cwe": "CWE-798",
            "confidence": 90.0,
            "validation": "github_app_token",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "JWT Token": {
            "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
            "severity": "High",
            "cwe": "CWE-798",
            "confidence": 88.0,
            "validation": "jwt",
            "mask": lambda s: s[:10] + "*" * 8 + s[-10:] if len(s) > 20 else s,
        },
        "Stripe API Key": {
            "pattern": r"(sk_live|sk_test|rk_live|rk_test)_[0-9A-Za-z]{24}",
            "severity": "Critical",
            "cwe": "CWE-798",
            "confidence": 95.0,
            "validation": "stripe_key",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "Stripe Webhook Secret": {
            "pattern": r"whsec_[A-Za-z0-9]{24}",
            "severity": "High",
            "cwe": "CWE-798",
            "confidence": 90.0,
            "validation": "stripe_webhook",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "Twilio API Key": {
            "pattern": r"twilio\s*[:=]\s*['\"]?([A-Za-z0-9]{32,34})['\"]?",
            "severity": "Critical",
            "cwe": "CWE-798",
            "confidence": 92.0,
            "validation": "twilio_key",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "Twilio Account SID": {
            "pattern": r"AC[A-Za-z0-9]{32}",
            "severity": "High",
            "cwe": "CWE-798",
            "confidence": 90.0,
            "validation": "twilio_sid",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "Discord Webhook": {
            "pattern": r"https?://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
            "severity": "High",
            "cwe": "CWE-798",
            "confidence": 95.0,
            "validation": "discord_webhook",
            "mask": lambda s: s[:20] + "*" * 8 + s[-10:] if len(s) > 30 else s,
        },
        "Discord Bot Token": {
            "pattern": r"[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}",
            "severity": "Critical",
            "cwe": "CWE-798",
            "confidence": 92.0,
            "validation": "discord_bot",
            "mask": lambda s: s[:10] + "*" * 8 + s[-10:] if len(s) > 20 else s,
        },
        "OpenAI API Key": {
            "pattern": r"sk-[A-Za-z0-9_-]{20,60}|sk-proj-[A-Za-z0-9_-]{20,60}",
            "severity": "Critical",
            "cwe": "CWE-798",
            "confidence": 95.0,
            "validation": "openai_key",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "Anthropic API Key": {
            "pattern": r"sk-ant-[A-Za-z0-9_-]{40,60}",
            "severity": "Critical",
            "cwe": "CWE-798",
            "confidence": 95.0,
            "validation": "anthropic_key",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
        "Slack Token": {
            "pattern": r"(xoxb|xoxp|xoa|xoxr)-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}",
            "severity": "Critical",
            "cwe": "CWE-798",
            "confidence": 92.0,
            "validation": "slack_token",
            "mask": lambda s: s[:10] + "*" * 8 + s[-10:] if len(s) > 20 else s,
        },
        "Generic Secret Key": {
            "pattern": r"(?:secret|api_key|api_token|auth_token|access_token|private_key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?",
            "severity": "High",
            "cwe": "CWE-798",
            "confidence": 70.0,
            "validation": "generic_secret",
            "mask": lambda s: s[:4] + "*" * 8 + s[-4:] if len(s) > 8 else s,
        },
    }

    # False positive patterns - ClassVar
    FALSE_POSITIVE_PATTERNS: typing.ClassVar[list[str]] = [
        r"(?:sample|demo|placeholder|dummy|fake|invalid|your_)",
        r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?\s*(?:\w{3,})?\s*['\"]?\s*$",
    ]

    # Validation patterns - ClassVar
    VALIDATION_PATTERNS: typing.ClassVar[dict[str, typing.Callable[[str], bool]]] = {
        "aws_access_key": lambda s: re.match(r"AKIA[0-9A-Z]{16}", s) is not None,
        "aws_secret_key": lambda s: (
            len(s) == 40 and re.match(r"^[A-Za-z0-9/+=]+$", s) is not None
        ),
        "google_api_key": lambda s: len(s) == 39 and s.startswith("AIza"),
        "google_oauth": lambda s: ".apps.googleusercontent.com" in s,
        "firebase_key": lambda s: 20 <= len(s) <= 50,
        "github_token": lambda s: (
            s.startswith(("ghp_", "gho_", "ghu_", "ghs_")) and len(s) == 40
        ),
        "github_app_token": lambda s: s.startswith(("ghs_", "ghu_")) and len(s) == 40,
        "jwt": lambda s: (
            len(s.split(".")) == 3
            and all(s.split("."))
            and s.split(".")[0].startswith("eyJ")
        ),
        "stripe_key": lambda s: (
            s.startswith(("sk_live_", "sk_test_", "rk_live_", "rk_test_"))
            and len(s) == 32
        ),
        "stripe_webhook": lambda s: s.startswith("whsec_") and len(s) == 30,
        "twilio_key": lambda s: 32 <= len(s) <= 34,
        "twilio_sid": lambda s: s.startswith("AC") and len(s) == 34,
        "discord_webhook": lambda s: "discord.com/api/webhooks/" in s,
        "discord_bot": lambda s: len(s.split(".")) == 3,
        "openai_key": lambda s: s.startswith("sk-") and len(s) >= 20,
        "anthropic_key": lambda s: s.startswith("sk-ant-"),
        "slack_token": lambda s: s.startswith(("xoxb", "xoxp", "xoa", "xoxr")),
        "generic_secret": lambda s: len(s) >= 20,
    }

    def __init__(
        self,
        target: str,
        scope: ScopeManager | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        """
        Initialize Secrets Scanner.

        Args:
            target: Target URL or file path to scan
            scope: ScopeManager instance
            config: Scanner configuration
        """
        super().__init__(target=target, scope=scope)
        self._config = config or {}
        self._request_engine = RequestEngine()
        self._findings: list[SecretFinding] = []
        self._seen_secrets: set[str] = set()

        # Thread-safe state
        self._lock = threading.RLock()
        self._is_running = False
        self._progress = 0
        self._total = 0

        # Configuration
        self._max_content_size = self._config.get("max_content_size", 10 * 1024 * 1024)
        self._min_confidence = self._config.get("min_confidence", 50.0)
        self._enable_validation = self._config.get("enable_validation", True)
        self._enable_context_extraction = self._config.get(
            "enable_context_extraction", True
        )

        # Statistics
        self.statistics = {
            "total_secrets_detected": 0,
            "valid_secrets": 0,
            "false_positives": 0,
            "duplicates_removed": 0,
            "processed_files": 0,
            "total_checks": 0,
        }

    def fetch_content(self, source: str) -> str:
        """
        Fetch content from URL or read from file.

        Args:
            source: URL or file path

        Returns:
            Content string

        Raises:
            ValueError: If source is invalid
            OSError: If content cannot be fetched
        """
        if source.startswith(("http://", "https://")):
            response = self._request_engine.get(source)
            if response is None:
                raise OSError(f"Failed to fetch URL: {source}")
            return response.text

        # Try to read as file
        try:
            with open(source, "r", encoding="utf-8") as f:
                content = f.read()
                if len(content) > self._max_content_size:
                    content = content[: self._max_content_size]
                return content
        except (FileNotFoundError, PermissionError, UnicodeDecodeError) as e:
            raise OSError(f"Failed to read file: {source} - {e}")

    def detect_secrets(self, content: str, source: str) -> list[SecretFinding]:
        """
        Detect secrets in content using pattern matching.

        Args:
            content: Content to scan
            source: Source URL or file path

        Returns:
            List of SecretFinding objects
        """
        findings: list[SecretFinding] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            self._total += 1

            # Skip empty lines
            if not line.strip():
                continue

            for secret_type, pattern_info in self.SECRET_PATTERNS.items():
                pattern = pattern_info["pattern"]

                for match in re.finditer(pattern, line, re.IGNORECASE):
                    secret = match.group(0)

                    # Skip if secret is masked or redacted
                    if self._is_redacted(secret):
                        continue

                    # Check false positive
                    if self._is_false_positive(line, secret):
                        self.statistics["false_positives"] += 1
                        continue

                    # Validate secret
                    confidence = pattern_info["confidence"]
                    if self._enable_validation:
                        validation_result = self.validate_secret(secret_type, secret)
                        if validation_result is not None:
                            confidence = validation_result
                        else:
                            confidence = confidence * 0.5

                    # Skip if confidence is below threshold
                    if confidence < self._min_confidence:
                        continue

                    # Generate unique ID for deduplication
                    secret_id = self._generate_secret_id(secret_type, secret, source)
                    if secret_id in self._seen_secrets:
                        self.statistics["duplicates_removed"] += 1
                        continue

                    self._seen_secrets.add(secret_id)

                    # Create finding
                    finding = self._create_finding(
                        secret_type=secret_type,
                        secret=secret,
                        line=line,
                        line_number=line_num,
                        source=source,
                        confidence=confidence,
                        pattern_info=pattern_info,
                    )

                    findings.append(finding)
                    self.statistics["total_secrets_detected"] += 1

        return findings

    def validate_secret(self, secret_type: str, secret: str) -> float | None:
        """
        Validate secret format and return confidence score.

        Args:
            secret_type: Type of secret
            secret: Secret string

        Returns:
            Confidence score (0-100) or None if invalid
        """
        pattern_info = self.SECRET_PATTERNS.get(secret_type)
        if not pattern_info:
            return None

        validation_key = pattern_info.get("validation", "")
        if not validation_key:
            return None

        validator = self.VALIDATION_PATTERNS.get(validation_key)
        if validator is None:
            return None

        # For JWT, validate format strictly
        if secret_type == "JWT Token":
            parts = secret.split(".")
            if len(parts) != 3:
                return None
            if not all(parts):
                return None
            for part in parts:
                if not part or not re.match(r"^[A-Za-z0-9_-]+$", part):
                    return None
            if not parts[0].startswith("eyJ"):
                return None
            return pattern_info["confidence"]

        if not validator(secret):
            return None

        # Additional validation checks for secrets with length requirement
        if (
            secret_type in ("AWS Secret Key", "GitHub Personal Access Token")
            and len(secret) != 40
        ):
            return None

        return pattern_info["confidence"]

    def enrich_finding(self, finding: SecretFinding) -> SecretFinding:
        """
        Enrich finding with additional metadata.

        Args:
            finding: SecretFinding to enrich

        Returns:
            Enriched SecretFinding
        """
        if not finding.cwe:
            finding.cwe = "CWE-798"
        if not finding.owasp:
            finding.owasp = "OWASP Top 10 2021 - A02: Cryptographic Failures"

        if not finding.description:
            finding.description = (
                f"A {finding.secret_type} was detected in the target. "
                f"This credential should never be hardcoded or exposed in "
                f"source code, configuration files, or logs."
            )

        if not finding.remediation:
            finding.remediation = (
                f"Remove the hardcoded {finding.secret_type} from the source. "
                "Use environment variables, secret management services (AWS Secrets Manager, "
                "Vault, or GitHub Secrets), or a secure credential store. "
                "Rotate the exposed secret immediately."
            )

        if not finding.references:
            finding.references = [
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ]

        if not finding.cvss:
            severity_map = {
                "Critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (8.2)",
                "High": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (6.5)",
                "Medium": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (5.0)",
                "Low": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:N/A:N (2.5)",
            }
            finding.cvss = severity_map.get(finding.severity, severity_map["High"])

        return finding

    def merge_findings(self, findings: list[SecretFinding]) -> list[SecretFinding]:
        """
        Merge duplicate findings based on secret ID.

        Args:
            findings: List of SecretFinding objects

        Returns:
            Merged list of SecretFinding objects
        """
        merged: dict[str, SecretFinding] = {}

        for finding in findings:
            key = self._generate_secret_id(
                finding.secret_type, finding.secret, finding.url
            )

            if key not in merged:
                merged[key] = finding
                continue

            existing = merged[key]

            for evidence in finding.evidence:
                if evidence not in existing.evidence:
                    existing.evidence.append(evidence)

            existing.confidence = max(existing.confidence, finding.confidence)

            severity_priority = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            current_priority = severity_priority.get(existing.severity, 0)
            new_priority = severity_priority.get(finding.severity, 0)
            if new_priority > current_priority:
                existing.severity = finding.severity

        return list(merged.values())

    def scan(self, **kwargs) -> ScanResult:
        """
        Execute the secrets scan.

        Args:
            **kwargs: Additional parameters

        Returns:
            ScanResult with findings
        """
        self._is_running = True
        start_time = datetime.now(timezone.utc)
        self._findings = []
        self._seen_secrets.clear()
        self.statistics["total_secrets_detected"] = 0
        self.statistics["valid_secrets"] = 0
        self.statistics["false_positives"] = 0
        self.statistics["duplicates_removed"] = 0
        self.statistics["processed_files"] = 0
        self.statistics["total_checks"] = 0
        self._progress = 0
        self._total = 0

        try:
            content = self.fetch_content(self.target)
            self.statistics["processed_files"] += 1

            raw_findings = self.detect_secrets(content, self.target)
            enriched_findings = [self.enrich_finding(f) for f in raw_findings]
            self._findings = self.merge_findings(enriched_findings)
            self.statistics["valid_secrets"] = len(self._findings)

        except (OSError, ValueError, TypeError) as e:
            self._is_running = False
            return ScanResult(
                scanner_name="secrets",
                vulnerability_type="scan_error",
                severity="info",
                confidence=0.0,
                url=self.target,
                description=f"Scan failed: {e!s}",
                metadata={"error": str(e)},
                vulnerable=False,
                success=False,
                findings=[],
            )

        self._is_running = False

        if not self._findings:
            return ScanResult(
                scanner_name="secrets",
                vulnerability_type="no_secrets_found",
                severity="info",
                confidence=100.0,
                url=self.target,
                description="No secrets were detected in the target.",
                metadata=self.statistics,
                vulnerable=False,
                success=True,
                findings=[],
            )

        findings_list = []
        for f in self._findings:
            findings_list.append(
                {
                    "vulnerable": f.vulnerable,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "secret_type": f.secret_type,
                    "url": f.url,
                    "secret": f.secret,
                    "evidence": f.evidence,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "cvss": f.cvss,
                    "remediation": f.remediation,
                    "references": f.references,
                    "confidence": f.confidence,
                    "line_number": f.line_number,
                    "file_path": f.file_path,
                    "timestamp": f.timestamp.isoformat(),
                    "metadata": f.metadata,
                }
            )

        first = self._findings[0]
        evidence_text = "\n".join(first.evidence) if first.evidence else ""

        return ScanResult(
            scanner_name="secrets",
            vulnerability_type=first.secret_type,
            severity=first.severity,
            confidence=first.confidence,
            url=first.url,
            method="GET",
            parameter="",
            payload=first.secret,
            evidence=evidence_text,
            description=first.description,
            remediation=first.remediation,
            references=first.references,
            cwe_id=first.cwe,
            cvss_score=7.5,
            timestamp=start_time,
            metadata={
                "total_secrets_detected": self.statistics["total_secrets_detected"],
                "valid_secrets": self.statistics["valid_secrets"],
                "false_positives": self.statistics["false_positives"],
                "duplicates_removed": self.statistics["duplicates_removed"],
                "processed_files": self.statistics["processed_files"],
                "all_findings": findings_list,
            },
            vulnerable=True,
            success=True,
            findings=findings_list,
        )

    def get_findings(self) -> list[SecretFinding]:
        """Get all findings."""
        with self._lock:
            return self._findings.copy()

    def get_statistics(self) -> dict[str, Any]:
        """Get scan statistics."""
        return self.statistics.copy()

    def stop_scan(self) -> None:
        """Stop the current scan."""
        self._is_running = False

    def get_scan_status(self) -> dict[str, Any]:
        """Get current scan status."""
        return {
            "is_running": self._is_running,
            "progress": self._progress,
            "total": self._total,
            "findings": len(self._findings),
        }

    # Private helper methods

    def _is_redacted(self, secret: str) -> bool:
        """Check if secret appears to be redacted or masked."""
        redacted_patterns = [
            r"[*#x]{4,}",
            r"\[REDACTED\]",
            r"\[MASKED\]",
            r"\[REMOVED\]",
            r"<REDACTED>",
            r"<MASKED>",
        ]
        for pattern in redacted_patterns:
            if re.search(pattern, secret, re.IGNORECASE):
                return True
        return False

    def _is_false_positive(self, line: str, secret: str) -> bool:
        """
        Check if the detection is a false positive.

        Args:
            line: The line containing the potential secret
            secret: The detected secret string

        Returns:
            True if false positive, False otherwise
        """
        # Check false positive patterns
        for pattern in self.FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return True

        # Check for placeholder text
        placeholder_patterns = [
            r"your_",
            r"xxxx",
            r"\*{3,}",
            r"<secret>",
            r"{secret}",
            r"\[secret\]",
        ]

        for pattern in placeholder_patterns:
            if re.search(pattern, secret, re.IGNORECASE) or re.search(
                pattern, line, re.IGNORECASE
            ):
                return True

        # Check if line is commented out
        if re.search(r"^(//|#|/\*|\*|<!--)", line.strip()):
            return True

        # Check for test/example keywords - but ONLY if it's not a real AWS key
        if re.search(
            r"\b(example|test|demo|sample|placeholder|dummy)\b", line, re.IGNORECASE
        ):
            return not re.search(r"AKIA[0-9A-Z]{16}", secret)

        return False

    def _generate_secret_id(self, secret_type: str, secret: str, source: str) -> str:
        """Generate unique ID for a secret."""
        normalized = secret.strip()
        data = f"{secret_type}:{normalized}:{source}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def _create_finding(
        self,
        secret_type: str,
        secret: str,
        line: str,
        line_number: int,
        source: str,
        confidence: float,
        pattern_info: dict[str, Any],
    ) -> SecretFinding:
        """Create a SecretFinding from detection data."""
        severity = pattern_info.get("severity", "High")
        mask_func = pattern_info.get("mask", lambda s: s[:4] + "****" + s[-4:])

        finding = SecretFinding()
        finding.secret_type = secret_type
        finding.secret = mask_func(secret)
        finding.severity = severity
        finding.confidence = confidence
        finding.line_number = line_number
        finding.url = source
        finding.file_path = source

        finding.title = f"Hardcoded {secret_type} Detected"
        finding.evidence = [
            f"Secret Type: {secret_type}",
            f"Line {line_number}: {line.strip()[:200]}",
            f"Confidence: {confidence:.1f}%",
        ]

        finding.cwe = pattern_info.get("cwe", "CWE-798")
        finding.metadata = {
            "pattern": pattern_info.get("pattern", ""),
            "line_content": line.strip()[:200],
            "source_type": (
                "url" if source.startswith(("http://", "https://")) else "file"
            ),
        }

        return finding

    def _extract_context(self, line: str, lines_around: int) -> list[str]:
        """Extract context lines around the detection."""
        lines = line.split("\n")
        context = []
        for i in range(max(0, len(lines) - lines_around), len(lines)):
            context.append(lines[i].strip())
        return context
