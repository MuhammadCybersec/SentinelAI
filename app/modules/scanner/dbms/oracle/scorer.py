# app/modules/scanner/dbms/oracle/scorer.py

"""
Oracle-specific scoring and ranking logic.
"""


class OracleScorer:
    """Oracle-specific scoring for tables and columns."""

    def __init__(self):
        """Initialize Oracle scorer."""
        self.table_scores = {
            # High priority user tables
            "USERS": 100,
            "USER": 95,
            "ACCOUNTS": 90,
            "ACCOUNT": 85,
            "LOGIN": 80,
            "MEMBER": 75,
            "MEMBERS": 75,
            "AUTH": 70,
            "AUTHENTICATION": 70,
            "CREDENTIALS": 65,
            "CREDENTIAL": 60,
            "PROFILE": 55,
            "PROFILES": 55,
            "EMPLOYEE": 50,
            "EMPLOYEES": 50,
            "CUSTOMER": 45,
            "CUSTOMERS": 45,
            # System tables (lower priority)
            "ALL_TABLES": 10,
            "USER_TABLES": 10,
            "DBA_TABLES": 10,
            "TAB": 10,
            "DUAL": 5,
        }

        self.username_column_scores = {
            "USERNAME": 100,
            "USER": 95,
            "USER_ID": 90,
            "LOGIN": 85,
            "EMAIL": 80,
            "EMAIL_ADDRESS": 80,
            "ACCOUNT": 75,
            "ACCOUNT_NAME": 75,
            "NAME": 70,
            "FULL_NAME": 70,
            "UID": 65,
            "USR": 65,
        }

        self.password_column_scores = {
            "PASSWORD": 100,
            "PASS": 95,
            "PASSWD": 95,
            "PWD": 90,
            "HASH": 85,
            "PASSWORD_HASH": 85,
            "SECRET": 80,
            "PASSCODE": 75,
            "PIN": 70,
            "TOKEN": 65,
            "AUTH_TOKEN": 65,
        }

    def score_table(self, table_name: str) -> int:
        """
        Score a table name based on likelihood of being a user table.

        Args:
            table_name: Table name to score

        Returns:
            int: Score (higher is better)
        """
        table_upper = table_name.upper()

        # Check exact match
        if table_upper in self.table_scores:
            return self.table_scores[table_upper]

        # Check partial matches with bonus for exact format
        best_score = 0
        for key, score in self.table_scores.items():
            if key in table_upper:
                # Bonus if it starts with the key or is exactly the key
                if table_upper == key:
                    return score
                elif table_upper.startswith(key):
                    best_score = max(best_score, score + 10)
                else:
                    best_score = max(best_score, score // 2)

        # Bonus for plural or common endings
        if table_upper.endswith("S") and table_upper[:-1] in self.table_scores:
            best_score = max(best_score, self.table_scores[table_upper[:-1]] + 5)

        # Bonus for containing 'USER' or 'ACCOUNT'
        if "USER" in table_upper or "ACCOUNT" in table_upper:
            best_score = max(best_score, 60)

        return best_score

    def score_username_column(self, column_name: str) -> int:
        """
        Score a column for being a username column.

        Args:
            column_name: Column name to score

        Returns:
            int: Score (higher is better)
        """
        col_upper = column_name.upper()

        # Check exact match
        if col_upper in self.username_column_scores:
            return self.username_column_scores[col_upper]

        # Check partial matches
        best_score = 0
        for key, score in self.username_column_scores.items():
            if key in col_upper:
                if col_upper == key:
                    return score
                elif col_upper.startswith(key):
                    best_score = max(best_score, score + 5)
                else:
                    best_score = max(best_score, score // 2)

        return best_score

    def score_password_column(self, column_name: str) -> int:
        """
        Score a column for being a password column.

        Args:
            column_name: Column name to score

        Returns:
            int: Score (higher is better)
        """
        col_upper = column_name.upper()

        # Check exact match
        if col_upper in self.password_column_scores:
            return self.password_column_scores[col_upper]

        # Check partial matches
        best_score = 0
        for key, score in self.password_column_scores.items():
            if key in col_upper:
                if col_upper == key:
                    return score
                elif col_upper.startswith(key):
                    best_score = max(best_score, score + 5)
                else:
                    best_score = max(best_score, score // 2)

        return best_score

    def find_best_table(self, tables: list[str]) -> str | None:
        """
        Find the best table from a list based on scoring.

        Args:
            tables: List of table names

        Returns:
            Optional[str]: Best table name or None
        """
        if not tables:
            return None

        scored_tables = [(table, self.score_table(table)) for table in tables]
        scored_tables.sort(key=lambda x: x[1], reverse=True)

        # Return the highest scoring table if score > 0
        if scored_tables and scored_tables[0][1] > 0:
            return scored_tables[0][0]

        return None

    def find_best_username_column(self, columns: list[str]) -> str | None:
        """
        Find the best username column from a list.

        Args:
            columns: List of column names

        Returns:
            Optional[str]: Best username column or None
        """
        if not columns:
            return None

        scored_columns = [(col, self.score_username_column(col)) for col in columns]
        scored_columns.sort(key=lambda x: x[1], reverse=True)

        if scored_columns and scored_columns[0][1] > 0:
            return scored_columns[0][0]

        return None

    def find_best_password_column(self, columns: list[str]) -> str | None:
        """
        Find the best password column from a list.

        Args:
            columns: List of column names

        Returns:
            Optional[str]: Best password column or None
        """
        if not columns:
            return None

        scored_columns = [(col, self.score_password_column(col)) for col in columns]
        scored_columns.sort(key=lambda x: x[1], reverse=True)

        if scored_columns and scored_columns[0][1] > 0:
            return scored_columns[0][0]

        return None

    def find_administrator(
        self, credentials: list[dict[str, str]]
    ) -> dict[str, str] | None:
        """
        Find administrator credentials from a list.

        Args:
            credentials: List of {username, password} dicts

        Returns:
            Optional[Dict]: Administrator credentials or None
        """
        admin_patterns = ["ADMINISTRATOR", "ADMIN", "ROOT", "SUPERUSER", "SYSADMIN"]

        for cred in credentials:
            username = cred.get("username", "").upper()
            if any(pattern in username for pattern in admin_patterns):
                return cred

        return None
