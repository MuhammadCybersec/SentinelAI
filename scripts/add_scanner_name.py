"""
Database migration script to add scanner_name column to findings table
Run this script once after updating the Finding model
"""

import sqlite3
import os
import sys
from pathlib import Path


def migrate_database():
    """Add scanner_name column to findings table if not exists"""

    # Database path - adjust if your database is elsewhere
    db_path = "data/sentinel.db"

    # Check if database exists
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        print(f"Current directory: {os.getcwd()}")
        return False

    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check if column already exists
        cursor.execute("PRAGMA table_info(findings)")
        columns = [column[1] for column in cursor.fetchall()]

        if "scanner_name" in columns:
            print("✅ scanner_name column already exists")
            conn.close()
            return True

        # Add the column
        print("📝 Adding scanner_name column to findings table...")
        cursor.execute("""
            ALTER TABLE findings 
            ADD COLUMN scanner_name VARCHAR(100) DEFAULT 'unknown'
        """)
        conn.commit()

        # Update existing records
        cursor.execute("""
            UPDATE findings 
            SET scanner_name = 'legacy' 
            WHERE scanner_name IS NULL
        """)
        conn.commit()

        print("✅ Migration completed successfully!")
        conn.close()
        return True

    except sqlite3.Error as e:
        print(f"❌ SQLite error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("SentinelAI Database Migration")
    print("Adding scanner_name to findings table")
    print("=" * 60)

    success = migrate_database()

    if success:
        print("\n✅ Migration successful! You can now use the scanner.")
        sys.exit(0)
    else:
        print("\n❌ Migration failed. Please check the error above.")
        sys.exit(1)
