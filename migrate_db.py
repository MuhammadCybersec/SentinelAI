"""
Database Migration Script for SentinelAI
Adds all missing columns to findings table
Run this script once after updating models
"""

import sqlite3
import os
import sys
from pathlib import Path


def get_db_path() -> str:
    """Get database path from environment or use default."""
    # Check if database exists in different locations
    possible_paths = [
        "data/sentinel.db",
        "sentinel.db",
        "app/data/sentinel.db",
        "database/sentinel.db",
    ]

    for path in possible_paths:
        if os.path.exists(path):
            print(f"📁 Found database at: {path}")
            return path

    # If no database found, use default
    print("⚠️  No existing database found. Using default path: data/sentinel.db")
    return "data/sentinel.db"


def get_existing_columns(cursor) -> list:
    """Get list of existing column names in findings table."""
    try:
        cursor.execute("PRAGMA table_info(findings)")
        return [column[1] for column in cursor.fetchall()]
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            print(
                "ℹ️  Findings table does not exist yet. Will be created by SQLAlchemy."
            )
            return []
        raise


def add_column(cursor, conn, column_name: str, column_type: str) -> bool:
    """Add a column to findings table if it doesn't exist."""
    try:
        cursor.execute(f"ALTER TABLE findings ADD COLUMN {column_name} {column_type}")
        conn.commit()
        print(f"   ✅ Added column: {column_name} ({column_type})")
        return True
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            print(f"   ℹ️  Column already exists: {column_name}")
            return False
        print(f"   ❌ Failed to add {column_name}: {e}")
        return False


def migrate_database() -> bool:
    """Main migration function."""
    print("=" * 70)
    print("  SentinelAI Database Migration")
    print("  Adding missing columns to findings table")
    print("=" * 70)

    db_path = get_db_path()

    # Ensure data directory exists
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
        print(f"📁 Created directory: {db_dir}")

    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        print(f"✅ Connected to database: {db_path}")

        # Get existing columns
        existing_columns = get_existing_columns(cursor)

        if not existing_columns:
            print("\n⚠️  Findings table not found. SQLAlchemy will create it.")
            print("   Please run the application first to create tables.")
            conn.close()
            return False

        print(f"\n📋 Existing columns ({len(existing_columns)}):")
        for col in existing_columns:
            print(f"   - {col}")

        # Define all required columns with their SQL types
        columns_to_add = {
            # Scanner Information
            "scanner_name": "VARCHAR(100) DEFAULT 'unknown'",
            "scanner_version": "VARCHAR(50) DEFAULT '1.0.0'",
            # Vulnerability Type
            "vulnerability_type": "VARCHAR(100) DEFAULT ''",
            # Request Information
            "method": "VARCHAR(10) DEFAULT 'GET'",
            # Response Information
            "status_code": "INTEGER DEFAULT 0",
            "response_time": "FLOAT DEFAULT 0.0",
            # Confidence & Verification
            "confidence": "FLOAT DEFAULT 0.0",
            "is_false_positive": "BOOLEAN DEFAULT 0",
            "verified": "BOOLEAN DEFAULT 0",
            # Tags & Metadata
            "tags": "TEXT DEFAULT ''",
            "metadata_json": "TEXT DEFAULT '{}'",
        }

        print("\n📝 Checking for missing columns...")
        added_count = 0
        skipped_count = 0

        for col_name, col_type in columns_to_add.items():
            if col_name in existing_columns:
                skipped_count += 1
                continue

            if add_column(cursor, conn, col_name, col_type):
                added_count += 1

        # Update existing records with default values
        if added_count > 0:
            print("\n🔄 Updating existing records with default values...")
            try:
                # Update null values to defaults
                cursor.execute(
                    "UPDATE findings SET scanner_name = 'legacy' WHERE scanner_name IS NULL OR scanner_name = ''"
                )
                cursor.execute(
                    "UPDATE findings SET scanner_version = '1.0.0' WHERE scanner_version IS NULL OR scanner_version = ''"
                )
                cursor.execute(
                    "UPDATE findings SET vulnerability_type = 'Unknown' WHERE vulnerability_type IS NULL OR vulnerability_type = ''"
                )
                cursor.execute(
                    "UPDATE findings SET method = 'GET' WHERE method IS NULL OR method = ''"
                )
                cursor.execute(
                    "UPDATE findings SET confidence = 0.0 WHERE confidence IS NULL"
                )
                cursor.execute("UPDATE findings SET tags = '' WHERE tags IS NULL")
                cursor.execute(
                    "UPDATE findings SET metadata_json = '{}' WHERE metadata_json IS NULL"
                )
                conn.commit()
                print("   ✅ Updated existing records")
            except Exception as e:
                print(f"   ⚠️  Could not update records: {e}")

        # Show final summary
        print("\n" + "=" * 70)
        print("  Migration Summary")
        print("=" * 70)
        print(f"  ✅ Columns added:   {added_count}")
        print(f"  ℹ️  Already exists:  {skipped_count}")

        # Show final column list
        cursor.execute("PRAGMA table_info(findings)")
        final_columns = [col[1] for col in cursor.fetchall()]
        print(f"\n  Total columns now: {len(final_columns)}")
        print("  Columns:", ", ".join(final_columns))

        conn.close()
        print("\n✅ Migration completed successfully!")
        return True

    except sqlite3.Error as e:
        print(f"\n❌ SQLite error: {e}")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return False


def create_database_if_not_exists():
    """Create database directory and initialize if needed."""
    db_path = get_db_path()
    db_dir = os.path.dirname(db_path)

    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    if not os.path.exists(db_path):
        print(f"📁 Creating new database at: {db_path}")
        try:
            conn = sqlite3.connect(db_path)
            conn.close()
            print("✅ Database created successfully!")
            print("ℹ️  Run the application to create tables.")
            return True
        except Exception as e:
            print(f"❌ Failed to create database: {e}")
            return False
    return True


def main():
    """Main entry point."""
    print("\n" + "=" * 70)
    print("  SentinelAI Database Migration Tool")
    print("  Version: 2.0.0")
    print("=" * 70 + "\n")

    # Ensure database exists
    if not create_database_if_not_exists():
        sys.exit(1)

    # Run migration
    success = migrate_database()

    if success:
        print("\n" + "=" * 70)
        print("  ✅ Migration Successful!")
        print("  You can now run the application.")
        print("=" * 70)
        sys.exit(0)
    else:
        print("\n" + "=" * 70)
        print("  ❌ Migration Failed!")
        print("  Please check the errors above.")
        print("=" * 70)
        sys.exit(1)


if __name__ == "__main__":
    main()
