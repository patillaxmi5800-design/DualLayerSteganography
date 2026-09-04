import sqlite3
from pathlib import Path

db_path = Path("data.db")

conn = sqlite3.connect(db_path)

try:
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]

    if "is_admin" not in columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0"
        )
        conn.commit()
        print("SUCCESS: is_admin column added.")
    else:
        print("is_admin column already exists.")

finally:
    conn.close()