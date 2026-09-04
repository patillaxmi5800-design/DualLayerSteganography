import sqlite3

conn = sqlite3.connect("data.db")

username = input("Enter the username to make admin: ").strip()

cursor = conn.cursor()

cursor.execute(
    "UPDATE users SET is_admin = 1 WHERE username = ?",
    (username,)
)

if cursor.rowcount == 1:
    conn.commit()
    print(f"SUCCESS: {username} is now an admin.")
else:
    print(f"ERROR: User '{username}' was not found.")

conn.close()