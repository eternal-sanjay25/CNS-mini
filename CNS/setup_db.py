import sqlite3
import hashlib
import os

DB = "auth.db"

# username -> password (only place the passwords exist)
ACCOUNTS = {
    "admin": "admin123",
    "user": "user123",
}

conn = sqlite3.connect(DB)
conn.execute("DROP TABLE IF EXISTS users")
conn.execute("DROP TABLE IF EXISTS login_log")
conn.execute(
    "CREATE TABLE users (username TEXT PRIMARY KEY, salt TEXT, password_hash TEXT)"
)
conn.execute(
    "CREATE TABLE login_log (id INTEGER PRIMARY KEY AUTOINCREMENT, "
    "time TEXT, username TEXT, ip TEXT, status TEXT)"
)

for name, pw in ACCOUNTS.items():
    salt = os.urandom(16)
    h = hashlib.sha256(salt + pw.encode()).hexdigest()
    conn.execute("INSERT INTO users VALUES (?, ?, ?)", (name, salt.hex(), h))

conn.commit()
conn.close()
print("Database created: auth.db")
