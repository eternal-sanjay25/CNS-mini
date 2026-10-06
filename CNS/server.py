import socket
import threading
import sqlite3
import hashlib
import hmac
import json
import time
from datetime import datetime

HOST, PORT = "127.0.0.1", 5000
DB = "auth.db"

WINDOW = 60       # seconds in which failures are counted
WARN_AT = 3       # failures that trigger a warning
BLOCK_AT = 5      # failures that trigger an IP block
BLOCK_SECS = 60   # block duration

failures = {}       # ip -> list of failure timestamps
blocked_until = {}  # ip -> unblock time
lock = threading.Lock()


def db_exec(sql, args=()):
    conn = sqlite3.connect(DB)
    try:
        rows = conn.execute(sql, args).fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def log(username, ip, status):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db_exec(
        "INSERT INTO login_log (time, username, ip, status) VALUES (?, ?, ?, ?)",
        (now, username, ip, status),
    )
    print(f"{now[11:]}   {username:<10} {ip:<12} {status}")


def check_password(username, password):
    rows = db_exec(
        "SELECT salt, password_hash FROM users WHERE username=?", (username,)
    )
    if not rows:
        return False
    salt, stored = rows[0]
    calc = hashlib.sha256(bytes.fromhex(salt) + password.encode()).hexdigest()
    return hmac.compare_digest(calc, stored)


def handle_login(ip, username, password):
    """Returns (status, message, success)."""
    with lock:
        now = time.time()

        # already blocked?
        if blocked_until.get(ip, 0) > now:
            remaining = int(blocked_until[ip] - now) + 1
            log(username, ip, "BLOCKED")
            return ("BLOCKED",
                    f"IP temporarily blocked. Try again in {remaining}s.", False)

        # correct credentials
        if check_password(username, password):
            failures[ip] = []
            log(username, ip, "SUCCESS")
            return ("SUCCESS", "Authentication Successful", True)

        # wrong credentials
        recent = [t for t in failures.get(ip, []) if now - t < WINDOW]
        recent.append(now)
        failures[ip] = recent
        n = len(recent)

        if n >= BLOCK_AT:
            blocked_until[ip] = now + BLOCK_SECS
            failures[ip] = []
            print("\n" + "=" * 44)
            print("  SECURITY ALERT")
            print("  Possible brute-force activity detected.")
            print(f"  Username: {username}")
            print(f"  IP: {ip}")
            print(f"  Failed Attempts: {n}")
            print(f"  Action: IP blocked for {BLOCK_SECS} seconds")
            print("=" * 44 + "\n")
            log(username, ip, "BLOCKED")
            return ("BLOCKED",
                    f"IP temporarily blocked for {BLOCK_SECS} seconds.", False)

        if n >= WARN_AT:
            log(username, ip, "WARNING")
            return ("WARNING",
                    f"Warning: {n} failed attempts. Suspicious activity noticed. "
                    f"{BLOCK_AT} failures will block your IP.", False)

        log(username, ip, "FAILED")
        return ("FAILED", "Invalid Username/Password", False)


def get_log_table():
    rows = db_exec(
        "SELECT time, username, ip, status FROM login_log ORDER BY id DESC LIMIT 20"
    )
    lines = [f"{'TIME':<10} {'USER':<10} {'IP':<12} STATUS", "-" * 46]
    for t, u, ip, s in reversed(rows):
        lines.append(f"{t[11:]:<10} {u:<10} {ip:<12} {s}")
    return "\n".join(lines)


def send(f, obj):
    f.write(json.dumps(obj) + "\n")
    f.flush()


def handle_client(conn, addr):
    ip = addr[0]
    session_user = None
    f = conn.makefile("rw", encoding="utf-8")
    try:
        for line in f:
            try:
                req = json.loads(line)
            except ValueError:
                continue
            action = req.get("action")

            if action == "login":
                username = str(req.get("username", ""))
                password = str(req.get("password", ""))
                status, msg, ok = handle_login(ip, username, password)
                if ok:
                    session_user = username
                send(f, {"status": status, "msg": msg})

            elif action == "viewlog":
                if session_user == "admin":
                    send(f, {"status": "OK", "msg": get_log_table()})
                else:
                    send(f, {"status": "DENIED", "msg": "Access denied."})

            elif action == "logout":
                if session_user:
                    log(session_user, ip, "LOGOUT")
                    session_user = None
                send(f, {"status": "OK", "msg": "Logged out."})
                break
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            f.close()
        except OSError:
            pass
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen()
    print(f"Server listening on {HOST}:{PORT}\n")
    print(f"{'TIME':<10} {'USER':<10} {'IP':<12} STATUS")
    print("-" * 46)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
