import socket
import json
import getpass

SERVER = ("127.0.0.1", 5000)
SOURCE_IPS = {"1": "127.0.0.1", "2": "127.0.0.2"}


def send(f, obj):
    f.write(json.dumps(obj) + "\n")
    f.flush()


def recv(f):
    line = f.readline()
    if not line:
        raise ConnectionError("Server closed the connection")
    return json.loads(line)


def logged_in_menu(f):
    while True:
        print("\n1. Logout")
        print("2. View login log")
        choice = input("Choose: ").strip()

        if choice == "1":
            send(f, {"action": "logout"})
            print(recv(f)["msg"])
            return
        elif choice == "2":
            send(f, {"action": "viewlog"})
            print("\n" + recv(f)["msg"])
        else:
            print("Invalid choice.")


def login():
    print("\nSource IP:")
    print("1. 127.0.0.1")
    print("2. 127.0.0.2")
    ip_choice = input("Choose: ").strip()
    if ip_choice not in SOURCE_IPS:
        print("Invalid choice.")
        return

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((SOURCE_IPS[ip_choice], 0))  # pick which IP the server sees
        sock.connect(SERVER)
        f = sock.makefile("rw", encoding="utf-8")

        send(f, {"action": "login", "username": username, "password": password})
        reply = recv(f)
        print("\n" + reply["msg"])

        if reply["status"] == "SUCCESS":
            logged_in_menu(f)
    except ConnectionRefusedError:
        print("Cannot reach the server. Is server.py running?")
    except (ConnectionError, OSError) as e:
        print(f"Connection error: {e}")
    finally:
        sock.close()


def main():
    while True:
        print("\n1. Login")
        print("2. Exit")
        choice = input("Choose: ").strip()

        if choice == "1":
            login()
        elif choice == "2":
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
