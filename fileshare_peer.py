import socket
import threading
import os
from crypto_utils import hash_password, verify_password
import json

SHARED_DIR = "shared"
os.makedirs(SHARED_DIR, exist_ok=True)

USERS_FILE = "users_peer.json"
METADATA_FILE = "shared_metadata.json"  # store IV and hash


def recv_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.strip().decode()


class FileSharePeer:
    def __init__(self, port):
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = '0.0.0.0'
        self.port = port
        self.users = self.load_users()
        self.shared_files = self.load_metadata()

    def load_users(self):
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        return {}

    def save_users(self):
        with open(USERS_FILE, 'w') as f:
            json.dump(self.users, f)

    def load_metadata(self):
        if os.path.exists(METADATA_FILE):
            with open(METADATA_FILE, 'r') as f:
                return json.load(f)
        return {}

    def save_metadata(self):
        with open(METADATA_FILE, 'w') as f:
            json.dump(self.shared_files, f)

    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5)
        print(f"[+] Peer listening on {self.port}...")

        while True:
            client_socket, addr = self.peer_socket.accept()
            threading.Thread(target=self.handle_client_connection, args=(client_socket, addr)).start()

    def handle_client_connection(self, client_socket, client_address):
        print(f"[+] Connected by {client_address}")
        try:
            command = client_socket.recv(1024)
            if not command:
                print(f"[-] Empty command received from {client_address}")
                return
            command = command.decode().strip()

            if command == "LIST":
                # Clean up metadata from deleted files
                for filename in list(self.shared_files.keys()):
                    if not os.path.exists(self.shared_files[filename]["path"]):
                        del self.shared_files[filename]
                self.save_metadata()

                # Send only valid files
                valid_files = []
                for filename, meta in self.shared_files.items():
                    if os.path.exists(meta["path"]):
                        valid_files.append(filename)
                files = "\n".join(valid_files)
                client_socket.send(files.encode())

            elif command.startswith("REGISTER"):
                _, username, password = command.split(maxsplit=2)
                if username in self.users:
                    client_socket.send(b"USER_EXISTS")
                else:
                    hashed_password = hash_password(password)
                    self.users[username] = {"password_hash": hashed_password}
                    self.save_users()
                    client_socket.send(b"REGISTERED")

            elif command.startswith("LOGIN"):
                _, username, password = command.split(maxsplit=2)
                if username not in self.users:
                    client_socket.send(b"USER_NOT_FOUND")
                else:
                    stored_hash = self.users[username]["password_hash"]
                    if verify_password(password, stored_hash):
                        client_socket.send(b"LOGIN_SUCCESS")
                    else:
                        client_socket.send(b"INVALID_PASSWORD")

            elif command.startswith("UPLOAD"):
                _, filename = command.split(maxsplit=1)
                filepath = os.path.join(SHARED_DIR, filename + ".enc")

                iv_hex = client_socket.recv(1024).strip().decode()
                file_hash = recv_line(client_socket)

                with open(filepath, "wb") as f:
                    while True:
                        chunk = client_socket.recv(1024)
                        if not chunk:
                            break
                        f.write(chunk)

                self.shared_files[filename] = {
                    "path": filepath,
                    "iv": iv_hex,
                    "hash": file_hash
                }
                self.save_metadata()
                client_socket.send(b"UPLOAD_SUCCESS")


            elif command.startswith("DOWNLOAD"):

                try:

                    parts = command.split(maxsplit=1)

                    if len(parts) != 2:
                        client_socket.send(b"INVALID_COMMAND")

                        return

                    filename = parts[1].strip()

                    print(f"[DEBUG] DOWNLOAD requested for: {filename}")

                    print(f"[DEBUG] Available files: {list(self.shared_files.keys())}")

                    meta = self.shared_files.get(filename)

                    if meta and os.path.exists(meta["path"]):

                        client_socket.send(b"EXISTS\n")
                        client_socket.send((meta["iv"] + "\n").encode())
                        client_socket.send((meta["hash"] + "\n").encode())

                        with open(meta["path"], "rb") as f:

                            while chunk := f.read(1024):
                                client_socket.send(chunk)

                    else:

                        client_socket.send(b"NOT_FOUND")

                except Exception as e:

                    print(f"[ERROR] Failed to process DOWNLOAD: {e}")

                    client_socket.send(b"INVALID_COMMAND")

        finally:
            client_socket.close()


if __name__ == "__main__":
    port = int(input("Enter port for peer to listen on: "))
    peer = FileSharePeer(port)
    peer.start_peer()
