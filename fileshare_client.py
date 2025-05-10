# fileshare_client.py
import socket
import os
from auth import register_user, login_user

# ==== Step 1: User Authentication ====
print("Welcome to CipherShare!")
while True:
    action = input("Do you want to LOGIN or REGISTER? ").strip().upper()
    username = input("Username: ")
    password = input("Password: ")

    if action == "REGISTER":
        success, msg = register_user(username, password)
        print(msg)
        if success:
            break
    elif action == "LOGIN":
        if login_user(username, password):
            print("[+] Login successful!")
            break
        else:
            print("[-] Invalid username or password.")
    else:
        print("[-] Invalid action.")

# ==== Step 2: Directory for Received Files ====
RECEIVED_DIR = "received"
os.makedirs(RECEIVED_DIR, exist_ok=True)

# ==== Step 3: Client Class ====
class FileShareClient:
    def __init__(self):
        self.username = username  # Store current user
        self.session_key = None   # Placeholder for future use

    def connect_to_peer(self, ip, port):
        try:
            sock = socket.socket()
            sock.connect((ip, port))
            return sock
        except Exception as e:
            print(f"[-] Could not connect to peer {ip}:{port} – {e}")
            return None

    def list_shared_files(self, ip, port):
        sock = self.connect_to_peer(ip, port)
        if not sock:
            return
        sock.send(b"LIST")
        data = sock.recv(4096).decode()
        print("[+] Files shared on peer:\n" + data)
        sock.close()

    def download_file(self, ip, port, filename):
        sock = self.connect_to_peer(ip, port)
        if not sock:
            return

        sock.send(f"DOWNLOAD {filename}".encode())
        status = sock.recv(1024)

        if status == b"EXISTS":
            print(f"[+] Downloading {filename}...")
            with open(os.path.join(RECEIVED_DIR, filename), "wb") as f:
                while True:
                    chunk = sock.recv(1024)
                    if chunk.endswith(b"DONE"):
                        f.write(chunk[:-4])
                        break
                    f.write(chunk)
            print("[+] File downloaded.")
        elif status == b"NOT_FOUND":
            print("[-] File not found.")
        else:
            print("[-] Invalid response.")
        sock.close()

    def upload_file(self, filepath):
        print("[*] Upload is handled manually by placing files in the 'shared' folder of the peer.")
        print("[*] This feature will be automated in Phase 3.")

# ==== Step 4: Interactive Client Menu ====
if __name__ == "__main__":
    client = FileShareClient()

    while True:
        cmd = input("Command (LIST, DOWNLOAD <file>, EXIT): ").strip()
        if cmd == "EXIT":
            break
        elif cmd.startswith("LIST"):
            ip = input("Peer IP: ").strip()
            try:
                port = int(input("Peer Port: ").strip())
            except ValueError:
                print("[-] Invalid port number. Please enter a valid number like 9000.")
                continue
            client.list_shared_files(ip, port)

        elif cmd.startswith("DOWNLOAD"):
            ip = input("Peer IP: ").strip()
            try:
                port = int(input("Peer Port: ").strip())
            except ValueError:
                print("[-] Invalid port number. Please enter a valid number like 9000.")
                continue
            parts = cmd.split(" ", 1)
            if len(parts) < 2:
                print("[-] Missing filename.")
                continue
            filename = parts[1]
            client.download_file(ip, port, filename)

        else:
            print("[-] Unknown command.")
