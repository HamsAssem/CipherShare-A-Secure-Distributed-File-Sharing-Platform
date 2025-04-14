import socket

class FileShareClient:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def say_hello(self):
        try:
            s = socket.socket()
            s.connect((self.ip, self.port))
            print("[+] Connected to peer")
            msg = s.recv(1024).decode()
            print("[+] Received from peer:", msg)
            s.close()
        except Exception as e:
            print("[-] Connection failed:", e)
# fileshare_client.py
import socket
import os

RECEIVED_DIR = "received"
os.makedirs(RECEIVED_DIR, exist_ok=True)

class FileShareClient:
    def __init__(self):
        self.username = None
        self.session_key = None

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


if __name__ == "__main__":
    client = FileShareClient()

    while True:
        cmd = input("Command (LIST, DOWNLOAD <file>, EXIT): ").strip()
        if cmd == "EXIT":
            break
        elif cmd.startswith("LIST"):
            ip = input("Peer IP: ")
            port = int(input("Peer Port: "))
            client.list_shared_files(ip, port)
        elif cmd.startswith("DOWNLOAD"):
            ip = input("Peer IP: ")
            port = int(input("Peer Port: "))
            filename = cmd.split(" ", 1)[1]
            client.download_file(ip, port, filename)
        else:
            print("[-] Unknown command.")

if __name__ == '__main__':
    client = FileShareClient('127.0.0.1', 5001)
    client.say_hello()
