# fileshare_peer.py
import socket
import threading
import os

SHARED_DIR = "shared"
os.makedirs(SHARED_DIR, exist_ok=True)

class FileSharePeer:
    def __init__(self, port):
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = '0.0.0.0'
        self.port = port
        self.shared_files = {}  # filename: filepath

        # Preload shared files
        for f in os.listdir(SHARED_DIR):
            self.shared_files[f] = os.path.join(SHARED_DIR, f)

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
            command = client_socket.recv(1024).decode().strip()

            if command == "LIST":
                files = "\n".join(self.shared_files.keys())
                client_socket.send(files.encode())

            elif command.startswith("DOWNLOAD"):
                _, filename = command.split(maxsplit=1)
                filepath = self.shared_files.get(filename)

                if filepath and os.path.exists(filepath):
                    client_socket.send(b"EXISTS")
                    with open(filepath, "rb") as f:
                        while chunk := f.read(1024):
                            client_socket.send(chunk)
                    client_socket.send(b"DONE")
                else:
                    client_socket.send(b"NOT_FOUND")

            else:
                client_socket.send(b"INVALID_COMMAND")

        except Exception as e:
            print(f"[-] Error with client {client_address}: {e}")
        finally:
            client_socket.close()


if __name__ == "__main__":
    port = int(input("Enter port for peer to listen on: "))
    peer = FileSharePeer(port)
    peer.start_peer()
