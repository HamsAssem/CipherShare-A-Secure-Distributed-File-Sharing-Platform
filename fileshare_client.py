import socket
import os
from auth import register_user, login_user

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

RECEIVED_DIR = "received"
os.makedirs(RECEIVED_DIR, exist_ok=True)

class FileShareClient:
    def __init__(self):
        self.username = username
        self.session_key = None

    def connect_to_peer(self, ip, port):
        try:
            sock = socket.socket()
            sock.settimeout(5)
            sock.connect((ip, port))
            return sock
        except Exception as e:
            print(f"[-] Could not connect to peer {ip}:{port} – {e}")
            return None

    def recv_line(self, sock):
        data = b''
        while not data.endswith(b'\n'):
            chunk = sock.recv(1)
            if not chunk:
                break
            data += chunk
        return data.strip().decode()

    def list_shared_files(self, ip, port):
        sock = self.connect_to_peer(ip, port)
        if not sock:
            return
        sock.send(b"LIST")
        try:
            data = sock.recv(4096).decode()
            print("[+] Files shared on peer:\n" + data)
        except Exception as e:
            print("[-] Failed to receive file list:", e)
        sock.close()

    def download_file(self, ip, port, filename):
        import crypto_utils

        sock = self.connect_to_peer(ip, port)
        if not sock:
            return

        sock.send(f"DOWNLOAD {filename}".encode())
        status = self.recv_line(sock)
        if status == "EXISTS":
            iv_hex = self.recv_line(sock)
            expected_hash = self.recv_line(sock)

            encrypted_path = os.path.join(RECEIVED_DIR, filename + ".enc")
            with open(encrypted_path, "wb") as f:
                while True:
                    try:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        f.write(chunk)
                    except socket.timeout:
                        print("[-] Timeout during file download.")
                        break

            salt = b'static_salt_demo'
            key = crypto_utils.derive_key_from_password(password, salt)

            decrypted_path = os.path.join(RECEIVED_DIR, filename)
            crypto_utils.decrypt_file(encrypted_path, decrypted_path, key, iv_hex)
            os.remove(encrypted_path)

            actual_hash = crypto_utils.compute_sha256(decrypted_path)
            if actual_hash == expected_hash:
                print("[+] File integrity verified.")
            else:
                print("[-] Integrity check failed.")
        elif status == b"NOT_FOUND":
            print("[-] File not found.")
        else:
            print(f"[-] Invalid response: {status}")
        sock.close()

    def upload_file(self, filepath):
        import crypto_utils

        if not os.path.exists(filepath):
            print("[-] File does not exist.")
            return

        ip = input("Peer IP: ").strip()
        try:
            port = int(input("Peer Port: ").strip())
        except ValueError:
            print("[-] Invalid port number.")
            return

        sock = self.connect_to_peer(ip, port)
        if not sock:
            return

        filename = os.path.basename(filepath)
        sock.send(f"UPLOAD {filename}".encode())

        salt = b'static_salt_demo'
        key = crypto_utils.derive_key_from_password(password, salt)

        encrypted_path = filepath + ".enc"
        iv_hex = crypto_utils.encrypt_file(filepath, encrypted_path, key)
        file_hash = crypto_utils.compute_sha256(filepath)

        sock.send((iv_hex + "\n").encode())
        sock.send((file_hash + "\n").encode())

        with open(encrypted_path, "rb") as f:
            while chunk := f.read(1024):
                sock.send(chunk)


        os.remove(encrypted_path)
        print("[+] Encrypted file uploaded.")
        sock.close()

if __name__ == "__main__":
    client = FileShareClient()

    while True:
        cmd = input("Command (LIST, DOWNLOAD <file>, UPLOAD <path>, EXIT): ").strip()
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

        elif cmd.startswith("UPLOAD"):
            parts = cmd.split(" ", 1)
            if len(parts) < 2:
                print("[-] Missing file path.")
                continue
            filepath = parts[1]
            client.upload_file(filepath)

        else:
            print("[-] Unknown command.")
