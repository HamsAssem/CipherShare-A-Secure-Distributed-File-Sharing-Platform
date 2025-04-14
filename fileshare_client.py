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

if __name__ == '__main__':
    client = FileShareClient('127.0.0.1', 5001)
    client.say_hello()