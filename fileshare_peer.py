import socket

class FileSharePeer:
    def __init__(self, port):
        self.host = '0.0.0.0'
        self.port = port
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start_peer(self):
        self.peer_socket.bind((self.host, self.port))
        self.peer_socket.listen(5)
        print(f"[+] Peer started on port {self.port}, waiting for connections...")

        while True:
            client_socket, addr = self.peer_socket.accept()
            print(f"[+] Connection received from {addr}")
            client_socket.send(b"Hello from Peer!")
            client_socket.close()

if __name__ == '__main__':
    peer = FileSharePeer(port=5001)
    peer.start_peer()