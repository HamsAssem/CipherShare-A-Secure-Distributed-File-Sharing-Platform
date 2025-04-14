# CipherShare – Phase 1 (Initial Connection Test)

## Project Overview

CipherShare is a secure distributed file sharing system developed for the CSE451 course at Ain Shams University, Faculty of Engineering. It is designed to enable peer-to-peer (P2P) file transfers with a strong focus on security, including user authentication, credential management, file encryption, and integrity verification.

This repository contains the initial Phase 1 milestone, which is a minimal proof-of-concept demonstrating successful socket-based communication between a client and a peer. This step serves as the foundation for building the full system collaboratively.

---

## Phase 1 Objective

- Set up the basic P2P socket connection between two nodes.
- Ensure the client can successfully connect to the peer.
- Exchange a basic message ("Hello from Peer!") to verify communication.
- Establish version control and team collaboration structure on GitHub.

---

## File Structure

CipherShare-Phase1/
│
├── fileshare_peer.py         # Peer script that listens for incoming connections and sends a greeting
├── fileshare_client.py       # Client script that connects to the peer and receives a message
└── README.md                 # Project documentation

---

## Technologies Used

- Python 3.x
- TCP Socket Programming (socket module)
- Command-line interface (CLI)

---

## How to Run the Application

### Step 1: Start the Peer Node

In a terminal window, run the following command:
```bash
python fileshare_peer.py
```

Expected output:
```
[+] Peer started on port 5001, waiting for connections...
```

### Step 2: Start the Client

In a second terminal window, run:
```bash
python fileshare_client.py
```

Expected output:
```
[+] Connected to peer
[+] Received from peer: Hello from Peer!
```

This confirms that the connection between the client and peer is successfully established.

---

## Purpose of This Initial Commit

- Establish the base socket communication.
- Set up the folder and file structure on GitHub.
- Allow teammates to contribute in a structured, sequential manner.
- Prepare the codebase for future implementation of file transfer and encryption features.

---

## Next Steps (Planned for Future Phases)

- Implement file listing and downloading.
- Add secure password-based user authentication.
- Integrate file encryption (AES or ChaCha20).
- Introduce hashing (SHA-256) for integrity verification.
- Explore key derivation techniques (Argon2, PBKDF2).
- Design a simple distributed file discovery mechanism.

---

## Team Collaboration

This repository is managed by a group of 2–4 students working collaboratively using Git. This commit is the foundation, and subsequent commits will gradually implement the full functionality of CipherShare.

---

## Contact

For questions or collaboration:

Course: CSE451 – Computer and Network Security  
Instructor-provided templates and policies apply
