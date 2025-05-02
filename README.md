# CipherShare – Phase 1: Basic P2P File Transfer & Unencrypted Sharing

## Project Overview

CipherShare is a secure, distributed file sharing system developed for the CSE451 course at Ain Shams University, Faculty of Engineering. It enables peer-to-peer (P2P) file transfers with a strong focus on security, credential management, and encryption. 

This repository contains the finalized implementation of **Phase 1**, which establishes the foundation for secure and distributed file sharing. It includes a functional P2P network, basic file listing, and unencrypted file transfer between peers.

---

## Phase 1 Objectives

- Implement a basic P2P network allowing peer-to-peer connections.
- Enable rudimentary file listing from the peer’s shared directory.
- Support unencrypted file transfer from one peer to another.
- Set up the initial Git-based project structure for team collaboration.

---

## Implemented Features

- Basic socket-based P2P network setup.
- Peer server that shares files from a local directory.
- Client application that connects to the peer, lists available files, and downloads selected files.
- Manual upload system (files placed in the `shared` folder).
- Directory management for received files.

---

## File Structure

```
CipherShare-Phase1/
│
├── fileshare_peer.py         # Runs the peer server, accepts LIST and DOWNLOAD requests
├── fileshare_client.py       # Client application to list and download files from peer
├── shared/                   # Folder for files to be shared by peer
├── received/                 # Folder where downloaded files are saved
└── README.md                 # Project documentation
```

---

## Technologies Used

- Python 3.x
- TCP Socket Programming (socket module)
- File I/O and CLI interaction

---

## How to Use

### 1. Start the Peer

Run this command in a terminal:
```bash
python fileshare_peer.py
```

The peer will listen on a port (default or entered by user) and serve files from the `shared` directory.

### 2. Place Files to Share

Copy any files you want to share into the `shared/` folder before clients connect.

### 3. Run the Client

In a second terminal:
```bash
python fileshare_client.py
```

You will be prompted for:
- The peer IP address (use `127.0.0.1` for local testing)
- The peer port
- The command to `LIST` files or `DOWNLOAD <filename>`

### 4. Check Downloaded Files

All downloaded files will be saved in the `received/` folder.

---

## Deliverables

- A working prototype of an unencrypted P2P file sharing system
- Rudimentary file discovery and listing
- Functional Git repository with clear structure and version history

---

## Documentation

- Phase 1 report (including implemented features, challenges, and future plans)
- Initial system architecture diagram
- Basic user manual (how to run the peer and client applications)

---

## Next Phase Preview

- Add secure user registration and login with Argon2 password hashing
- Enable encrypted file transfer (AES/ChaCha20)
- Introduce file integrity checks (SHA-256)
- Improve peer discovery and session management

---

## Team Notes

This project is developed in a team of 2–4 members using Git-based version control. This commit represents the completion of Phase 1. Future commits will build upon this version to implement advanced security and distributed functionality.
