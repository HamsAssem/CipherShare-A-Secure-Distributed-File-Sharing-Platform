
# CipherShare - Secure P2P File Sharing

CipherShare is a secure, distributed file sharing system developed for the CSE451 course at Ain Shams University, Faculty of Engineering. It enables peer-to-peer (P2P) file transfers with a strong focus on security, credential management, and encryption.

This repository contains the finalized implementation of Phase 1, which establishes the foundation for secure and distributed file sharing. It includes a functional P2P network, basic file listing, and encrypted file transfer between peers.

## Features

### ✅ Phase 1: Basic P2P File Transfer
- Peer-to-peer network setup using sockets
- Encrypted file transfer functionality
- File listing and discovery mechanism
- Clean project structure with modular components

### ✅ Phase 2: User Authentication
- User registration and login system
- Argon2 password hashing (superior to PBKDF2/SHA-256)
- Encrypted credential storage using AES-256
- Session management

### ✅ Phase 3: File Security
- AES-256-CBC file encryption/decryption
- SHA-256 file integrity verification
- Secure key derivation (PBKDF2-HMAC-SHA256)
- Encrypted metadata storage

### ✅ Phase 4: Enhanced Features
- Client-side encrypted credential storage
- Basic command-line interface
- File transfer status indicators

## Technology Stack

| Component           | Technology Used               |
|---------------------|-------------------------------|
| Encryption          | AES-256-CBC, Argon2, PBKDF2   |
| Hashing             | SHA-256                       |
| Networking          | Python sockets                |
| Key Exchange        | ECDH (available but unused)   |
| User Authentication | Encrypted JSON storage        |

## Installation

1. **Prerequisites**:
   - Python 3.8+
   - Required packages: `pip install cryptography argon2-cffi`

2. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/ciphershare.git
   cd ciphershare
   ```

3. **Set up environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

## Usage

### Running a Peer Node
```bash
python fileshare_peer.py
Enter port for peer to listen on: 5000
```

### Using the Client
```bash
python fileshare_client.py
```

### Basic Commands:

1. **Register/Login**:
   ```
   [🔐] Choose LOGIN or REGISTER
   [👤] Enter username
   [🔑] Enter password
   ```

2. **File Operations**:

   * `LIST` - Show available files
   * `UPLOAD <path>` - Share a file
   * `DOWNLOAD <filename>` - Get a file
   * `EXIT` - Quit application

## Project Structure

```
ciphershare/
├── auth.py               # User authentication handlers
├── crypto_utils.py       # Cryptographic operations
├── fileshare_client.py   # Client implementation
├── fileshare_peer.py     # Peer node implementation
├── format_users.py       # User management utility
├── shared/               # Directory for shared files
├── received/             # Directory for downloaded files
├── users.json            # Encrypted user database (users are hashed in a machine language that is not human-readable)
├── shared_metadata.json  # File transfer metadata
└── salt.bin              # Cryptographic salt
```

## Security Implementation

| Feature            | Implementation Details             |
| ------------------ | ---------------------------------- |
| Password Hashing   | Argon2id with 3 iterations         |
| File Encryption    | AES-256-CBC with random IVs        |
| Key Derivation     | PBKDF2-HMAC-SHA256 (100,000 iters) |
| Data Integrity     | SHA-256 checksums                  |
| Credential Storage | AES-encrypted JSON                 |

## User Management

The user data is stored in **users.json** with hashed passwords in a format that is not human-readable for added security. However, for testing purposes, you can run `format_users.py` to generate a readable `users_formatted.txt` file, which lists the usernames to ensure users are registered in the system.

## Roadmap

* [ ] Implement ECDH key exchange
* [ ] Add file chunking for large files
* [ ] Develop peer discovery mechanism
* [ ] Create graphical user interface

