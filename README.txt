# CipherShare Phase 3 - Full VSCode Project

## Features
- Encrypts file with AES-256 CBC
- Derives key from password using PBKDF2
- Stores SHA-256 hash + IV in .meta file
- Verifies integrity after decrypting

## How to Run
1. Open in VSCode
2. Run: `python main.py`
3. Enter password when prompted
4. Encrypted file and meta saved to `shared/`, decrypted copy in `received/`