import json
import os
from base64 import b64decode
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

USERS_FILE = "users.json"
SALT_FILE = "salt.bin"

# Load salt
with open(SALT_FILE, "rb") as f:
    salt = f.read()

def derive_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def try_decrypt_users(key):
    try:
        with open(USERS_FILE, "r") as f:
            enc_data = b64decode(f.read().encode())
        iv, ciphertext = enc_data[:16], enc_data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        json_data = unpadder.update(padded) + unpadder.finalize()
        return json.loads(json_data.decode())
    except Exception:
        return None

# Retry until correct password entered
while True:
    master_password = input("🔐 Enter master password to format users: ")
    key = derive_key(master_password)
    users = try_decrypt_users(key)
    if users is not None:
        break
    print("❌ Incorrect password or decryption failed. Try again.\n")

# Save as formatted .txt file
with open("users_formatted.txt", "w") as f:
    for username, password_hash in users.items():
        f.write(f"{username} - {password_hash}\n")

print("✅ users_formatted.txt generated successfully.")
