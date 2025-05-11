import json
import os
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from crypto_utils import hash_password, verify_password

USERS_FILE = "users.json"
SALT_FILE = "salt.bin"

# Load or create a salt for PBKDF2
if os.path.exists(SALT_FILE):
    with open(SALT_FILE, "rb") as f:
        salt = f.read()
else:
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)

# --- KEY HANDLING BLOCK ---
def derive_key(master_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password.encode())

def try_decrypt_with_key(key):
    if not os.path.exists(USERS_FILE):
        return True  # Nothing to decrypt yet = OK

    try:
        with open(USERS_FILE, "r") as f:
            encrypted_json = f.read()
        raw = b64decode(encrypted_json.encode())
        iv, ciphertext = raw[:16], raw[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        _ = unpadder.update(padded) + unpadder.finalize()
        return True
    except Exception:
        return False

# Loop until valid master password is entered
while True:
    master_password = input("🔐 Enter master password: ")
    key = derive_key(master_password)
    if try_decrypt_with_key(key):
        break
    print("❌ Incorrect master password. Please try again.\n")

# --- ENCRYPTION FUNCTIONS ---
def encrypt_data(data_str):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data_str.encode()) + padder.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return b64encode(iv + encrypted).decode()

def decrypt_data(enc_str):
    raw = b64decode(enc_str.encode())
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

# --- USER OPERATIONS ---
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        encrypted_json = f.read()
    decrypted = decrypt_data(encrypted_json)
    return json.loads(decrypted)

def save_users(users):
    json_str = json.dumps(users)
    encrypted = encrypt_data(json_str)
    with open(USERS_FILE, "w") as f:
        f.write(encrypted)

def register_user(username, password):
    users = load_users()
    if username in users:
        return False, "User already exists."
    users[username] = hash_password(password)
    save_users(users)
    return True, "User registered."

def login_user(username, password):
    users = load_users()
    stored_hash = users.get(username)
    if not stored_hash:
        return False
    return verify_password(password, stored_hash)
