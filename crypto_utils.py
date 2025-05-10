import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

# Hash Password and Verification Functions
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_bytes(16)  # Generate new salt if none is provided
    hashed_password = hashlib.sha256(password.encode('utf-8') + salt).hexdigest()
    return hashed_password, salt

def verify_password(password, hashed_password, salt):
    return hashed_password == hashlib.sha256(password.encode('utf-8') + salt).hexdigest()

# Derive Key from Password
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for AES-256
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encryption Function
def encrypt_file(input_path, output_path, key):
    iv = os.urandom(16)  # Generate a random IV for each file
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        outfile.write(iv)  # Write IV at the beginning of the file
        while chunk := infile.read(1024):
            padded_data = padder.update(chunk)
            outfile.write(encryptor.update(padded_data))
        outfile.write(encryptor.update(padder.finalize()))
        outfile.write(encryptor.finalize())  # Finalize encryption

    return iv.hex()  # Return the IV in hexadecimal format

# Decryption Function
def decrypt_file(input_path, output_path, key, iv_hex):
    iv = bytes.fromhex(iv_hex)  # Convert the IV back from hexadecimal
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()

    with open(input_path, 'rb') as infile:
        infile.seek(16)  # Skip the IV in the file
        ciphertext = infile.read()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()

    with open(output_path, 'wb') as outfile:
        outfile.write(unpadded)

# Compute SHA256 Hash of a File
def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()
