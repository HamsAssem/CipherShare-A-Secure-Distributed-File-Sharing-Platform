import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_path, output_path, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        outfile.write(iv)
        while chunk := infile.read(1024):
            padded_data = padder.update(chunk)
            outfile.write(encryptor.update(padded_data))
        outfile.write(encryptor.update(padder.finalize()))
        outfile.write(encryptor.finalize())

    return iv.hex()

def decrypt_file(input_path, output_path, key, iv_hex):
    iv = bytes.fromhex(iv_hex)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()

    with open(input_path, 'rb') as infile:
        infile.seek(16)
        ciphertext = infile.read()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadded = unpadder.update(plaintext) + unpadder.finalize()

    with open(output_path, 'wb') as outfile:
        outfile.write(unpadded)

def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            sha256.update(chunk)
    return sha256.hexdigest()