import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# === Argon2 Password Hasher ===
argon2_hasher = PasswordHasher()

# Hash Password (Argon2)
def hash_password(password):
    hashed = argon2_hasher.hash(password)
    return hashed

# Verify Password (Argon2)
def verify_password(password, hashed_password):
    try:
        return argon2_hasher.verify(hashed_password, password)
    except VerifyMismatchError:
        return False

# Derive Key from Password using PBKDF2
def derive_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Key length for AES-256
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# AES Encryption
def encrypt_file(input_path, output_path, key):
    iv = os.urandom(16)  # Random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(128).padder()

    with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        outfile.write(iv)  # Save IV at beginning
        while chunk := infile.read(1024):
            padded_data = padder.update(chunk)
            outfile.write(encryptor.update(padded_data))
        outfile.write(encryptor.update(padder.finalize()))
        outfile.write(encryptor.finalize())

    return iv.hex()

# AES Decryption
def decrypt_file(input_path, output_path, key, iv_hex):
    iv = bytes.fromhex(iv_hex)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(128).unpadder()

    with open(input_path, 'rb') as infile:
        infile.read(16)
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

def generate_ecdh_keypair():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_key(private_key, peer_public_bytes):
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), peer_public_bytes)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file-transfer",
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key