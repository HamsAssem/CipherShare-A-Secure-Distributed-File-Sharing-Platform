import os
import time
from utils.crypto_utils import derive_key_from_password, encrypt_file, decrypt_file, compute_sha256

def run_node():
    print("🔐 CipherShare Phase 3 Demo")
    password = input("Enter password: ")
    salt = os.urandom(16)
    key = derive_key_from_password(password, salt)

    src_file = "shared/sample.txt"
    enc_file = "shared/sample.txt.enc"
    meta_file = "shared/sample.txt.enc.meta"

    print("🔒 Encrypting...")
    iv_hex = encrypt_file(src_file, enc_file, key)
    hash_val = compute_sha256(src_file)

    with open(meta_file, "w") as f:
        f.write(f"{hash_val}\n{iv_hex}")

    print("✅ Encrypted and saved to:", enc_file)

    print("⬇️ Decrypting...")
    with open(meta_file, "r") as f:
        lines = f.readlines()
        hash_check = lines[0].strip()
        iv_check = lines[1].strip()

    dec_file = "received/sample.txt"
    os.makedirs(os.path.dirname(dec_file), exist_ok=True)  # ✅ Ensure 'received/' exists
    decrypt_file(enc_file, dec_file, key, iv_check)

    print("🔁 Verifying...")
    final_hash = compute_sha256(dec_file)
    if final_hash == hash_check:
        print("✅ Integrity Verified: Decrypted file matches original.")
    else:
        print("❌ Integrity Check Failed.")