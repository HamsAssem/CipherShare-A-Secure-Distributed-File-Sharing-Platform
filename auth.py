import json
import os
from crypto_utils import hash_password, verify_password

USERS_FILE = "users.json"

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

def register_user(username, password):
    users = load_users()
    if username in users:
        return False, "User already exists."
    hashed_pw = hash_password(password)
    users[username] = hashed_pw
    save_users(users)
    return True, "User registered."

def login_user(username, password):
    users = load_users()
    stored_hash = users.get(username)
    if not stored_hash:
        return False
    return verify_password(password, stored_hash)
