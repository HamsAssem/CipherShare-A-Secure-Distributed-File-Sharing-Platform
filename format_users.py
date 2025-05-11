import json

# Load users from the existing JSON file
with open("users.json", "r") as f:
    users = json.load(f)

# Write to a new file in the desired format
with open("users_formatted.txt", "w") as f:
    for username, password_hash in users.items():
        f.write(f"{username} - {password_hash}\n")
