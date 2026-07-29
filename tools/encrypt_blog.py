import os
import json
import base64
import yaml
import getpass

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

# ---------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)

BLOG_DIR = os.path.join(ROOT_DIR, "content", "blog")
OUTPUT_DIR = os.path.join(ROOT_DIR, "static", "encrypted")
PASSWORD_FILE = os.path.join(SCRIPT_DIR, "passwords.yaml")

PBKDF2_ITERATIONS = 200000
KEY_LENGTH = 32


# ---------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------

def load_passwords():
    if not os.path.exists(PASSWORD_FILE):
        return {}

    with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return data or {}


def save_passwords(passwords):
    passwords = dict(sorted(passwords.items()))

    with open(PASSWORD_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            passwords,
            f,
            sort_keys=False,
            allow_unicode=True,
        )


def split_front_matter(text):
    text = text.lstrip("\ufeff").lstrip()

    lines = text.splitlines()

    if not lines or lines[0].strip() != "---":
        raise ValueError("No front matter found.")

    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break

    if end is None:
        raise ValueError("Closing --- not found.")

    front = "\n".join(lines[1:end])
    body = "\n".join(lines[end + 1:])

    return yaml.safe_load(front), body


def encrypt(plaintext, password):
    salt = get_random_bytes(16)

    key = PBKDF2(
        password,
        salt,
        dkLen=KEY_LENGTH,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256,
    )

    cipher = AES.new(key, AES.MODE_GCM)

    ciphertext, tag = cipher.encrypt_and_digest(
        plaintext.encode("utf-8")
    )

    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(cipher.nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def ask_password(post_name):
    print(f"\nNo saved password found for '{post_name}'.")

    while True:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm Password: ")

        if password != confirm:
            print("❌ Passwords do not match.\n")
            continue

        if not password.strip():
            print("❌ Password cannot be empty.\n")
            continue

        return password


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------

def main():

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    passwords = load_passwords()

    for item in sorted(os.listdir(BLOG_DIR)):

        folder = os.path.join(BLOG_DIR, item)

        if not os.path.isdir(folder):
            continue

        md_file = os.path.join(folder, "index.md")

        if not os.path.exists(md_file):
            continue

        with open(md_file, "r", encoding="utf-8") as f:
            text = f.read()

        front, body = split_front_matter(text)

        if not front.get("protected", False):
            continue

        if "password" in front:
            raise ValueError(
                f"\n'{item}' still contains a 'password:' field.\n"
                "Remove it from the Markdown before encrypting."
            )

        # --------------------------------------------------------------
        # Get password
        # --------------------------------------------------------------

        if item in passwords:
            password = passwords[item]
            print(f"🔑 Using saved password for '{item}'.")

        else:
            password = ask_password(item)
            passwords[item] = password
            save_passwords(passwords)
            print(f"💾 Saved password for '{item}'.")

        # --------------------------------------------------------------
        # Encrypt
        # --------------------------------------------------------------

        encrypted = encrypt(body, password)

        encrypted["title"] = front["title"]
        encrypted["description"] = front.get("description", "")
        encrypted["date"] = str(front.get("date", ""))

        out = os.path.join(
            OUTPUT_DIR,
            item + ".json"
        )

        with open(out, "w", encoding="utf-8") as f:
            json.dump(
                encrypted,
                f,
                indent=4
            )

        print(f"✅ Encrypted '{item}'")

    print("\nDone.")


if __name__ == "__main__":
    main()