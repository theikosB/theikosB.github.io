import os
import json
import base64
import yaml

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

BLOG_DIR = "content/blog"
OUTPUT_DIR = "static/encrypted"

PBKDF2_ITERATIONS = 200000
KEY_LENGTH = 32


def split_front_matter(text):

    text = text.lstrip("\ufeff").lstrip()

    lines = text.splitlines()

    if lines[0].strip() != "---":
        raise ValueError("No front matter.")

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


def main():

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for item in os.listdir(BLOG_DIR):

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

        encrypted = encrypt(
            body,
            front["password"]
        )

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

        print(f"Encrypted {item}")


if __name__ == "__main__":
    main()