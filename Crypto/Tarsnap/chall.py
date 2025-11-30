#!/usr/bin/env python3
import io
import tarfile
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


def encrypt(content: bytes) -> bytes:
    key, nonce = os.urandom(32), os.urandom(16)
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    return cipher.encryptor().update(content)


print(
    "Welcome to my encrypted tar archive service !",
    "1. Add flag to encrypted archive",
    "2. Add file to encrypted archive",
    "3. Export encrypted archive",
    "4. Quit",
    sep="\n",
)

while True:
    fd = io.BytesIO()

    with tarfile.open(fileobj=fd, mode="w:gz") as tar:
        while choice := input("> "):
            match choice:
                case "1":
                    tar.add("flag.txt")

                case "2":
                    filename = input("Filename: ")
                    content = bytes.fromhex(input("Content: "))

                    info = tarfile.TarInfo(filename)
                    info.size = len(content)
                    tar.addfile(info, io.BytesIO(content))

                case "3":
                    tar.close()
                    content = fd.getvalue()
                    print("Encrypted content:", encrypt(content).hex())
                    break

                case "4":
                    print(
                        "Bye! I promise I'll give you the key to decrypt your"
                        "archives at some point... maybe..."
                    )
                    exit(0)

                case _:
                    continue
