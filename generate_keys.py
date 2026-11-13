#!/usr/bin/env python3
"""Generate a 2048-bit RSA key pair and save them as PEM files."""

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUT_DIR = Path(__file__).resolve().parent / "output"
PRIVATE_KEY_PATH = OUT_DIR / "private.pem"
PUBLIC_KEY_PATH = OUT_DIR / "public.pem"
KEY_SIZE = 2048


def generate_rsa_keypair(bits=KEY_SIZE):
    # RSA needs two big primes. The library picks them and builds the key pair.
    # public_exponent=65537 is the usual safe default almost everyone uses.
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def save_keys(private_key, private_path=PRIVATE_KEY_PATH, public_path=PUBLIC_KEY_PATH):
    # PEM is just a text-friendly way to store keys (Base64 + headers).
    # Private key stays unencrypted here so the other scripts can load it easily.
    # In real systems you'd password-protect this file.
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    os.makedirs(private_path.parent, exist_ok=True)
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)


def main():
    private_key = generate_rsa_keypair()
    save_keys(private_key)
    print(f"private key -> {PRIVATE_KEY_PATH}")
    print(f"public key  -> {PUBLIC_KEY_PATH}")


if __name__ == "__main__":
    main()
