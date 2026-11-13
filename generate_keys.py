#!/usr/bin/env python3
"""Generate a 2048-bit RSA key pair and save them as PEM files."""

import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_OUT_DIR = Path(__file__).resolve().parent / "output"
KEY_SIZE = 2048


def generate_rsa_keypair(bits=KEY_SIZE):
    # RSA needs two big primes. The library picks them and builds the key pair.
    # public_exponent=65537 is the usual safe default almost everyone uses.
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def save_keys(private_key, private_path, public_path):
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

    os.makedirs(Path(private_path).parent, exist_ok=True)
    os.makedirs(Path(public_path).parent, exist_ok=True)
    Path(private_path).write_bytes(private_bytes)
    Path(public_path).write_bytes(public_bytes)


def main():
    # usage:
    #   generate_keys.py
    #   generate_keys.py <outdir>
    #   generate_keys.py <private.pem> <public.pem>
    if len(sys.argv) == 1:
        out_dir = DEFAULT_OUT_DIR
        private_path = out_dir / "private.pem"
        public_path = out_dir / "public.pem"
    elif len(sys.argv) == 2:
        out_dir = Path(sys.argv[1])
        private_path = out_dir / "private.pem"
        public_path = out_dir / "public.pem"
    elif len(sys.argv) == 3:
        private_path = Path(sys.argv[1])
        public_path = Path(sys.argv[2])
    else:
        print(
            f"usage:\n"
            f"  {sys.argv[0]}\n"
            f"  {sys.argv[0]} <outdir>\n"
            f"  {sys.argv[0]} <private.pem> <public.pem>",
            file=sys.stderr,
        )
        sys.exit(1)

    private_key = generate_rsa_keypair()
    save_keys(private_key, private_path, public_path)
    print(f"private key -> {private_path}")
    print(f"public key  -> {public_path}")


if __name__ == "__main__":
    main()
