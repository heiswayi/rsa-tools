#!/usr/bin/env python3
"""
Encrypt / decrypt a file with the RSA key pair from generate_keys.py.

RSA alone can only handle a tiny payload (~190 bytes with OAEP + 2048-bit key),
so we use the usual hybrid approach:
  - AES-256-GCM encrypts the actual file (fast, works for any size)
  - RSA-OAEP encrypts the random AES key (so only the private key holder can open it)
"""

import os
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OUT_DIR = Path(__file__).resolve().parent / "output"
PRIVATE_KEY_PATH = OUT_DIR / "private.pem"
PUBLIC_KEY_PATH = OUT_DIR / "public.pem"

# encrypted file layout:
#   [4-byte big-endian length of RSA blob]
#   [RSA-encrypted AES key]
#   [12-byte AES-GCM nonce]
#   [ciphertext + 16-byte GCM tag]
NONCE_SIZE = 12
AES_KEY_SIZE = 32  # 256-bit


def load_public_key(path=PUBLIC_KEY_PATH):
    return serialization.load_pem_public_key(path.read_bytes())


def load_private_key(path=PRIVATE_KEY_PATH):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def encrypt_file(src, dst, public_key=None):
    # Hybrid encrypt: AES for the file body, RSA for the AES key.
    if public_key is None:
        public_key = load_public_key()

    plaintext = Path(src).read_bytes()
    aes_key = os.urandom(AES_KEY_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    # OAEP + SHA-256 is the modern padding choice for RSA encryption.
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    with open(dst, "wb") as f:
        f.write(struct.pack(">I", len(wrapped_key)))
        f.write(wrapped_key)
        f.write(nonce)
        f.write(ciphertext)


def decrypt_file(src, dst, private_key=None):
    # Reverse of encrypt_file: unwrap AES key with RSA, then decrypt the body.
    if private_key is None:
        private_key = load_private_key()

    data = Path(src).read_bytes()
    if len(data) < 4 + NONCE_SIZE:
        raise ValueError("encrypted file is too short / corrupt")

    key_len = struct.unpack(">I", data[:4])[0]
    offset = 4
    wrapped_key = data[offset : offset + key_len]
    offset += key_len
    nonce = data[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = data[offset:]

    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    Path(dst).write_bytes(plaintext)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("encrypt", "decrypt"):
        print(
            f"usage:\n"
            f"  {sys.argv[0]} encrypt <input> <output>\n"
            f"  {sys.argv[0]} decrypt <input> <output>",
            file=sys.stderr,
        )
        sys.exit(1)

    mode, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    if not Path(src).is_file():
        print(f"file not found: {src}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(Path(dst).parent, exist_ok=True)

    if mode == "encrypt":
        encrypt_file(src, dst)
        print(f"encrypted -> {dst}")
    else:
        decrypt_file(src, dst)
        print(f"decrypted -> {dst}")


if __name__ == "__main__":
    main()
