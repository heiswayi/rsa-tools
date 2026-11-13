#!/usr/bin/env python3
"""Print the SHA-256 hash of a file as hex (no signing)."""

import hashlib
import sys
from pathlib import Path


def sha256_hex(path):
    # Read the file in chunks so we don't blow memory on big images.
    # SHA-256 always returns 32 bytes; we just show them as hex.
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <file>", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"file not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(sha256_hex(path))


if __name__ == "__main__":
    main()
