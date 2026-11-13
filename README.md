# rsa-tools

Small Python scripts for RSA key generation, SHA-256 hashing, and file encrypt/decrypt.

| Script | Purpose |
|--------|---------|
| `generate_keys.py` | Create a 2048-bit RSA key pair (PEM) |
| `hash_file.py` | SHA-256 of a file, printed as hex |
| `encrypt_decrypt.py` | Encrypt or decrypt a file with those keys |

Encryption is hybrid: AES-256-GCM for the file, RSA-OAEP for the AES key.
RSA alone can only encrypt a small chunk (~200 bytes), so the file is encrypted with AES and RSA only wraps that AES key.

## Setup

```bash
cd rsa-tools
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Requires Python 3.10+. Only third-party package is `cryptography`.

## Usage

```bash
python generate_keys.py
# or: python generate_keys.py keys/
# or: python generate_keys.py keys/private.pem keys/public.pem

# fingerprint the file so we can confirm it wasn't changed (not encryption)
python hash_file.py "input/AMD image file.JPG"

python encrypt_decrypt.py encrypt "input/AMD image file.JPG" "output/AMD image file.JPG.enc" output/public.pem
python encrypt_decrypt.py decrypt "output/AMD image file.JPG.enc" "output/AMD image file.JPG.dec" output/private.pem
```

Round-trip check:

```bash
cmp "input/AMD image file.JPG" "output/AMD image file.JPG.dec" && echo OK
```

## Layout

```
input/    original input (e.g. AMD image file.JPG)
output/   keys and encrypted file (keys can live anywhere; pass the path)
```
