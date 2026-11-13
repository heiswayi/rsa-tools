# rsa-tools

Small Python scripts for RSA key generation, SHA-256 hashing, and file encrypt/decrypt.

| Script | Purpose |
|--------|---------|
| `generate_keys.py` | Create a 2048-bit RSA key pair (PEM) |
| `hash_file.py` | SHA-256 of a file, printed as hex |
| `encrypt_decrypt.py` | Encrypt or decrypt a file with those keys |

Encryption is hybrid: AES-256-GCM for the file, RSA-OAEP for the AES key. Details in `HOWTO.md`.

## Setup

```bash
cd rsa-code-challenge
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Requires Python 3.10+. Only third-party package is `cryptography`.

## Usage

Place your input file under `data/`, then:

```bash
python generate_keys.py
# writes output/private.pem and output/public.pem

python hash_file.py data/sample.txt

python encrypt_decrypt.py encrypt data/sample.txt output/sample.txt.enc
python encrypt_decrypt.py decrypt output/sample.txt.enc output/sample.txt.dec
```

Round-trip check:

```bash
cmp data/sample.txt output/sample.txt.dec && echo OK
```

## Layout

```
data/      input files
output/   keys and encrypted/decrypted results
```

Keep private keys out of public repos. `output/` is gitignored aside from a placeholder.
