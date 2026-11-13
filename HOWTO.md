# How it works

Background on the scripts, the crypto they use, and why the project is structured this way.

## `generate_keys.py` — RSA key pair

Creates a public/private RSA key pair and writes them as PEM files under `output/`.

**RSA in short**

- Private key decrypts. Keep it secret.
- Public key encrypts. Safe to share.
- The two keys are linked mathematically. With a large enough key size, recovering the private key from the public key is not practical.

**2048-bit keys** are a common baseline. 1024-bit is outdated; 3072/4096 are stronger but slower.

**Where RSA shows up today:** TLS certificates, SSH, code signing, S/MIME email, wrapping small secrets (session keys, AES keys).

---

## `hash_file.py` — SHA-256

Reads a file and prints a 64-character hex digest. No keys, no signing.

**Hashing in short**

- Same file → same hash.
- Small change → completely different hash.
- One-way: you cannot turn a hash back into the file.
- Not encryption. There is nothing to “decrypt.”

**SHA-256** is widely used and available in Python’s stdlib (`hashlib`). The script hashes in chunks so large files do not need to sit fully in memory.

**Where hashes show up today:** download checksums, git object IDs, integrity checks, password storage (with salt + a proper KDF), blockchains.

---

## `encrypt_decrypt.py` — file encrypt / decrypt

### RSA size limit

A 2048-bit RSA key can only encrypt a small payload after padding (roughly under 200 bytes with OAEP). Most real files are larger than that. Encrypting a whole file with raw RSA (or naively chunking it) is the wrong tool.

### Hybrid encryption (what we use)

1. Generate a random AES-256 key and nonce.
2. Encrypt the file with **AES-GCM** (fast, any size, authenticated).
3. Encrypt the AES key with the **RSA public key** (OAEP + SHA-256).
4. Store one blob: wrapped key + nonce + ciphertext.

Decrypt unwraps the AES key with the private key, then decrypts the file body.

Same idea as TLS, OpenPGP, age, and cloud “envelope encryption”: asymmetric crypto protects a small key; symmetric crypto protects the bulk data.

### On-disk format

```
[4 bytes] length of RSA-wrapped AES key (big-endian)
[N bytes] RSA-OAEP ciphertext of the AES key
[12 bytes] AES-GCM nonce
[rest]    ciphertext + GCM auth tag
```

---

## Design choices

**Plain scripts, one job each.** Easy to open, run, and follow. No framework or package layout for something this small.

**Stdlib when it exists.** Hashing uses `hashlib`. No extra package for that.

**One dependency: `cryptography`.** Python’s stdlib does not include high-level RSA/AES APIs the way some other languages do. This library fills that gap without pulling in a large stack.

**Hybrid RSA + AES.** Matches how file encryption is done in practice and avoids RSA’s payload-size limit.

**venv + `requirements.txt`.** Isolated, reproducible install.

**Code style**

- Functions over classes — enough for this size.
- `sys.argv` for CLI — obvious usage, few imports.
- PEM on disk — standard, easy to move around.
- Comments only where the “why” is not obvious (hybrid layout, OAEP, chunked hashing).

---

## Verify a round-trip

```bash
python generate_keys.py
python hash_file.py data/sample.txt
python encrypt_decrypt.py encrypt data/sample.txt output/sample.txt.enc
python encrypt_decrypt.py decrypt output/sample.txt.enc output/sample.txt.dec
cmp data/sample.txt output/sample.txt.dec && echo OK
```

If `cmp` exits 0, decrypt produced the same bytes as the original.
