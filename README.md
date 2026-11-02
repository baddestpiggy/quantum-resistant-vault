# 🔮 Quantum-Resistant Vault

[![CI](https://github.com/baddestpiggy/quantum-resistant-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/baddestpiggy/quantum-resistant-vault/actions/workflows/ci.yml)

A file vault built on post-quantum cryptography. Lock a file to someone's
public key, watch the key exchange happen step by step, and unlock it only
with the matching secret key.

Today's public-key encryption (RSA, elliptic curves) can be broken by a large
enough quantum computer, and data captured now can be decrypted later
("harvest now, decrypt later"). This vault uses **ML-KEM-768**, the lattice-based
key encapsulation mechanism NIST standardised in **FIPS 203**.

## Tech
Rust · ML-KEM-768 (FIPS 203) · HKDF-SHA256 · AES-256-GCM · RustCrypto

## Quick start
Requires the [Rust toolchain](https://rustup.rs).

```bash
cargo build --release
# binary: target/release/pqvault
```

```bash
pqvault keygen alice                                   # alice.pqpub + alice.pqkey
pqvault encrypt plans.txt --to alice.pqpub --explain   # -> plans.txt.vault
pqvault inspect plans.txt.vault                        # read the public header
pqvault decrypt plans.txt.vault --key alice.pqkey      # -> plans.txt
```

## See the key exchange
`--explain` prints every cryptographic step. Secrets are never printed; only
short SHA-256 fingerprints are shown, so you can see that the sender and the
recipient arrive at the same secret.

```text
$ pqvault encrypt plans.txt --to alice.pqpub --explain
[1] Load recipient public key
    ML-KEM-768 encapsulation key, 1184 bytes, key id 2ac9c3c7463848e8
[2] ML-KEM-768 encapsulate
    Created a fresh 32-byte shared secret (fingerprint b281d1b7) and a 1088-byte
    KEM ciphertext (6fc0600aca527fe0…) that only the secret key can open
[3] HKDF-SHA256 key derivation
    Expanded the shared secret into a 256-bit AES key (fingerprint 7394a024)
[4] AES-256-GCM encrypt
    Encrypted 15 bytes with nonce f66bd6be56f629d5721ec717 and authenticated
    the 1114-byte header; added a 16-byte tag
[5] Write vault
    1145 bytes total = 1114 header + 15 ciphertext + 16 tag

$ pqvault decrypt plans.txt.vault --key alice.pqkey --explain
[1] Read vault header
    Format v1, ML-KEM-768, locked to key id 2ac9c3c7463848e8
[2] ML-KEM-768 decapsulate
    Opened the KEM ciphertext with the secret key and recovered the shared
    secret (fingerprint b281d1b7)                     <- same secret as the sender
[3] HKDF-SHA256 key derivation
    Re-derived the AES key (fingerprint 7394a024)
[4] AES-256-GCM decrypt
    Tag verified: header and ciphertext are unmodified. Recovered 15 bytes
```

Tampering and wrong keys are rejected:

```text
$ pqvault decrypt plans.txt.vault --key bob.pqkey
Error: this file is locked to key 2ac9c3c7463848e8, but the key supplied is 8f2934a28d9942f5

$ pqvault decrypt tampered.vault --key alice.pqkey
Error: authentication failed: the file has been modified or corrupted
```

## How it works

```text
 sender (public key only)                       recipient (secret key)
 ───────────────────────                        ──────────────────────
 ML-KEM.Encaps(pk) ──► shared secret ss         ML-KEM.Decaps(sk, ct) ──► ss
                   └─► KEM ciphertext ct ─────────────────────▲
 HKDF-SHA256(ss)   ──► AES-256 key              HKDF-SHA256(ss) ──► AES-256 key
 AES-GCM(file, AAD = header) ──► vault ───────► AES-GCM verify + decrypt
```

- **Fresh key for every file:** each encryption runs a new encapsulation, so no two files share an AES key.
- **The header is authenticated:** the full header (version, algorithm, key id, KEM ciphertext, nonce) is the AES-GCM associated data. Changing any byte of the file makes decryption fail.
- **Seed-based secret keys:** the `.pqkey` file stores only the 64-byte seed that FIPS 203 recommends, not the 2400-byte expanded key. Secret material is zeroed in memory after use.
- **Clear wrong-key errors:** the header records an 8-byte key id (a SHA-256 prefix of the public key), so a wrong key gives a readable error. A forged key id still fails authentication, as covered by the tests.

### Vault file format (v1)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `PQVT` |
| 4 | 1 | format version (`1`) |
| 5 | 1 | KEM id (`2` = ML-KEM-768) |
| 6 | 8 | recipient key id |
| 14 | 1088 | ML-KEM-768 ciphertext |
| 1102 | 12 | AES-GCM nonce |
| 1114 | n + 16 | AES-256-GCM ciphertext + tag |

## Tests
```bash
cargo test
```
The tests cover:
- round trips, including empty files and 1 MiB files
- that the same plaintext never encrypts to the same bytes twice
- a bit flip in each region of the file (key id, KEM ciphertext, nonce, ciphertext, tag)
- wrong keys, including a forged key id
- truncated, malformed and wrong-version files
- key file type checks
- end-to-end CLI runs

## Limitations
This is an educational project built on the RustCrypto libraries. It has not
been independently reviewed.
- **No sender authentication:** anyone with your public key can create a vault for you. Signatures (ML-DSA) are on the roadmap.
- **Unprotected secret keys:** the secret key file is not passphrase-protected. Keep it private.
- **Whole-file processing:** files are read into memory in one piece, so very large files need streaming (planned).
- **ML-KEM only:** production systems often use a hybrid (X25519 + ML-KEM) during the transition; this project deliberately shows ML-KEM on its own.

## Roadmap
- [x] CLI: keygen / encrypt / decrypt / inspect
- [x] Versioned vault file format with authenticated header
- [x] Step-by-step `--explain` trace
- [x] Tests incl. tamper detection
- [ ] Passphrase-protected secret keys (Argon2id)
- [ ] Streaming encryption for large files
- [ ] ML-DSA signatures for sender authentication
- [ ] WASM build + browser visualisation of the key exchange

## License
MIT
