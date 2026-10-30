# 🔮 Quantum-Resistant Vault

A file vault built on post-quantum cryptography. Encrypt a file, watch the key
exchange happen step by step, and unlock it only with the right key.

> **Status:** in development

## Tech
Rust · ML-KEM (FIPS 203) · AES-256-GCM · lattice cryptography · WebAssembly

## How it works
1. **Key generation** – create an ML-KEM key pair.
2. **Encapsulation** – derive a shared secret against the recipient's public key.
3. **Encryption** – use the shared secret (via a KDF) as an AES-GCM key to encrypt the file.
4. **Unlock** – decapsulate with the private key, re-derive the key, decrypt and verify.
5. **Visualise** – a WASM build runs in the browser and animates each step.

## Roadmap
- [ ] CLI: keygen / encrypt / decrypt
- [ ] Vault file format (header, ciphertext, nonce, tag)
- [ ] Tests incl. tamper detection
- [ ] WASM build
- [ ] Browser visualisation of the key exchange

## Getting started
Requires the [Rust toolchain](https://rustup.rs).
```bash
cargo run
cargo test
```

## Disclaimer
Educational project built on audited libraries; it has not been independently
reviewed. Do not use it as your only copy of important data.

## License
MIT
