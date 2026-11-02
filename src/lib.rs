//! Encrypt files to an ML-KEM-768 public key.
//!
//! Encryption (sender, needs only the public key):
//! 1. ML-KEM-768 encapsulate -> 32-byte shared secret + 1088-byte KEM ciphertext
//! 2. HKDF-SHA256(shared secret) -> 256-bit AES key
//! 3. AES-256-GCM(plaintext, AAD = vault header) with a random 96-bit nonce
//!
//! Decryption (recipient, needs the secret key) runs the same steps in reverse:
//! decapsulating the KEM ciphertext recovers the same shared secret.
//!
//! Every file gets a fresh encapsulation, so every file has its own AES key.

pub mod format;

use aes_gcm::aead::{Aead, Generate, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use ml_kem::ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Encapsulate, FromSeed, KeyExport, MlKem768, Seed, TryKeyInit};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use format::{Header, KeyKind, KEY_ID_LEN, SEED_LEN};

/// HKDF context string; changing it changes every derived key.
const HKDF_INFO: &[u8] = b"quantum-resistant-vault v1 ML-KEM-768 AES-256-GCM";

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("not a vault file (bad magic bytes)")]
    BadMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported KEM algorithm id {0}")]
    UnsupportedKem(u8),
    #[error("vault file is truncated")]
    Truncated,
    #[error("this file is locked to key {expected}, but the key supplied is {actual}")]
    WrongKey { expected: String, actual: String },
    #[error("authentication failed: the file has been modified or corrupted")]
    AuthenticationFailed,
    #[error("invalid key file: {0}")]
    InvalidKeyFile(&'static str),
    #[error("encryption failed")]
    EncryptionFailed,
}

/// One step of an encryption or decryption, for `--explain` and visualisation.
#[derive(Debug, Clone)]
pub struct Step {
    pub title: &'static str,
    pub detail: String,
}

impl Step {
    fn new(title: &'static str, detail: String) -> Self {
        Step { title, detail }
    }
}

/// Recipient's public key: anyone holding it can lock files for them.
#[derive(Clone)]
pub struct PublicKey {
    ek: EncapsulationKey,
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        format::encode_key(KeyKind::Public, &self.ek.to_bytes())
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, VaultError> {
        let payload = format::decode_key(KeyKind::Public, data)?;
        let ek = EncapsulationKey::new_from_slice(payload)
            .map_err(|_| VaultError::InvalidKeyFile("malformed ML-KEM public key"))?;
        Ok(PublicKey { ek })
    }

    /// Short fingerprint stored in each vault header so decrypting with the
    /// wrong key gives a clear error.
    pub fn key_id(&self) -> [u8; KEY_ID_LEN] {
        let digest = Sha256::digest(self.ek.to_bytes());
        digest[..KEY_ID_LEN].try_into().unwrap()
    }
}

/// Secret key, stored as the 64-byte FIPS 203 seed it is derived from.
pub struct SecretKey {
    seed: Zeroizing<[u8; SEED_LEN]>,
    dk: DecapsulationKey,
    public: PublicKey,
}

impl SecretKey {
    pub fn generate() -> Self {
        let seed = Zeroizing::new(<[u8; SEED_LEN]>::generate());
        Self::from_seed(seed)
    }

    fn from_seed(seed: Zeroizing<[u8; SEED_LEN]>) -> Self {
        let (dk, ek) = MlKem768::from_seed(&Seed::from(*seed));
        SecretKey {
            seed,
            dk,
            public: PublicKey { ek },
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(format::encode_key(KeyKind::Secret, &self.seed[..]))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, VaultError> {
        let payload = format::decode_key(KeyKind::Secret, data)?;
        let seed = Zeroizing::new(<[u8; SEED_LEN]>::try_from(payload).unwrap());
        Ok(Self::from_seed(seed))
    }
}

pub fn encrypt(public: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
    encrypt_traced(public, plaintext, &mut Vec::new())
}

pub fn decrypt(secret: &SecretKey, data: &[u8]) -> Result<Vec<u8>, VaultError> {
    decrypt_traced(secret, data, &mut Vec::new())
}

pub fn encrypt_traced(
    public: &PublicKey,
    plaintext: &[u8],
    trace: &mut Vec<Step>,
) -> Result<Vec<u8>, VaultError> {
    let key_id = public.key_id();
    trace.push(Step::new(
        "Load recipient public key",
        format!(
            "ML-KEM-768 encapsulation key, {} bytes, key id {}",
            format::PUBLIC_KEY_LEN,
            to_hex(&key_id)
        ),
    ));

    let (kem_ct, shared) = public.ek.encapsulate();
    trace.push(Step::new(
        "ML-KEM-768 encapsulate",
        format!(
            "Created a fresh 32-byte shared secret (fingerprint {}) and a {}-byte \
             KEM ciphertext ({}…) that only the secret key can open",
            fingerprint(&shared),
            kem_ct.len(),
            to_hex(&kem_ct[..8])
        ),
    ));

    let aes_key = derive_key(&shared);
    trace.push(Step::new(
        "HKDF-SHA256 key derivation",
        format!(
            "Expanded the shared secret into a 256-bit AES key (fingerprint {})",
            fingerprint(&aes_key[..])
        ),
    ));

    let nonce = Nonce::generate();
    let header = Header {
        key_id,
        kem_ciphertext: kem_ct.as_slice().try_into().unwrap(),
        nonce: nonce.into(),
    };
    let header_bytes = header.to_bytes();

    let cipher = Aes256Gcm::new_from_slice(&aes_key[..]).expect("AES-256 key is 32 bytes");
    let body = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &header_bytes,
            },
        )
        .map_err(|_| VaultError::EncryptionFailed)?;
    trace.push(Step::new(
        "AES-256-GCM encrypt",
        format!(
            "Encrypted {} bytes with nonce {} and authenticated the {}-byte header; \
             added a {}-byte tag",
            plaintext.len(),
            to_hex(&header.nonce),
            header_bytes.len(),
            format::TAG_LEN
        ),
    ));

    let mut out = Vec::with_capacity(header_bytes.len() + body.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&body);
    trace.push(Step::new(
        "Write vault",
        format!(
            "{} bytes total = {} header + {} ciphertext + {} tag",
            out.len(),
            header_bytes.len(),
            plaintext.len(),
            format::TAG_LEN
        ),
    ));
    Ok(out)
}

pub fn decrypt_traced(
    secret: &SecretKey,
    data: &[u8],
    trace: &mut Vec<Step>,
) -> Result<Vec<u8>, VaultError> {
    let (header, header_bytes, body) = Header::parse(data)?;
    trace.push(Step::new(
        "Read vault header",
        format!(
            "Format v{}, ML-KEM-768, locked to key id {}",
            format::FORMAT_VERSION,
            to_hex(&header.key_id)
        ),
    ));

    let our_id = secret.public.key_id();
    if header.key_id != our_id {
        return Err(VaultError::WrongKey {
            expected: to_hex(&header.key_id),
            actual: to_hex(&our_id),
        });
    }

    let kem_ct = Ciphertext::try_from(&header.kem_ciphertext[..]).unwrap();
    let shared = secret.dk.decapsulate(&kem_ct);
    trace.push(Step::new(
        "ML-KEM-768 decapsulate",
        format!(
            "Opened the KEM ciphertext with the secret key and recovered the shared \
             secret (fingerprint {})",
            fingerprint(&shared)
        ),
    ));

    let aes_key = derive_key(&shared);
    trace.push(Step::new(
        "HKDF-SHA256 key derivation",
        format!(
            "Re-derived the AES key (fingerprint {})",
            fingerprint(&aes_key[..])
        ),
    ));

    let cipher = Aes256Gcm::new_from_slice(&aes_key[..]).expect("AES-256 key is 32 bytes");
    let nonce = Nonce::from(header.nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: body,
                aad: header_bytes,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    trace.push(Step::new(
        "AES-256-GCM decrypt",
        format!(
            "Tag verified: header and ciphertext are unmodified. Recovered {} bytes",
            plaintext.len()
        ),
    ));
    Ok(plaintext)
}

fn derive_key(shared: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(HKDF_INFO, &mut key[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// SHA-256 prefix of a secret: lets `--explain` show that both sides agree
/// without printing the secret itself.
fn fingerprint(secret: &[u8]) -> String {
    to_hex(&Sha256::digest(secret)[..4])
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
