//! Byte layouts for vault files and key files.
//!
//! Vault file (`.vault`):
//!
//! ```text
//! offset  size   field
//! 0       4      magic "PQVT"
//! 4       1      format version (1)
//! 5       1      KEM algorithm id (2 = ML-KEM-768)
//! 6       8      recipient key id (first 8 bytes of SHA-256 of the public key)
//! 14      1088   ML-KEM-768 ciphertext (encapsulated shared secret)
//! 1102    12     AES-GCM nonce
//! 1114    n+16   AES-256-GCM ciphertext followed by the 16-byte tag
//! ```
//!
//! The first 1114 bytes (the header) are passed to AES-GCM as associated data,
//! so changing any header byte makes decryption fail.
//!
//! Key file (`.pqpub` / `.pqkey`):
//!
//! ```text
//! 0  4  magic "PQVK"
//! 4  1  format version (1)
//! 5  1  kind ('P' = public, 'S' = secret)
//! 6  1  KEM algorithm id (2 = ML-KEM-768)
//! 7  …  payload: 1184-byte encapsulation key, or 64-byte secret seed
//! ```

use crate::VaultError;

pub const VAULT_MAGIC: &[u8; 4] = b"PQVT";
pub const KEY_MAGIC: &[u8; 4] = b"PQVK";
pub const FORMAT_VERSION: u8 = 1;
pub const KEM_ML_KEM_768: u8 = 2;

pub const KEY_ID_LEN: usize = 8;
pub const KEM_CIPHERTEXT_LEN: usize = 1088;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const PUBLIC_KEY_LEN: usize = 1184;
pub const SEED_LEN: usize = 64;

pub const HEADER_LEN: usize = 4 + 1 + 1 + KEY_ID_LEN + KEM_CIPHERTEXT_LEN + NONCE_LEN;
const KEY_PREFIX_LEN: usize = 4 + 1 + 1 + 1;

/// The unencrypted (but authenticated) front of a vault file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub key_id: [u8; KEY_ID_LEN],
    pub kem_ciphertext: [u8; KEM_CIPHERTEXT_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let mut w = Writer {
            buf: &mut out,
            pos: 0,
        };
        w.put(VAULT_MAGIC);
        w.put(&[FORMAT_VERSION, KEM_ML_KEM_768]);
        w.put(&self.key_id);
        w.put(&self.kem_ciphertext);
        w.put(&self.nonce);
        out
    }

    /// Splits a vault file into its parsed header, the raw header bytes (used
    /// as AAD) and the AES-GCM body.
    pub fn parse(data: &[u8]) -> Result<(Header, &[u8], &[u8]), VaultError> {
        if data.len() < 4 || &data[..4] != VAULT_MAGIC {
            return Err(VaultError::BadMagic);
        }
        if data.len() < HEADER_LEN + TAG_LEN {
            return Err(VaultError::Truncated);
        }
        let (header_bytes, body) = data.split_at(HEADER_LEN);
        if header_bytes[4] != FORMAT_VERSION {
            return Err(VaultError::UnsupportedVersion(header_bytes[4]));
        }
        if header_bytes[5] != KEM_ML_KEM_768 {
            return Err(VaultError::UnsupportedKem(header_bytes[5]));
        }
        let mut r = Reader {
            buf: header_bytes,
            pos: 6,
        };
        let header = Header {
            key_id: r.take(),
            kem_ciphertext: r.take(),
            nonce: r.take(),
        };
        Ok((header, header_bytes, body))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    Public,
    Secret,
}

impl KeyKind {
    fn tag(self) -> u8 {
        match self {
            KeyKind::Public => b'P',
            KeyKind::Secret => b'S',
        }
    }
}

pub fn encode_key(kind: KeyKind, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_PREFIX_LEN + payload.len());
    out.extend_from_slice(KEY_MAGIC);
    out.extend_from_slice(&[FORMAT_VERSION, kind.tag(), KEM_ML_KEM_768]);
    out.extend_from_slice(payload);
    out
}

/// Checks a key file's prefix and returns its payload.
pub fn decode_key(kind: KeyKind, data: &[u8]) -> Result<&[u8], VaultError> {
    if data.len() < KEY_PREFIX_LEN || &data[..4] != KEY_MAGIC {
        return Err(VaultError::InvalidKeyFile("not a vault key file"));
    }
    if data[4] != FORMAT_VERSION {
        return Err(VaultError::UnsupportedVersion(data[4]));
    }
    if data[5] != kind.tag() {
        return Err(VaultError::InvalidKeyFile(match kind {
            KeyKind::Public => "expected a public key (.pqpub)",
            KeyKind::Secret => "expected a secret key (.pqkey)",
        }));
    }
    if data[6] != KEM_ML_KEM_768 {
        return Err(VaultError::UnsupportedKem(data[6]));
    }
    let payload = &data[KEY_PREFIX_LEN..];
    let expected = match kind {
        KeyKind::Public => PUBLIC_KEY_LEN,
        KeyKind::Secret => SEED_LEN,
    };
    if payload.len() != expected {
        return Err(VaultError::InvalidKeyFile("wrong key length"));
    }
    Ok(payload)
}

struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let out = self.buf[self.pos..self.pos + N].try_into().unwrap();
        self.pos += N;
        out
    }
}
