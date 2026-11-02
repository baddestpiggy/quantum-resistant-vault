use quantum_resistant_vault::format::{HEADER_LEN, KEM_CIPHERTEXT_LEN, KEY_ID_LEN, TAG_LEN};
use quantum_resistant_vault::{decrypt, encrypt, PublicKey, SecretKey, VaultError};

const MESSAGE: &[u8] = b"attack at dawn, but quantum-safely";

#[test]
fn round_trip() {
    let sk = SecretKey::generate();
    let sealed = encrypt(sk.public_key(), MESSAGE).unwrap();
    assert_eq!(sealed.len(), HEADER_LEN + MESSAGE.len() + TAG_LEN);
    assert_eq!(decrypt(&sk, &sealed).unwrap(), MESSAGE);
}

#[test]
fn round_trip_empty_and_large() {
    let sk = SecretKey::generate();
    for len in [0usize, 1, 1 << 20] {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let sealed = encrypt(sk.public_key(), &data).unwrap();
        assert_eq!(decrypt(&sk, &sealed).unwrap(), data);
    }
}

#[test]
fn same_plaintext_encrypts_differently() {
    let sk = SecretKey::generate();
    let a = encrypt(sk.public_key(), MESSAGE).unwrap();
    let b = encrypt(sk.public_key(), MESSAGE).unwrap();
    assert_ne!(a, b, "each file must use a fresh encapsulation and nonce");
}

#[test]
fn wrong_key_is_rejected() {
    let alice = SecretKey::generate();
    let mallory = SecretKey::generate();
    let sealed = encrypt(alice.public_key(), MESSAGE).unwrap();
    assert!(matches!(
        decrypt(&mallory, &sealed),
        Err(VaultError::WrongKey { .. })
    ));
}

#[test]
fn wrong_key_with_forged_key_id_still_fails_authentication() {
    let alice = SecretKey::generate();
    let mallory = SecretKey::generate();
    let mut sealed = encrypt(alice.public_key(), MESSAGE).unwrap();
    // Pretend the file was locked to Mallory's key.
    sealed[6..6 + KEY_ID_LEN].copy_from_slice(&mallory.public_key().key_id());
    assert!(matches!(
        decrypt(&mallory, &sealed),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn any_flipped_bit_is_detected() {
    let sk = SecretKey::generate();
    let sealed = encrypt(sk.public_key(), MESSAGE).unwrap();
    let kem_ct_start = 6 + KEY_ID_LEN;
    let regions = [
        ("key id", 6),
        ("KEM ciphertext", kem_ct_start + KEM_CIPHERTEXT_LEN / 2),
        ("nonce", kem_ct_start + KEM_CIPHERTEXT_LEN),
        ("ciphertext", HEADER_LEN),
        ("tag", sealed.len() - 1),
    ];
    for (name, offset) in regions {
        let mut tampered = sealed.clone();
        tampered[offset] ^= 0x01;
        assert!(
            decrypt(&sk, &tampered).is_err(),
            "tampering with the {name} was not detected"
        );
    }
}

#[test]
fn malformed_files_are_rejected() {
    let sk = SecretKey::generate();
    let sealed = encrypt(sk.public_key(), MESSAGE).unwrap();

    assert!(matches!(decrypt(&sk, b"hello"), Err(VaultError::BadMagic)));
    assert!(matches!(
        decrypt(&sk, &sealed[..HEADER_LEN + TAG_LEN - 1]),
        Err(VaultError::Truncated)
    ));

    let mut bad_version = sealed.clone();
    bad_version[4] = 99;
    assert!(matches!(
        decrypt(&sk, &bad_version),
        Err(VaultError::UnsupportedVersion(99))
    ));

    let mut truncated_body = sealed.clone();
    truncated_body.pop();
    assert!(matches!(
        decrypt(&sk, &truncated_body),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn key_files_round_trip() {
    let sk = SecretKey::generate();
    let sk2 = SecretKey::from_bytes(&sk.to_bytes()).unwrap();
    let pk2 = PublicKey::from_bytes(&sk.public_key().to_bytes()).unwrap();
    assert_eq!(sk2.public_key().key_id(), sk.public_key().key_id());
    assert_eq!(pk2.key_id(), sk.public_key().key_id());

    // A file locked to the reloaded public key opens with the reloaded secret key.
    let sealed = encrypt(&pk2, MESSAGE).unwrap();
    assert_eq!(decrypt(&sk2, &sealed).unwrap(), MESSAGE);
}

#[test]
fn key_files_are_type_checked() {
    let sk = SecretKey::generate();
    assert!(PublicKey::from_bytes(&sk.to_bytes()).is_err());
    assert!(SecretKey::from_bytes(&sk.public_key().to_bytes()).is_err());
    assert!(PublicKey::from_bytes(b"not a key").is_err());
}
