use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn pqvault(dir: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pqvault"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pqvault-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn keygen_encrypt_decrypt() {
    let dir = temp_dir("e2e");
    fs::write(dir.join("secret.txt"), b"top secret notes").unwrap();

    assert!(pqvault(&dir, &["keygen", "alice"]).status.success());
    assert!(
        pqvault(&dir, &["encrypt", "secret.txt", "--to", "alice.pqpub"])
            .status
            .success()
    );
    fs::remove_file(dir.join("secret.txt")).unwrap();

    let inspect = pqvault(&dir, &["inspect", "secret.txt.vault"]);
    assert!(String::from_utf8_lossy(&inspect.stdout).contains("ML-KEM-768"));

    let out = pqvault(
        &dir,
        &[
            "decrypt",
            "secret.txt.vault",
            "--key",
            "alice.pqkey",
            "--explain",
        ],
    );
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Tag verified"));
    assert_eq!(
        fs::read(dir.join("secret.txt")).unwrap(),
        b"top secret notes"
    );

    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn refuses_to_overwrite_without_force() {
    let dir = temp_dir("overwrite");
    assert!(pqvault(&dir, &["keygen", "bob"]).status.success());
    let original = fs::read(dir.join("bob.pqkey")).unwrap();

    let again = pqvault(&dir, &["keygen", "bob"]);
    assert!(!again.status.success());
    assert_eq!(fs::read(dir.join("bob.pqkey")).unwrap(), original);

    fs::remove_dir_all(&dir).unwrap();
}
