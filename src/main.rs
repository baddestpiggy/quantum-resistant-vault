use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use quantum_resistant_vault::format::{self, Header};
use quantum_resistant_vault::{self as vault, PublicKey, SecretKey, Step};

/// Post-quantum file vault: ML-KEM-768 key exchange + AES-256-GCM.
#[derive(Parser)]
#[command(name = "pqvault", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a key pair: <NAME>.pqpub (share it) and <NAME>.pqkey (keep it secret)
    Keygen {
        #[arg(default_value = "vault")]
        name: PathBuf,
        /// Overwrite existing key files
        #[arg(long)]
        force: bool,
    },
    /// Lock a file so only the holder of the matching secret key can open it
    Encrypt {
        file: PathBuf,
        /// Recipient's public key (.pqpub)
        #[arg(long, short)]
        to: PathBuf,
        /// Output path (default: <FILE>.vault)
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Print each cryptographic step
        #[arg(long)]
        explain: bool,
        #[arg(long)]
        force: bool,
    },
    /// Unlock a .vault file with your secret key
    Decrypt {
        file: PathBuf,
        /// Your secret key (.pqkey)
        #[arg(long, short)]
        key: PathBuf,
        /// Output path (default: <FILE> without .vault)
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Print each cryptographic step
        #[arg(long)]
        explain: bool,
        #[arg(long)]
        force: bool,
    },
    /// Show the public header of a .vault file (no key needed)
    Inspect { file: PathBuf },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { name, force } => keygen(&name, force),
        Command::Encrypt {
            file,
            to,
            out,
            explain,
            force,
        } => {
            let public = PublicKey::from_bytes(&read(&to)?)
                .with_context(|| format!("loading public key {}", to.display()))?;
            let mut trace = Vec::new();
            let sealed = vault::encrypt_traced(&public, &read(&file)?, &mut trace)?;
            let out = out.unwrap_or_else(|| append_ext(&file, "vault"));
            write_new(&out, &sealed, force)?;
            if explain {
                print_trace(&trace);
            }
            println!("Locked {} -> {}", file.display(), out.display());
            Ok(())
        }
        Command::Decrypt {
            file,
            key,
            out,
            explain,
            force,
        } => {
            let secret = SecretKey::from_bytes(&read(&key)?)
                .with_context(|| format!("loading secret key {}", key.display()))?;
            let mut trace = Vec::new();
            let result = vault::decrypt_traced(&secret, &read(&file)?, &mut trace);
            if explain {
                print_trace(&trace);
            }
            let plaintext = result?;
            let out = match out {
                Some(out) => out,
                None => strip_vault_ext(&file)?,
            };
            write_new(&out, &plaintext, force)?;
            println!("Unlocked {} -> {}", file.display(), out.display());
            Ok(())
        }
        Command::Inspect { file } => inspect(&file),
    }
}

fn keygen(name: &Path, force: bool) -> Result<()> {
    let secret = SecretKey::generate();
    let pub_path = append_ext(name, "pqpub");
    let key_path = append_ext(name, "pqkey");
    // Write the secret first so a failure never leaves a public key without its secret.
    write_new(&key_path, &secret.to_bytes(), force)?;
    write_new(&pub_path, &secret.public_key().to_bytes(), force)?;
    println!(
        "Key id:      {}",
        vault::to_hex(&secret.public_key().key_id())
    );
    println!("Public key:  {}  (share this)", pub_path.display());
    println!(
        "Secret key:  {}  (keep this private, never commit it)",
        key_path.display()
    );
    Ok(())
}

fn inspect(file: &Path) -> Result<()> {
    let data = read(file)?;
    let (header, _, body) = Header::parse(&data)?;
    println!("File:            {}", file.display());
    println!("Format version:  {}", format::FORMAT_VERSION);
    println!("Key exchange:    ML-KEM-768 (FIPS 203)");
    println!("Cipher:          AES-256-GCM, key from HKDF-SHA256");
    println!("Locked to key:   {}", vault::to_hex(&header.key_id));
    println!("KEM ciphertext:  {} bytes", header.kem_ciphertext.len());
    println!("Nonce:           {}", vault::to_hex(&header.nonce));
    println!(
        "Encrypted data:  {} bytes (+{} byte tag)",
        body.len() - format::TAG_LEN,
        format::TAG_LEN
    );
    Ok(())
}

fn print_trace(trace: &[Step]) {
    for (i, step) in trace.iter().enumerate() {
        println!("[{}] {}\n    {}", i + 1, step.title, step.detail);
    }
    println!();
}

fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn write_new(path: &Path, data: &[u8], force: bool) -> Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    let mut f = opts.open(path).with_context(|| {
        if path.exists() && !force {
            format!(
                "{} already exists (use --force to overwrite)",
                path.display()
            )
        } else {
            format!("creating {}", path.display())
        }
    })?;
    f.write_all(data)
        .with_context(|| format!("writing {}", path.display()))
}

fn append_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

fn strip_vault_ext(path: &Path) -> Result<PathBuf> {
    if path.extension().is_some_and(|e| e == "vault") {
        Ok(path.with_extension(""))
    } else {
        bail!("{} doesn't end in .vault; pass --out", path.display())
    }
}
