use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use hex;
use sha2::{Digest, Sha256};

use std::{
    collections::HashMap,
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};

use dotenv::dotenv;

/// Generates a 32-byte encryption key from the given password using SHA-256.
///
/// # Arguments
///
/// * `password` - A string slice that holds the password to derive the key from.
///
/// # Returns
///
/// * `[u8; 32]` - A 32-byte array that represents the encryption key.
pub fn key_gen(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    key
}

/// Generates a 12-byte nonce from the given password using SHA-256.
///
/// # Arguments
///
/// * `password` - A string slice that holds the password to derive the nonce from.
///
/// # Returns
///
/// * `[u8; 12]` - A 12-byte array that represents the nonce.
pub fn nonce_gen(password: &str) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&result[..12]);
    nonce
}

/// Encrypts and stores an environment variable using the provided key and nonce.
///
/// If the variable already exists, no changes are made.
///
/// # Arguments
///
/// * `var_name` - The name of the environment variable to set.
/// * `var_text` - The plaintext value of the environment variable to encrypt.
/// * `key` - The 32-byte encryption key.
/// * `nonce` - The 12-byte nonce used for encryption.
pub fn set_enc_env(var_name: &str, var_text: &str, key: [u8; 32], nonce: [u8; 12]) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), var_text.as_bytes())
        .expect("encryption failure!");

    let mut combined = nonce.to_vec();
    combined.extend(ciphertext);

    let encrypted_value = hex::encode(combined);

    let env_file_path = Path::new(".env");
    let mut env_vars = HashMap::new();

    if let Ok(file) = File::open(env_file_path) {
        let reader = BufReader::new(file);
        for line in reader.lines().filter_map(Result::ok) {
            if let Some((key, value)) = line.split_once('=') {
                env_vars.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }

    if env_vars.contains_key(var_name) {
        println!(
            "Environment variable '{}' already exists. No changes made.",
            var_name
        );
    } else {
        env_vars.insert(var_name.to_string(), encrypted_value);

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(env_file_path)
            .expect("Unable to open or create .env file");

        let mut writer = BufWriter::new(file);
        for (key, value) in &env_vars {
            writeln!(writer, "{}={}", key, value).expect("Unable to write to .env file");
        }
    }
}

/// Reads all environment variables stored in the `.env` file.
///
/// # Returns
///
/// * `HashMap<String, String>` - A hashmap containing the environment variable names and their encrypted values.
pub fn read_env_enc() -> HashMap<String, String> {
    dotenv().ok();

    let mut env_vars = HashMap::new();
    if let Ok(lines) = fs::read_to_string(".env") {
        for line in lines.lines() {
            if let Some((key, value)) = line.split_once('=') {
                env_vars.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    env_vars
}

/// Decrypts the provided environment variables using the provided key and nonce.
///
/// # Arguments
///
/// * `env_vars` - A hashmap containing the encrypted environment variables.
/// * `key` - The 32-byte encryption key.
/// * `nonce` - The 12-byte nonce used for decryption.
pub fn decrypt_env(env_vars: HashMap<String, String>, key: [u8; 32], nonce: [u8; 12]) {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

    for (var_name, enc_value) in env_vars {
        if let Ok(combined) = hex::decode(enc_value) {
            if combined.len() < 12 {
                eprintln!("Skipping {}: combined data too short", var_name);
                continue;
            }

            let ciphertext = &combined[12..];
            let decrypted = cipher
                .decrypt(Nonce::from_slice(&nonce), ciphertext)
                .expect("decryption failure!");

            let decrypted_str = String::from_utf8(decrypted).expect("invalid utf-8");
            env::set_var(var_name, decrypted_str);
        } else {
            eprintln!("Skipping {}: invalid hex encoding", var_name);
        }
    }
}

/// Reads the value of a decrypted environment variable by its name.
///
/// # Arguments
///
/// * `var_name` - The name of the environment variable to read.
///
/// # Returns
///
/// * `Option<String>` - The decrypted value of the environment variable if it exists, otherwise `None`.
pub fn read_env(var_name: &str) -> Option<String> {
    env::var(var_name).ok()
}