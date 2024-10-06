//! # EnvEnc - Secure Environment Variable Management
//!
//! **EnvEnc** is a Rust crate that helps you securely encrypt and decrypt environment variables using
//! the ChaCha20-Poly1305 or AES256-GCM encryption schemes.
//!
//! Store sensitive information like API keys, database credentials, and other configuration secrets
//! in your `.env` file in a secure, encrypted format.
//!
//! ## Features
//!
//! - Encrypt environment variables before storing them.
//! - Automatically decrypt environment variables when needed.
//! - Support for secure key and nonce generation.
//! - Support for multiple encryption algorithms.
//!
//! ## Usage
//!
//! Below is an example of how to encrypt, decrypt, and read environment variables using EnvEnc:
//!
//! ```rust
//! use envenc::{decrypt_env, keys_generation, read_env, read_env_enc, set_enc_env, CipherType};
//!
//! fn main() {
//!     // Choose cipher type
//!     let cipher_type = CipherType::AES256GCM; // or CipherType::ChaCha20Poly1305
//!
//!     // Generate encryption key and nonce
//!     let (key, nonce) = keys_generation(cipher_type);
//!
//!     // Encrypt and set environment variables
//!     set_enc_env(
//!         "DATABASE_URL",
//!         "postgres://user:password@localhost/db",
//!         cipher_type,
//!         &key,
//!         &nonce,
//!     );
//!     set_enc_env(
//!         "API_KEY",
//!         "super_secret_api_key",
//!         cipher_type,
//!         &key,
//!         &nonce,
//!     );
//!     set_enc_env(
//!         "CACHE_SERVER",
//!         "redis://localhost:6379",
//!         cipher_type,
//!         &key,
//!         &nonce,
//!     );
//!
//!     // Read the encrypted environment variables from the .env file
//!     let encrypted_env = read_env_enc();
//!
//!     // Decrypt the environment variables using the key and nonce
//!     decrypt_env(encrypted_env, cipher_type, &key, &nonce);
//!
//!     // Read the decrypted values from the environment variables
//!     let database_url = read_env("DATABASE_URL").unwrap_or("DATABASE_URL not found".to_string());
//!     let api_key = read_env("API_KEY").unwrap_or("API_KEY not found".to_string());
//!     let cache_server = read_env("CACHE_SERVER").unwrap_or("CACHE_SERVER not found".to_string());
//!
//!     // Print the decrypted environment variables
//!     println!("Database URL: {}", database_url);
//!     println!("API Key: {}", api_key);
//!     println!("Cache Server: {}", cache_server);
//! }
//! ```
//!
//! ### How It Works
//!
//! 1. **Key and Nonce Generation**: The key and nonce are generated using secure random bytes.
//!    This ensures that each encryption is securely tied to unique keys.
//! 2. **Encryption and Storage**: Sensitive environment variables are encrypted and stored in the `.env` file.
//! 3. **Decryption**: The encrypted variables are decrypted and read back into the runtime environment using the same key and nonce.
//!
//! ### Why Use EnvEnc?
//!
//! - **Security**: Environment variables are stored in an encrypted format, reducing the risk of exposing sensitive data.
//! - **Ease of Use**: Encrypting and decrypting environment variables is as simple as calling a few functions.
//! - **Customization**: You can choose between different encryption algorithms, giving you flexibility in how encryption is handled.
//!

use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use dotenv::dotenv;
use rand::{thread_rng, RngCore};
use std::{
    collections::HashMap,
    env,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};

/// Enum to represent different cipher types.
///
/// Currently supported ciphers:
/// - `ChaCha20Poly1305`
/// - `AES256GCM`
///
/// # Example
///
/// ```
/// use envenc::CipherType;
///
/// let cipher_type = CipherType::AES256GCM;
/// ```
#[derive(Clone, Copy)]
pub enum CipherType {
    ChaCha20Poly1305,
    AES256GCM,
}

impl CipherType {
    pub fn key_size(&self) -> usize {
        match self {
            CipherType::ChaCha20Poly1305 => 32,
            CipherType::AES256GCM => 32,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            CipherType::ChaCha20Poly1305 => 12,
            CipherType::AES256GCM => 12,
        }
    }
}

impl std::fmt::Display for CipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            CipherType::ChaCha20Poly1305 => write!(f, "CHACHA20POLY1305"),
            CipherType::AES256GCM => write!(f, "AES256GCM"),
        }
    }
}

/// Generates or retrieves the encryption key and nonce based on the cipher type.
///
/// This function checks if the key and nonce for the specified cipher type are already set
/// in environment variables. If they are, it retrieves and uses them. Otherwise, it generates
/// new key and nonce using secure random bytes, and stores them in environment variables for future use.
///
/// # Arguments
///
/// * `cipher_type` - The cipher type to use (either `CipherType::ChaCha20Poly1305` or `CipherType::AES256GCM`).
///
/// # Returns
///
/// A tuple `(Vec<u8>, Vec<u8>)` containing the encryption key and nonce.
///
/// # Example
///
/// ```
/// use envenc::{keys_generation, CipherType};
///
/// let cipher_type = CipherType::AES256GCM;
/// let (key, nonce) = keys_generation(cipher_type);
/// ```
pub fn keys_generation(cipher_type: CipherType) -> (Vec<u8>, Vec<u8>) {
    let key_var = format!("{}_KEY", cipher_type);
    let nonce_var = format!("{}_NONCE", cipher_type);

    let key = match env::var(&key_var) {
        Ok(key_hex) => hex::decode(key_hex).expect("Invalid key hex"),
        Err(_) => {
            let key_size = cipher_type.key_size();
            let mut key = vec![0u8; key_size];
            thread_rng().fill_bytes(&mut key);
            let key_hex = hex::encode(&key);
            env::set_var(&key_var, &key_hex);
            key
        }
    };

    let nonce = match env::var(&nonce_var) {
        Ok(nonce_hex) => hex::decode(nonce_hex).expect("Invalid nonce hex"),
        Err(_) => {
            let nonce_size = cipher_type.nonce_size();
            let mut nonce = vec![0u8; nonce_size];
            thread_rng().fill_bytes(&mut nonce);
            let nonce_hex = hex::encode(&nonce);
            env::set_var(&nonce_var, &nonce_hex);
            nonce
        }
    };

    (key, nonce)
}

/// Encrypts data based on the cipher type.
///
/// This is a lower-level function that performs encryption using the specified cipher,
/// key, and nonce.
///
/// # Arguments
///
/// * `cipher_type` - The cipher type to use.
/// * `key` - The encryption key.
/// * `nonce` - The nonce.
/// * `plaintext` - The data to encrypt.
///
/// # Returns
///
/// A `Vec<u8>` containing the encrypted data.
///
/// # Example
///
/// ```
/// use envenc::{encrypt, keys_generation, CipherType};
///
/// let cipher_type = CipherType::AES256GCM;
/// let (key, nonce) = keys_generation(cipher_type);
/// let plaintext = b"Secret message";
/// let ciphertext = encrypt(cipher_type, &key, &nonce, plaintext);
/// ```
pub fn encrypt(cipher_type: CipherType, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    match cipher_type {
        CipherType::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
            cipher
                .encrypt(ChaChaNonce::from_slice(nonce), plaintext)
                .expect("encryption failure!")
        }
        CipherType::AES256GCM => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            cipher
                .encrypt(AesNonce::from_slice(nonce), plaintext)
                .expect("encryption failure!")
        }
    }
}

/// Decrypts data based on the cipher type.
///
/// This is a lower-level function that performs decryption using the specified cipher,
/// key, and nonce.
///
/// # Arguments
///
/// * `cipher_type` - The cipher type to use.
/// * `key` - The encryption key.
/// * `nonce` - The nonce.
/// * `ciphertext` - The data to decrypt.
///
/// # Returns
///
/// A `Vec<u8>` containing the decrypted data.
///
/// # Example
///
/// ```
/// use envenc::{encrypt, decrypt, keys_generation, CipherType};
///
/// let cipher_type = CipherType::AES256GCM;
/// let (key, nonce) = keys_generation(cipher_type);
/// let plaintext = b"Secret message";
/// let ciphertext = encrypt(cipher_type, &key, &nonce, plaintext);
/// let decrypted = decrypt(cipher_type, &key, &nonce, &ciphertext);
/// assert_eq!(plaintext.to_vec(), decrypted);
/// ```
pub fn decrypt(cipher_type: CipherType, key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    match cipher_type {
        CipherType::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
            cipher
                .decrypt(ChaChaNonce::from_slice(nonce), ciphertext)
                .expect("decryption failure!")
        }
        CipherType::AES256GCM => {
            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            cipher
                .decrypt(AesNonce::from_slice(nonce), ciphertext)
                .expect("decryption failure!")
        }
    }
}

/// Encrypts and stores an environment variable using the provided cipher, key, and nonce.
///
/// If the variable already exists in the `.env` file, no changes are made.
///
/// # Arguments
///
/// * `var_name` - The name of the environment variable to set.
/// * `var_text` - The plaintext value of the environment variable to encrypt.
/// * `cipher_type` - The cipher type to use.
/// * `key` - The encryption key.
/// * `nonce` - The nonce.
///
/// # Example
///
/// ```
/// use envenc::{set_enc_env, keys_generation, CipherType};
///
/// let cipher_type = CipherType::AES256GCM;
/// let (key, nonce) = keys_generation(cipher_type);
///
/// set_enc_env("API_KEY", "my_secret_api_key", cipher_type, &key, &nonce);
/// ```
pub fn set_enc_env(
    var_name: &str,
    var_text: &str,
    cipher_type: CipherType,
    key: &[u8],
    nonce: &[u8],
) {
    let ciphertext = encrypt(cipher_type, key, nonce, var_text.as_bytes());

    let mut combined = Vec::new();
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&ciphertext);

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

/// Reads all encrypted environment variables from the `.env` file.
///
/// # Returns
///
/// A `HashMap<String, String>` containing the environment variable names and their encrypted values.
///
/// # Example
///
/// ```
/// use envenc::read_env_enc;
///
/// let encrypted_env = read_env_enc();
/// ```
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

/// Decrypts the provided environment variables using the provided cipher, key, and nonce,
/// and sets them in the current process environment.
///
/// # Arguments
///
/// * `env_vars` - A hashmap containing the encrypted environment variables.
/// * `cipher_type` - The cipher type to use.
/// * `key` - The encryption key.
/// * `_nonce` - The nonce (unused, as the nonce is retrieved from the encrypted data).
///
/// # Example
///
/// ```
/// use envenc::{decrypt_env, read_env_enc, keys_generation, CipherType};
///
/// let cipher_type = CipherType::AES256GCM;
/// let (key, nonce) = keys_generation(cipher_type);
///
/// let encrypted_env = read_env_enc();
/// decrypt_env(encrypted_env, cipher_type, &key, &nonce);
/// ```
pub fn decrypt_env(
    env_vars: HashMap<String, String>,
    cipher_type: CipherType,
    key: &[u8],
    _nonce: &[u8], // Unused in this context
) {
    for (var_name, enc_value) in env_vars {
        if let Ok(combined) = hex::decode(enc_value) {
            let nonce_size = cipher_type.nonce_size();
            if combined.len() < nonce_size {
                eprintln!("Skipping {}: combined data too short", var_name);
                continue;
            }
            let nonce_used = &combined[..nonce_size];
            let ciphertext = &combined[nonce_size..];

            let decrypted = decrypt(cipher_type, key, nonce_used, ciphertext);

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
/// An `Option<String>` containing the decrypted value of the environment variable if it exists,
/// otherwise `None`.
///
/// # Example
///
/// ```
/// use envenc::read_env;
///
/// let api_key = read_env("API_KEY").unwrap_or("API_KEY not found".to_string());
/// println!("API Key: {}", api_key);
/// ```
pub fn read_env(var_name: &str) -> Option<String> {
    env::var(var_name).ok()
}