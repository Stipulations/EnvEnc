
# EnvEnc - Secure Environment Variable Management

**EnvEnc** is a Rust crate that helps you securely encrypt and decrypt environment variables using the ChaCha20-Poly1305 encryption scheme. Store sensitive information like API keys, database credentials, and other configuration secrets in your `.env` file in a secure, encrypted format.

## Features

- Encrypt environment variables before storing them.
- Automatically decrypt environment variables when needed.
- Support for secure key and nonce generation using passwords.

## Usage

### Installation

Add `envenc` to your `Cargo.toml`:

```toml
[dependencies]
envenc = "0.0.1"
```
## Usage/Examples
#### Below is an example of how to encrypt, decrypt, and read environment variables using EnvEnc:

```rust
use envenc::{decrypt_env, key_gen, nonce_gen, read_env, read_env_enc, set_enc_env};

fn main() {
    // Generate encryption key from a password
    let encryption_key = key_gen("encryption_password");

    // Generate a nonce from a separate password
    let nonce = nonce_gen("nonce_password");

    // Encrypt and set environment variables
    set_enc_env("DATABASE_URL", "postgres://user:password@localhost/db", encryption_key, nonce);
    set_enc_env("API_KEY", "super_secret_api_key", encryption_key, nonce);
    set_enc_env("CACHE_SERVER", "redis://localhost:6379", encryption_key, nonce);

    // Read the encrypted environment variables from the .env file
    let encrypted_env = read_env_enc();

    // Decrypt the environment variables using the key and nonce
    decrypt_env(encrypted_env, encryption_key, nonce);

    // Read the decrypted values from the environment variables
    let database_url = read_env("DATABASE_URL").unwrap_or("DATABASE_URL not found".to_string());
    let api_key = read_env("API_KEY").unwrap_or("API_KEY not found".to_string());
    let cache_server = read_env("CACHE_SERVER").unwrap_or("CACHE_SERVER not found".to_string());

    // Print the decrypted environment variables
    println!("Database URL: {}", database_url);
    println!("API Key: {}", api_key);
    println!("Cache Server: {}", cache_server);
}

```

# Output
```
Database URL: postgres://user:password@localhost/db
API Key: super_secret_api_key
Cache Server: redis://localhost:6379

```

### How It Works

1. **Key and Nonce Generation**: The key and nonce are generated using the provided passwords. This ensures that each encryption is securely tied to the passwords.
2. **Encryption and Storage**: Sensitive environment variables are encrypted and stored in the `.env` file.
3. **Decryption**: The encrypted variables are decrypted and read back into the runtime environment using the same key and nonce.

### Why Use EnvEnc?

- **Security**: Environment variables are stored in an encrypted format, reducing the risk of exposing sensitive data.
- **Ease of Use**: Encrypting and decrypting environment variables is as simple as calling a few functions.
- **Customization**: You can control the passwords used for key and nonce generation, giving you flexibility in how encryption is handled.
