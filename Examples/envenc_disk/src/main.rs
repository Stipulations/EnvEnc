// This example is just to show a "redundant"(i dont know the right terms but you will be fine) encryption so you can port
// this to what ever you want to do but tldr it generates keys saves to disk then uses keys from disk if they exist
// 
// Dont use in prodiction please and thank you, have a great day!

use envenc::{decrypt_env, keys_generation, read_env, read_env_enc, set_enc_env, CipherType};
use std::fs;

fn main() {
    let cipher_type = CipherType::ChaCha20Poly1305;

    let (key, nonce) = if let Ok(file_content) = fs::read_to_string("key_nonce.txt") {
        let mut lines = file_content.lines();
        let key_hex = lines.next().expect("Missing key");
        let nonce_hex = lines.next().expect("Missing nonce");
        (hex::decode(key_hex).expect("Invalid key hex"), hex::decode(nonce_hex).expect("Invalid nonce hex"))
    } else {
        let (key, nonce) = keys_generation(cipher_type);
        println!("Key: {:?} Nonce: {:?}", key, nonce);
        set_key_nonce_to_disk(&key, &nonce);
        (key, nonce)
    };

    set_enc_env("DATABASE_URL", "postgres://user:password@localhost/db", cipher_type, &key, &nonce);
    set_enc_env("API_KEY", "super_secret_api_key", cipher_type, &key, &nonce);
    set_enc_env("CACHE_SERVER", "redis://localhost:6379", cipher_type, &key, &nonce);

    let encrypted_env = read_env_enc();

    decrypt_env(encrypted_env, cipher_type, &key, &nonce);

    let database_url = read_env("DATABASE_URL").unwrap_or("DATABASE_URL not found".to_string());
    let api_key = read_env("API_KEY").unwrap_or("API_KEY not found".to_string());
    let cache_server = read_env("CACHE_SERVER").unwrap_or("CACHE_SERVER not found".to_string());

    println!("Database URL: {}", database_url);
    println!("API Key: {}", api_key);
    println!("Cache Server: {}", cache_server);
}

fn set_key_nonce_to_disk(key: &[u8], nonce: &[u8]) {
    let content = format!("{}\n{}", hex::encode(key), hex::encode(nonce));
    fs::write("key_nonce.txt", content).expect("Unable to write key and nonce to disk");
}