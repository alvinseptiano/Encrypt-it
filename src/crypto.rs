use chacha20poly1305::{
    aead::Aead,
    XChaCha20Poly1305,
    KeyInit,
};

use std::fs;
use anyhow::anyhow;

pub struct Crypto {
}

impl Crypto {
    pub fn encrypt(path: &String, key: &[u8; 32], nonce: &[u8; 24]) -> Result<(), anyhow::Error> {
        println!("{}", path);
        let cipher = XChaCha20Poly1305::new(key.into());
        let file_data = fs::read(path)?;
        let encrypted_file = cipher
            .encrypt(nonce.into(), file_data.as_ref())
            .map_err(|err| anyhow!("Encrypting small file: {}", err))?;
        fs::write(format!("{}", path), encrypted_file)?;
        Ok(())
    }

    pub fn decrypt(path: &String, key: &[u8; 32], nonce: &[u8; 24],) -> Result<(), anyhow::Error> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let file_data = fs::read(&path)?;
        let decrypted_file = cipher
            .decrypt(nonce.into(), file_data.as_ref())
            .map_err(|err| anyhow!("Decrypting small file: {}", err))?;
        fs::write(format!("{}", path.trim_end_matches(".encrypted")), decrypted_file)?;
        Ok(())
    }
}
