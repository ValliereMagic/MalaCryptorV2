use super::Create;
use super::SecretMem;
use libsodium_sys::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::Result;

const USIZE_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES: usize =
    libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;
pub type SodiumSymKey = SecretMem<USIZE_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES>;
// Symmetric key_file generation and retrieval using libsodium

// Generates a secretstream::KEYBYTES sized key_file and writes it into a
// new file at the key_file_path specified.
pub fn gen(key_file_path: &str) -> Result<()> {
    let mut key_file = File::create(&key_file_path)?;
    let mut key = SodiumSymKey::default();
    unsafe {
        randombytes_buf(key.as_mut_ptr() as *mut _, key.len());
    }
    key_file.write_all(key.as_ref())?;
    Ok(())
}
// Retrieves the first secretstream::KEYBYTES of the file passed at
// key_file_path, and returns them as a Key fit for SodiumOxide.
pub fn get(key_file_path: &str) -> Result<SodiumSymKey> {
    let mut key_file = File::open(&key_file_path)?;
    let mut key = SodiumSymKey::default();
    key_file.read_exact(key.as_mut())?;
    Ok(key)
}
