use libsodium_sys::*;
use std::ffi;
use std::fs::File;
use std::io::prelude::*;
use std::io::Result;
pub type SodiumSymKey =
	[u8; libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize];
// Symmetric key_file generation and retrieval using libsodium

// Generates a secretstream::KEYBYTES sized key_file and writes it into a
// new file at the key_file_path specified.
pub fn gen(key_file_path: &str) -> Result<()> {
	let mut key_file = File::create(&key_file_path)?;
	let mut key = SodiumSymKey::default();
	unsafe {
		randombytes_buf(key.as_mut_ptr() as *mut ffi::c_void, key.len());
	}
	key_file.write_all(&key)?;
	Ok(())
}
// Retrieves the first secretstream::KEYBYTES of the file passed at
// key_file_path, and returns them as a Key fit for SodiumOxide.
pub fn get(key_file_path: &str) -> Result<SodiumSymKey> {
	let mut key_file = File::open(&key_file_path)?;
	let mut key = SodiumSymKey::default();
	key_file.read_exact(&mut key)?;
	Ok(key)
}
