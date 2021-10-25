use sodiumoxide::crypto::{secretstream::gen_key, secretstream::Key, secretstream::KEYBYTES};
use std::fs::File;
use std::io::prelude::*;
use std::io::Result;
// Generates a secretstream::KEYBYTES sized key_file and writes it into a
// new file at the key_file_path specified.
pub fn gen(key_file_path: &str) -> Result<()> {
	let mut key_file = File::create(&key_file_path)?;
	let key = gen_key();
	key_file.write_all(&key.0)?;
	Ok(())
}
// Retrieves the first secretstream::KEYBYTES of the file passed at
// key_file_path, and returns them as a Key fit for SodiumOxide.
pub fn get(key_file_path: &str) -> Result<Key> {
	let mut key_file = File::open(&key_file_path)?;
	let mut key = Key([0u8; KEYBYTES]);
	key_file.read_exact(&mut key.0)?;
	Ok(key)
}
