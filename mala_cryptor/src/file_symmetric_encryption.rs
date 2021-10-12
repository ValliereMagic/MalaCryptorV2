use crate::global_constants::*;
use crate::key_derivation::key_derive_from_pass;
use sodiumoxide::crypto::pwhash::Salt;
use sodiumoxide::crypto::secretstream::{Header, Key, Stream, Tag, ABYTES, HEADERBYTES};
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind, Result};

// Password based functions
pub fn encrypt_file_with_password(
	file_in_path: &str,
	file_out_path: &str,
	password: &str,
) -> std::io::Result<()> {
	let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
	let (salt, key) = key_derive_from_pass(password, None);
	file_out.write_all(&salt.0)?;
	encrypt_file(&mut file_in, &mut file_out, key)
}

pub fn decrypt_file_with_password(
	file_in_path: &str,
	file_out_path: &str,
	password: &str,
) -> std::io::Result<()> {
	let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
	let mut salt = Salt([0u8; 32]);
	file_in.read_exact(&mut salt.0)?;
	let (_, key) = key_derive_from_pass(password, Some(salt));
	decrypt_file(&mut file_in, &mut file_out, key)
}
// Keyfile based functions
pub fn encrypt_file_with_key(file_in_path: &str, file_out_path: &str, key: Key) -> Result<()> {
	let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
	encrypt_file(&mut file_in, &mut file_out, key)
}

pub fn decrypt_file_with_key(file_in_path: &str, file_out_path: &str, key: Key) -> Result<()> {
	let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
	decrypt_file(&mut file_in, &mut file_out, key)
}
// Base functions
pub fn encrypt_file(file_in: &mut File, file_out: &mut File, key: Key) -> Result<()> {
	let (mut stream, header) =
		Stream::init_push(&key).expect("Unable to initialize encryption stream");
	// Figure out how many chunks we will iterate through
	let file_len = file_in.metadata().unwrap().len();
	let num_iterations = f64::ceil(file_len as f64 / CHUNK_SIZE as f64) as usize;
	// Write the stream header to the beginning of the encrypted file
	file_out.write_all(&header.0)?;
	let mut in_buff = [0u8; CHUNK_SIZE];
	let mut out_buff: Vec<u8> = Vec::new();
	for i in 0..num_iterations {
		let read_bytes = file_in.read(&mut in_buff)?;
		let tag = if i == num_iterations - 1 {
			Tag::Final
		} else {
			Tag::Message
		};
		stream
			.push_to_vec(&in_buff[0..read_bytes], None, tag, &mut out_buff)
			.expect("Unable to push message stream");
		file_out.write_all(&out_buff[..])?;
	}
	Ok(())
}

pub fn decrypt_file(file_in: &mut File, file_out: &mut File, key: Key) -> Result<()> {
	// Read in the stream header from the file to decrypt
	let mut header = Header([0u8; HEADERBYTES]);
	file_in.read_exact(&mut header.0)?;
	let mut stream =
		Stream::init_pull(&header, &key).expect("Unable to initialize decryption stream");
	let mut in_buff = [0u8; CHUNK_SIZE + ABYTES];
	let mut out_buff: Vec<u8> = Vec::new();
	while stream.is_not_finalized() {
		let read_bytes = file_in.read(&mut in_buff)?;
		match stream.pull_to_vec(&in_buff[0..read_bytes], None, &mut out_buff) {
			Ok(_) => (),
			Err(_) => {
				return Err(Error::new(
					ErrorKind::Other,
					"Error while decrypting file stream, possible tampering or bad key",
				));
			}
		};
		file_out.write_all(&out_buff[..])?;
	}
	Ok(())
}
