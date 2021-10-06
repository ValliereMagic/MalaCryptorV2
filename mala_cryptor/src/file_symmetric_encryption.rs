use crate::key_derivation::key_derive_from_pass;
use sodiumoxide::crypto::pwhash::Salt;
use sodiumoxide::crypto::secretstream::{Header, Key, Stream, Tag, ABYTES, HEADERBYTES};
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind, Result};

const CHUNK_SIZE: usize = 4096;

// Password based functions
pub fn encrypt_file_with_password(
	file_in_path: &str,
	file_out_path: &str,
	password: &str,
) -> std::io::Result<()> {
	let (file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
	let (salt, key) = key_derive_from_pass(password, None);
	file_out.write_all(&salt.0)?;
	encrypt_file(file_in, file_out, key)
}

pub fn decrypt_file_with_password(
	file_in_path: &str,
	file_out_path: &str,
	password: &str,
) -> std::io::Result<()> {
	let (mut file_in, file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
	let mut salt = Salt([0u8; 32]);
	file_in.read_exact(&mut salt.0)?;
	let (_, key) = key_derive_from_pass(password, Some(salt));
	decrypt_file(file_in, file_out, key)
}
// Keyfile based functions (TODO)

// Base functions
fn encrypt_file(mut file_in: File, mut file_out: File, key: Key) -> Result<()> {
	let (mut stream, header) =
		Stream::init_push(&key).expect("Unable to initialize encryption stream");
	// Write the stream header to the beginning of the encrypted file
	file_out.write_all(&header.0)?;
	let mut in_buff = [0u8; CHUNK_SIZE];
	let mut out_buff: Vec<u8> = Vec::new();
	loop {
		let read_bytes = file_in.read(&mut in_buff)?;
		if read_bytes == 0 {
			break;
		};
		let tag = if read_bytes == CHUNK_SIZE {
			Tag::Message
		} else {
			Tag::Final
		};
		stream
			.push_to_vec(&in_buff[0..read_bytes], None, tag, &mut out_buff)
			.expect("Unable to push message stream");
		file_out.write_all(&out_buff[..])?;
	}
	Ok(())
}

fn decrypt_file(mut file_in: File, mut file_out: File, key: Key) -> Result<()> {
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
