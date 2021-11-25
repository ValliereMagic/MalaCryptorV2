use crate::chunked_file_reader::*;
use crate::global_constants::*;
use crate::key_derivation;
use crate::key_derivation::key_derive_from_pass;
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
	file_out.write_all(&salt)?;
	encrypt_file(&mut file_in, &mut file_out, Key(key))
}

pub fn decrypt_file_with_password(
	file_in_path: &str,
	file_out_path: &str,
	password: &str,
) -> std::io::Result<()> {
	let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
	let mut salt = key_derivation::SodiumSalt::default();
	file_in.read_exact(&mut salt)?;
	let (_, key) = key_derive_from_pass(password, Some(salt));
	decrypt_file(&mut file_in, &mut file_out, Key(key))
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
	// Write the stream header to the beginning of the encrypted file
	file_out.write_all(&header.0)?;
	let mut in_buff = [0u8; CHUNK_SIZE];
	let mut chunked_reader = ChunkedFileReader::new(file_in, in_buff.len() as u64, None);
	let mut out_buff: Vec<u8> = Vec::new();
	let mut finalized = false;
	while !finalized {
		let (tag, read_bytes) = match chunked_reader.read_chunk(&mut in_buff)? {
			ChunkStatus::Body => (Tag::Message, in_buff.len()),
			ChunkStatus::Final(s) => {
				finalized = true;
				(Tag::Final, s as usize)
			}
			ChunkStatus::Err(e) => panic!("{}", e),
		};
		stream
			.push_to_vec(&in_buff[..read_bytes], None, tag, &mut out_buff)
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
	// Find out how far into the file we are currently seeked, and subtract that
	// from the total, to find out how much of the file is left.
	let distance_into_file = file_in.metadata().unwrap().len() - file_in.stream_position().unwrap();
	let mut chunked_reader =
		ChunkedFileReader::new(file_in, in_buff.len() as u64, Some(distance_into_file));
	let mut finalized = false;
	while !finalized {
		let read_bytes = match chunked_reader.read_chunk(&mut in_buff)? {
			ChunkStatus::Body => in_buff.len(),
			ChunkStatus::Final(s) => {
				finalized = true;
				s as usize
			}
			ChunkStatus::Err(e) => panic!("{}", e),
		};
		match stream.pull_to_vec(&in_buff[..read_bytes], None, &mut out_buff) {
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
