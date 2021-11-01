use crate::enc_algos_in_use::*;
use crate::file_symmetric_encryption::*;
use crate::global_constants::*;
use crate::key_file::*;
use sodiumoxide::crypto::generichash::{State, DIGEST_MAX};
use sodiumoxide::crypto::secretstream::{Key, KEYBYTES};
use std::convert::TryInto;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Result;
use std::io::SeekFrom;

// A: Shared Secret
// B: Ciphertext (Sometimes unused) could be unit
// C: public key
// D: our secret key
// E: Sig public key
// F: Sig secret key
// G: Signature
pub trait ICryptable<A, B, C, D, E, F, G> {
	// Shared secret based functions
	fn uses_cipher_text(&self) -> bool;
	fn create_shared_secret(&self, dest_pkey: &C, our_pkey: &C, our_skey: &D) -> (A, Option<B>);
	fn retrieve_shared_secret(
		&self,
		our_skey: &D,
		our_pkey: &C,
		sender_pkey: &C,
		ciphertext: Option<&B>,
	) -> A;
	// Serializers and Metadata
	fn ciphertext_to_bytes<'a>(&self, ct: &'a B) -> &'a [u8];
	fn shared_secret_to_bytes<'a>(&self, ss: &'a A) -> &'a [u8];
	// Signature based functions
	fn sign(&self, data: &[u8], key: &F) -> G;
	fn verify(&self, signature: &G, key: &E) -> bool;
	// Serializers and Metadata
	fn signature_length(&self) -> i64;
	fn signature_to_bytes<'a>(&self, signature: &'a G) -> &'a [u8];
	fn signature_from_bytes(&self, bytes: &[u8]) -> 
}

pub fn encrypt<A, B, C, D, E, F, G>(
	enc: impl ICryptable<A, B, C, D, E, F, G>,
	quad: impl IKeyQuad<E, C, F, D>,
	dest_pkey_path: &str,
	skey_path: &str,
	pkey_path: &str,
	file_in_path: &str,
	file_out_path: &str,
) -> Result<()> {
	let dest_pkey = quad.get_pub(dest_pkey_path)?;
	let skey = quad.get_sec(skey_path)?;
	let our_pub = quad.get_pub(pkey_path)?;
	// Derive the shared secret
	let (ss, ct) = enc.create_shared_secret(&dest_pkey.1, &our_pub.1, &skey.1);
	// Open up the files
	let (mut file_in, mut file_out) = (
		File::open(file_in_path)?,
		OpenOptions::new()
			.create(true)
			.read(true)
			.write(true)
			.truncate(true)
			.open(file_out_path)?,
	);
	// If there is a ciphertext, write it out to the file
	if let Some(ct) = ct {
		file_out.write_all(enc.ciphertext_to_bytes(&ct))?;
	}
	// Encrypt the source file with the shared secret, and write it to the out
	// file
	encrypt_file(
		&mut file_in,
		&mut file_out,
		Key(enc.shared_secret_to_bytes(&ss)[0..KEYBYTES]
			.try_into()
			.expect("Unable to turn shared secret into symmetric key")),
	)?;
	// Rewind the file back to the start
	file_out.rewind()?;
	// Digest, and sign the encrypted file
	let signature = enc.sign(&digest(&mut file_out, None)?, &skey.0);
	file_out.write_all(enc.signature_to_bytes(&signature))?;
	Ok(())
}

pub fn decrypt<A, B, C, D, E, F, G>(
	dec: impl ICryptable<A, B, C, D, E, F, G>,
	quad: impl IKeyQuad<E, C, F, D>,
	sender_pub_key_path: &str,
	skey_path: &str,
	pkey_path: &str,
	file_in_path: &str,
	file_out_path: &str,
) -> Result<()> {
	// Retrieve the required keys from files
	let sender_pkey = quad.get_pub(sender_pub_key_path)?;
	let skey = quad.get_sec(skey_path)?;
	let our_pkey = quad.get_pub(pkey_path)?;
	let (mut file_in, mut file_out) = (
		OpenOptions::new()
			.read(true)
			.write(true)
			.open(file_in_path)?,
		File::create(file_out_path)?,
	);
	// Seek to the beginning of the signature
	let signature_offset = dec.signature_length() as i64;
	file_in.seek(SeekFrom::End(-signature_offset))?;
	let mut buff = vec![0u8; signature_offset as usize];
	file_in.read_exact(&mut buff)?;
	Ok(())
}

fn digest(file: &mut File, signature_avoid: Option<i64>) -> Result<[u8; DIGEST_MAX]> {
	// Figure out how many chunks we will iterate through
	let mut file_len: i64 = file.metadata().unwrap().len() as i64;
	// If signature_avoid is present, decrease the file_len to remove the
	// signature from being read into the digest.
	if let Some(offset) = signature_avoid {
		file_len -= offset;
		if file_len <= 0 {
			panic!("Digesting negative or zero-sized file.");
		}
	}
	let mut state = State::new(Some(DIGEST_MAX), None).expect("Unable to create message state");
	let mut buff = [0u8; CHUNK_SIZE];
	// digest the file in chunks
	while file_len > 0 {
		// Only read what's left in the file
		let chunk_size = if file_len > CHUNK_SIZE as i64 {
			CHUNK_SIZE
		} else {
			file_len as usize
		};
		file.read_exact(&mut buff[0..chunk_size])?;
		// Add the bytes read to the digest
		state
			.update(&buff[0..chunk_size])
			.expect("Unable to update message state");
		// Remove the read bytes from file_len
		file_len -= chunk_size as i64;
	}
	Ok(
		state.finalize().expect("Unable to finalize message digest")[0..DIGEST_MAX]
			.try_into()
			.expect("Unable to finalize message digest"),
	)
}
