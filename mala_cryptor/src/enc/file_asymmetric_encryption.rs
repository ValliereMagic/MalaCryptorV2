use super::*;
use crate::global_constants::*;
use crate::key_file::*;
use sodiumoxide::crypto::generichash::{State, DIGEST_MAX};
use sodiumoxide::crypto::secretstream::{Key, KEYBYTES};
use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Result;
use std::io::SeekFrom;

pub trait IAsyCryptable<
	SharedSecret,
	CipherText,
	PublicKey,
	SecretKey,
	SigPublic,
	SigSecret,
	Signature,
>
{
	// Shared secret based functions
	// Specifies whether this IAsyCryptable key exchange mechanism uses a
	// ciphertext for acquiring a shared secret
	fn uses_cipher_text(&self) -> bool;
	// Create a shared secret on the "sender" side... used during the encryption
	// process
	fn create_shared_secret(
		&self,
		dest_pkey: &PublicKey,
		our_pkey: &PublicKey,
		our_skey: &SecretKey,
	) -> (SharedSecret, Option<CipherText>);
	// Retrieve the shared secret on the "receiver" side... used during the
	// decryption process
	fn retrieve_shared_secret(
		&self,
		our_skey: &SecretKey,
		our_pkey: &PublicKey,
		sender_pkey: &PublicKey,
		ciphertext: Option<&CipherText>,
	) -> SharedSecret;
	// Serializers and Metadata
	fn ciphertext_to_bytes<'a>(&self, ct: &'a CipherText) -> &'a [u8];
	fn ciphertext_from_bytes(&self, bytes: &[u8]) -> CipherText;
	fn ciphertext_length(&self) -> usize;
	fn shared_secret_to_bytes<'a>(&self, ss: &'a SharedSecret) -> &'a [u8];
	// Signature based functions
	fn sign(&self, data: &[u8], key: &SigSecret) -> Signature;
	fn verify(&self, message: &[u8], signature: &Signature, key: &SigPublic) -> bool;
	// Serializers and Metadata
	fn signature_length(&self) -> i64;
	fn signature_to_bytes<'a>(&self, signature: &'a Signature) -> &'a [u8];
	fn signature_from_bytes(&self, bytes: &[u8]) -> Signature;
}

pub fn asy_encrypt_file<
	SharedSecret,
	CipherText,
	PublicKey,
	SecretKey,
	SigPublic,
	SigSecret,
	Signature,
>(
	quad: impl IKeyQuad<SigPublic, PublicKey, SigSecret, SecretKey>
		+ IAsyCryptable<
			SharedSecret,
			CipherText,
			PublicKey,
			SecretKey,
			SigPublic,
			SigSecret,
			Signature,
		>,
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
	let (ss, ct) = quad.create_shared_secret(&dest_pkey.1, &our_pub.1, &skey.1);
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
		file_out.write_all(quad.ciphertext_to_bytes(&ct))?;
	}
	// Encrypt the source file with the shared secret, and write it to the out
	// file
	encrypt_file(
		&mut file_in,
		&mut file_out,
		Key(quad.shared_secret_to_bytes(&ss)[0..KEYBYTES]
			.try_into()
			.expect("Unable to turn shared secret into symmetric key")),
	)?;
	// Rewind the file back to the start
	file_out.rewind()?;
	// Digest, and sign the encrypted file
	let signature = quad.sign(&digest(&mut file_out, None)?, &skey.0);
	file_out.write_all(quad.signature_to_bytes(&signature))?;
	Ok(())
}

pub fn asy_decrypt_file<
	SharedSecret,
	CipherText,
	PublicKey,
	SecretKey,
	SigPublic,
	SigSecret,
	Signature,
>(
	quad: impl IKeyQuad<SigPublic, PublicKey, SigSecret, SecretKey>
		+ IAsyCryptable<
			SharedSecret,
			CipherText,
			PublicKey,
			SecretKey,
			SigPublic,
			SigSecret,
			Signature,
		>,
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
	let signature_offset = quad.signature_length();
	file_in.seek(SeekFrom::End(-signature_offset))?;
	let mut buff = vec![0u8; signature_offset as usize];
	file_in.read_exact(&mut buff)?;
	let signature = quad.signature_from_bytes(&buff);
	// Seek back to the beginning of the file
	file_in.rewind()?;
	// Digest the file up to the signature
	let digest = digest(&mut file_in, Some(signature_offset))?;
	// Check whether the signature matches
	match quad.verify(&digest, &signature, &sender_pkey.0) {
		true => (),
		false => panic!("Signature is bad. Not attempting to decrypt file. Aborting."),
	}
	// Truncate the signature from the end of the file
	file_in.set_len((file_in.metadata().unwrap().len() as i64 - signature_offset) as u64)?;
	// Rewind the file to the beginning
	file_in.rewind()?;
	// Read in the key exchange ciphertext if there is one
	let ct = if quad.uses_cipher_text() {
		let mut kem_ct_buff = vec![0u8; quad.ciphertext_length()];
		file_in.read_exact(&mut kem_ct_buff)?;
		Some(quad.ciphertext_from_bytes(&kem_ct_buff))
	} else {
		None
	};
	// Derive the shared secret
	let ss = quad.retrieve_shared_secret(&skey.1, &our_pkey.1, &sender_pkey.1, ct.as_ref());
	// Our file pointer is at the beginning of the encrypted file, and we have
	// removed the signature from the end. Time to finally decrypt the file
	decrypt_file(
		&mut file_in,
		&mut file_out,
		Key(quad.shared_secret_to_bytes(&ss)[0..KEYBYTES]
			.try_into()
			.expect("Unable to turn shared secret into symmetric key.")),
	)?;
	// Remove the encrypted in-file; it was modified in the decryption procedure.
	fs::remove_file(file_in_path)?;
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