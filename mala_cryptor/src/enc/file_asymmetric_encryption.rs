use super::*;
use crate::chunked_file_reader::{ChunkStatus, ChunkedFileReader};
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
use std::marker::PhantomData;

// Generic functions required to asymmetrically encrypt a file using the
// AsyCryptor struct.
pub trait IAsyCryptable<
	KEMSharedSecret,
	KEMCipherText,
	KEMPublicKey,
	KEMSecretKey,
	SigPublicKey,
	SigSecretKey,
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
		dest_pkey: &KEMPublicKey,
		our_pkey: &KEMPublicKey,
		our_skey: &KEMSecretKey,
	) -> (KEMSharedSecret, Option<KEMCipherText>);
	// Retrieve the shared secret on the "receiver" side... used during the
	// decryption process
	fn retrieve_shared_secret(
		&self,
		our_skey: &KEMSecretKey,
		our_pkey: &KEMPublicKey,
		sender_pkey: &KEMPublicKey,
		ciphertext: Option<&KEMCipherText>,
	) -> KEMSharedSecret;
	// Serializers and Metadata
	fn ciphertext_to_bytes<'a>(&self, ct: &'a KEMCipherText) -> &'a [u8];
	fn ciphertext_from_bytes(&self, bytes: &[u8]) -> KEMCipherText;
	fn ciphertext_length(&self) -> usize;
	fn shared_secret_to_bytes<'a>(&self, ss: &'a KEMSharedSecret) -> &'a [u8];
	// Signature based functions
	fn sign(&self, data: &[u8], key: &SigSecretKey) -> Signature;
	fn verify(&self, message: &[u8], signature: &Signature, key: &SigPublicKey) -> bool;
	// Serializers and Metadata
	fn signature_length(&self) -> i64;
	fn signature_to_bytes<'a>(&self, signature: &'a Signature) -> &'a [u8];
	fn signature_from_bytes(&self, bytes: &[u8]) -> Signature;
}

pub struct AsyCryptor<
	KEMSharedSecret,
	KEMCipherText,
	KEMPublicKey,
	KEMSecretKey,
	SigPublicKey,
	SigSecretKey,
	Signature,
	Cryptable,
> where
	Cryptable: IKeyQuad<SigPublicKey, SigSecretKey, KEMPublicKey, KEMSecretKey>
		+ IAsyCryptable<
			KEMSharedSecret,
			KEMCipherText,
			KEMPublicKey,
			KEMSecretKey,
			SigPublicKey,
			SigSecretKey,
			Signature,
		>,
{
	crypt: Cryptable,
	p1: PhantomData<KEMSharedSecret>,
	p2: PhantomData<KEMCipherText>,
	p3: PhantomData<KEMPublicKey>,
	p4: PhantomData<KEMSecretKey>,
	p5: PhantomData<SigPublicKey>,
	p6: PhantomData<SigSecretKey>,
	p7: PhantomData<Signature>,
}

impl<
		KEMSharedSecret,
		KEMCipherText,
		KEMPublicKey,
		KEMSecretKey,
		SigPublicKey,
		SigSecretKey,
		Signature,
		Cryptable,
	>
	AsyCryptor<
		KEMSharedSecret,
		KEMCipherText,
		KEMPublicKey,
		KEMSecretKey,
		SigPublicKey,
		SigSecretKey,
		Signature,
		Cryptable,
	> where
	Cryptable: IKeyQuad<SigPublicKey, SigSecretKey, KEMPublicKey, KEMSecretKey>
		+ IAsyCryptable<
			KEMSharedSecret,
			KEMCipherText,
			KEMPublicKey,
			KEMSecretKey,
			SigPublicKey,
			SigSecretKey,
			Signature,
		>,
{
	pub fn new(
		crypt: Cryptable,
	) -> AsyCryptor<
		KEMSharedSecret,
		KEMCipherText,
		KEMPublicKey,
		KEMSecretKey,
		SigPublicKey,
		SigSecretKey,
		Signature,
		Cryptable,
	> {
		AsyCryptor {
			crypt,
			p1: PhantomData,
			p2: PhantomData,
			p3: PhantomData,
			p4: PhantomData,
			p5: PhantomData,
			p6: PhantomData,
			p7: PhantomData,
		}
	}
	pub fn encrypt_file(
		&self,
		dest_pkey_path: &str,
		skey_path: &str,
		pkey_path: &str,
		file_in_path: &str,
		file_out_path: &str,
	) -> Result<()> {
		let dest_pkey = self.crypt.get_pub(dest_pkey_path)?;
		let skey = self.crypt.get_sec(skey_path)?;
		let our_pub = self.crypt.get_pub(pkey_path)?;
		// Derive the shared secret
		let (ss, ct) = self
			.crypt
			.create_shared_secret(&dest_pkey.1, &our_pub.1, &skey.1);
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
			file_out.write_all(self.crypt.ciphertext_to_bytes(&ct))?;
		}
		// Encrypt the source file with the shared secret, and write it to the out
		// file
		encrypt_file(
			&mut file_in,
			&mut file_out,
			Key(self.crypt.shared_secret_to_bytes(&ss)[0..KEYBYTES]
				.try_into()
				.expect("Unable to turn shared secret into symmetric key")),
		)?;
		// Rewind the file back to the start
		file_out.rewind()?;
		// Digest, and sign the encrypted file
		let signature = self.crypt.sign(&digest(&mut file_out, None)?, &skey.0);
		file_out.write_all(self.crypt.signature_to_bytes(&signature))?;
		Ok(())
	}

	pub fn decrypt_file(
		&self,
		sender_pub_key_path: &str,
		skey_path: &str,
		pkey_path: &str,
		file_in_path: &str,
		file_out_path: &str,
	) -> Result<()> {
		// Retrieve the required keys from files
		let sender_pkey = self.crypt.get_pub(sender_pub_key_path)?;
		let skey = self.crypt.get_sec(skey_path)?;
		let our_pkey = self.crypt.get_pub(pkey_path)?;
		let (mut file_in, mut file_out) = (
			OpenOptions::new()
				.read(true)
				.write(true)
				.open(file_in_path)?,
			File::create(file_out_path)?,
		);
		// Seek to the beginning of the signature
		let signature_offset = self.crypt.signature_length();
		file_in.seek(SeekFrom::End(-signature_offset))?;
		let mut buff = vec![0u8; signature_offset as usize];
		file_in.read_exact(&mut buff)?;
		let signature = self.crypt.signature_from_bytes(&buff);
		// Seek back to the beginning of the file
		file_in.rewind()?;
		// Digest the file up to the signature
		let digest = digest(&mut file_in, Some(signature_offset))?;
		// Check whether the signature matches
		match self.crypt.verify(&digest, &signature, &sender_pkey.0) {
			true => (),
			false => panic!("Signature is bad. Not attempting to decrypt file. Aborting."),
		}
		// Truncate the signature from the end of the file
		file_in.set_len((file_in.metadata().unwrap().len() as i64 - signature_offset) as u64)?;
		// Rewind the file to the beginning
		file_in.rewind()?;
		// Read in the key exchange ciphertext if there is one
		let ct = if self.crypt.uses_cipher_text() {
			let mut kem_ct_buff = vec![0u8; self.crypt.ciphertext_length()];
			file_in.read_exact(&mut kem_ct_buff)?;
			Some(self.crypt.ciphertext_from_bytes(&kem_ct_buff))
		} else {
			None
		};
		// Derive the shared secret
		let ss =
			self.crypt
				.retrieve_shared_secret(&skey.1, &our_pkey.1, &sender_pkey.1, ct.as_ref());
		// Our file pointer is at the beginning of the encrypted file, and we have
		// removed the signature from the end. Time to finally decrypt the file
		decrypt_file(
			&mut file_in,
			&mut file_out,
			Key(self.crypt.shared_secret_to_bytes(&ss)[0..KEYBYTES]
				.try_into()
				.expect("Unable to turn shared secret into symmetric key.")),
		)?;
		// Remove the encrypted in-file; it was modified in the decryption procedure.
		fs::remove_file(file_in_path)?;
		Ok(())
	}
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
	let mut chunked_reader = ChunkedFileReader::new(file, CHUNK_SIZE as u64, Some(file_len as u64));
	let mut state = State::new(Some(DIGEST_MAX), None).expect("Unable to create message state");
	let mut buff = [0u8; CHUNK_SIZE];
	// digest the file in chunks
	let mut finalized = false;
	while !finalized {
		let chunk_size = match chunked_reader.read_chunk(&mut buff)? {
			ChunkStatus::Body => CHUNK_SIZE,
			ChunkStatus::Final(c) => {
				finalized = true;
				c as usize
			}
			ChunkStatus::Err(e) => panic!("{}", e),
		};
		// Add the bytes read to the digest
		state
			.update(&buff[..chunk_size])
			.expect("Unable to update message state");
	}
	Ok(
		state.finalize().expect("Unable to finalize message digest")[0..DIGEST_MAX]
			.try_into()
			.expect("Unable to finalize message digest"),
	)
}
