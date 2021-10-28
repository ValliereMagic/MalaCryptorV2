use crate::enc_algos_in_use::*;
use crate::file_symmetric_encryption::*;
use crate::global_constants::*;
use crate::key_file::*;
use oqs::kem;
use oqs::sig;
use sodiumoxide::crypto::generichash::{State, DIGEST_MAX};
use sodiumoxide::crypto::secretstream::{Key, KEYBYTES};
use std::convert::TryInto;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::{Error, ErrorKind, Result};

pub fn encrypt_quantum(
	dest_pkey_path: &str,
	skey_path: &str,
	pkey_path: &str,
	file_in_path: &str,
	file_out_path: &str,
) -> Result<()> {
	let q = QuantumKeyQuad::new();
	// Retrieve the required keys from files
	let dest_pkey = q.get_pub(dest_pkey_path)?;
	let skey = q.get_sec(skey_path)?;
	let pkey = q.get_pub(pkey_path)?;
	let kem = get_q_kem_algo();
	// Derive the shared secret
	let (ct, ss) = kem.encapsulate(&dest_pkey.1).unwrap();
	let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
	// Write out the ciphertext of the shared secret into the file
	file_out.write_all(ct.as_ref())?;
	// Encrypt the source file with the shared secret, and write it to the out
	// file
	encrypt_file(
		&mut file_in,
		&mut file_out,
		Key(ss.as_ref()[0..KEYBYTES]
			.try_into()
			.expect("Unable to turn shared secret into symmetric key")),
	)?;
	// Digest, and sign the encrypted file
	let sig = get_q_sig_algo();
	let signature = sig
		.sign(
			&digest(&mut file_out, None).expect("Unable to digest encrypted file")[..],
			&skey.0,
		)
		.expect("Unable to sign digest");
	// Write the signature to the encrypted file
	file_out.write_all(signature.as_ref())?;
	Ok(())
}

pub fn decrypt_quantum(
	sender_pub_key_path: &str,
	skey_path: &str,
	pkey_path: &str,
	file_in_path: &str,
	file_out_path: &str,
) -> Result<()> {
	let q = QuantumKeyQuad::new();
	// Retrieve the required keys from files
	let sender_pkey = q.get_pub(sender_pub_key_path)?;
	let skey = q.get_sec(skey_path)?;
	let pkey = q.get_pub(pkey_path)?;
	let (mut file_in, mut file_out) = (
		OpenOptions::new()
			.read(true)
			.write(true)
			.open(file_in_path)?,
		File::create(file_out_path)?,
	);
	// Seek to the signature and pull it in
	let sig = get_q_sig_algo();
	// Seek to the beginning of the signature
	let signature_offset = -(sig.length_signature() as i64);
	file_in.seek(SeekFrom::End(signature_offset))?;
	let mut buff = vec![0u8; sig.length_signature()];
	file_in.read_exact(&mut buff)?;
	let signature = sig
		.signature_from_bytes(&buff)
		.expect("Unable to extract signature from file.");
	// Seek back to the beginning of the file
	file_in.seek(SeekFrom::Start(0))?;
	// Digest the file up to the signature
	let digest = digest(&mut file_in, Some(signature_offset))?;
	// Check whether the signature matches
	match sig.verify(&digest, signature, &sender_pkey.0) {
		Ok(()) => (),
		Err(_) => panic!("Signature is bad. Not attempting to decrypt file. Aborting."),
	}
	// Truncate the signature from the end of the file
	file_in.set_len((file_in.metadata().unwrap().len() as i64 + signature_offset) as u64)?;
	// Seek back to the beginning of the file
	file_in.seek(SeekFrom::Start(0))?;
	let kem = get_q_kem_algo();
	// Read in the key exchange ciphertext
	let mut kem_ct_buff = vec![0u8; kem.length_ciphertext()];
	file_in.read_exact(&mut kem_ct_buff)?;
	let ct = kem
		.ciphertext_from_bytes(&kem_ct_buff)
		.expect("Unable to extract KEM ciphertext from file.");
	// Derive the shared secret
	let ss = kem
		.decapsulate(&skey.1, &ct)
		.expect("Unable to get shared secret.");
	// Our file pointer is at the beginning of the encrypted file, and we have
	// removed the signature from the end. Time to finally decrypt the file
	decrypt_file(
		&mut file_in,
		&mut file_out,
		Key(ss.as_ref()[0..32]
			.try_into()
			.expect("Unable to turn shared secret into symmetric key.")),
	)?;
	Ok(())
}

fn digest(file: &mut File, signature_avoid: Option<i64>) -> Result<[u8; DIGEST_MAX]> {
	// Figure out how many chunks we will iterate through
	let mut file_len: u64 = file.metadata().unwrap().len();
	// If signature_avoid is present, decrease the file_len to remove the
	// signature from being read into the digest.
	if let Some(offset) = signature_avoid {
		let file_len_i = (file_len as i64) + offset;
		if file_len_i <= 0 {
			panic!("Digesting negative or zero-sized file.");
		}
		file_len = file_len_i as u64;
	}
	let mut state = State::new(Some(DIGEST_MAX), None).expect("Unable to create message state");
	let mut buff = [0u8; CHUNK_SIZE];
	// digest the file in chunks
	while file_len > 0 {
		// Only read what's left in the file
		let chunk_size = if file_len >= CHUNK_SIZE as u64 {
			CHUNK_SIZE
		} else {
			CHUNK_SIZE - file_len as usize
		};
		let read_bytes = file.read(&mut buff[0..chunk_size])?;
		// Add the bytes read to the digest
		state
			.update(&buff[0..read_bytes])
			.expect("Unable to update message state");
		// Remove the read bytes from file_len
		file_len -= read_bytes as u64;
	}
	Ok(
		state.finalize().expect("Unable to finalize message digest")[0..DIGEST_MAX]
			.try_into()
			.expect("Unable to finalize message digest"),
	)
}
