use crate::enc_algos_in_use::*;
use crate::file_symmetric_encryption::*;
use crate::global_constants::*;
use crate::key_file::key_file::*;
use crate::key_file::*;
use oqs::kem;
use oqs::sig;
use sodiumoxide::crypto::generichash::{State, DIGEST_MAX};
use sodiumoxide::crypto::secretstream::{Key, KEYBYTES};
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind, Result};

pub fn encrypt_quantum(
	dest_pkey_path: &str,
	skey_path: &str,
	pkey_path: &str,
	file_in_path: &str,
	file_out_path: &str,
) -> Result<()> {
	let q = quantum::QuantumKeyQuad::new();
	let dest_pkey = q.get_pub(dest_pkey_path)?;
	let skey = q.get_sec(skey_path)?;
	let pkey = q.get_pub(pkey_path)?;
	let kem = get_q_kem_algo();
	let (ct, ss) = kem.encapsulate(&dest_pkey.1).unwrap();
	let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
	file_out.write_all(&ct.into_vec())?;
	encrypt_file(
		&mut file_in,
		&mut file_out,
		Key(ss.into_vec()[0..KEYBYTES]
			.try_into()
			.expect("Unable to turn shared secret into symmetric key")),
	)?;
	let sig = get_q_sig_algo();
	let signature = sig
		.sign(
			&digest(&mut file_out).expect("Unable to digest encrypted file")[..],
			&skey.0,
		)
		.expect("Unable to sign digest");
	unimplemented!();
}

fn digest(file: &mut File) -> Result<[u8; DIGEST_MAX]> {
	// Figure out how many chunks we will iterate through
	let file_len = file.metadata().unwrap().len();
	let num_iterations = f64::ceil(file_len as f64 / CHUNK_SIZE as f64) as usize;
	let mut state = State::new(Some(DIGEST_MAX), None).expect("Unable to create message state");
	let mut buff = [0u8; CHUNK_SIZE];
	// digest the file in chunks
	for _ in 0..num_iterations {
		let read_bytes = file.read(&mut buff)?;
		state
			.update(&buff[0..read_bytes])
			.expect("Unable to update message state");
	}
	Ok(
		state.finalize().expect("Unable to finalize message digest")[0..DIGEST_MAX]
			.try_into()
			.expect("Unable to finalize message digest"),
	)
}
