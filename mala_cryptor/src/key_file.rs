use kem::Kem;
use oqs::kem;
use oqs::sig;
use sig::Sig;
use sodiumoxide::crypto::{
	kx, secretstream::gen_key, secretstream::Key, secretstream::KEYBYTES, sign,
};
use std::fs::File;
use std::io::prelude::*;
use std::io::Result;

pub fn gen_symmetric_keyfile(key_file_path: &str) -> Result<()> {
	sodiumoxide::init().expect("Unable to initialize libsodium.");
	let mut key_file = File::create(&key_file_path)?;
	let key = gen_key();
	key_file.write_all(&key.0)?;
	Ok(())
}

pub fn get_symmetric_keyfile(key_file_path: &str) -> Result<Key> {
	let mut key_file = File::open(&key_file_path)?;
	let mut key = Key([0u8; KEYBYTES]);
	key_file.read_exact(&mut key.0)?;
	Ok(key)
}

// File format:
// [qkey][classical_key]
// where:
// qkey: [q_sig_key][q_kem_key]
// classical_key: [c_sig_key][c_kem_key]
pub fn gen_hybrid_keypair(pkey_path: &str, skey_path: &str) -> Result<()> {
	let (mut pkey_f, mut skey_f) = (File::create(pkey_path)?, File::create(skey_path)?);
	quantum(&mut pkey_f, &mut skey_f)?;
	classical(&mut pkey_f, &mut skey_f)?;
	Ok(())
}

pub fn gen_quantum_keypair(pkey_path: &str, skey_path: &str) -> Result<()> {
	let (mut pkey_f, mut skey_f) = (File::create(pkey_path)?, File::create(skey_path)?);
	quantum(&mut pkey_f, &mut skey_f)
}

pub fn gen_classical_keypair(pkey_path: &str, skey_path: &str) -> Result<()> {
	let (mut pkey_f, mut skey_f) = (File::create(pkey_path)?, File::create(skey_path)?);
	classical(&mut pkey_f, &mut skey_f)
}

fn quantum(pkey_f: &mut File, skey_f: &mut File) -> Result<()> {
	oqs::init();
	let kem = Kem::new(kem::Algorithm::ClassicMcEliece6688128f)
		.expect("Unable to acquire quantum KEM algo.");
	let sig = Sig::new(sig::Algorithm::Dilithium5).expect("Unable to acquire quantum SIG algo.");
	let (sig_pkey, sig_skey) = sig
		.keypair()
		.expect("Unable to generate quantum signature keypair.");
	let (pkey, skey) = kem.keypair().expect("Unable to generate quantum keypair.");
	pkey_f.write_all(&sig_pkey.into_vec())?;
	pkey_f.write_all(&pkey.into_vec())?;
	skey_f.write_all(&sig_skey.into_vec())?;
	skey_f.write_all(&skey.into_vec())?;
	Ok(())
}

fn classical(pkey_f: &mut File, skey_f: &mut File) -> Result<()> {
	sodiumoxide::init().expect("Unable to initialize libsodium.");
	let (sig_pkey, sig_skey) = sign::gen_keypair();
	let (pkey, skey) = kx::gen_keypair();
	pkey_f.write_all(&sig_pkey.0)?;
	pkey_f.write_all(&pkey.0)?;
	skey_f.write_all(&sig_skey.0)?;
	skey_f.write_all(&skey.0)?;
	Ok(())
}
