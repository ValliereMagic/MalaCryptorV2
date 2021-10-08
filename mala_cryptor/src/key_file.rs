use oqs::kem::{Algorithm, Kem};
use sodiumoxide::crypto::kx;
use std::fs::File;
use std::io::prelude::*;
use std::io::Result;

// File format:
// [qkey][classical_key]
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
	let kem =
		Kem::new(Algorithm::ClassicMcEliece6688128f).expect("Unable to acquire quantum KEM algo.");
	let (pkey, skey) = kem.keypair().expect("Unable to generate quantum keypair.");
	pkey_f.write_all(&pkey.into_vec())?;
	skey_f.write_all(&skey.into_vec())?;
	Ok(())
}

fn classical(pkey_f: &mut File, skey_f: &mut File) -> Result<()> {
	sodiumoxide::init().expect("Unable to initialize libsodium.");
	let (pkey, skey) = kx::gen_keypair();
	pkey_f.write_all(&pkey.0)?;
	skey_f.write_all(&skey.0)?;
	Ok(())
}
