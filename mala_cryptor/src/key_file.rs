use crate::enc_algos_in_use::*;
use kem::Kem;
use oqs::kem;
use oqs::sig;
use sig::Sig;
use sodiumoxide::crypto::{
	kx, secretstream::gen_key, secretstream::Key, secretstream::KEYBYTES, sign,
};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Result;
use std::io::SeekFrom;

pub mod symmetric {
	use super::*;
	// Generates a secretstream::KEYBYTES sized key_file and writes it into a
	// new file at the key_file_path specified.
	pub fn gen(key_file_path: &str) -> Result<()> {
		let mut key_file = File::create(&key_file_path)?;
		let key = gen_key();
		key_file.write_all(&key.0)?;
		Ok(())
	}
	// Retrieves the first secretstream::KEYBYTES of the file passed at
	// key_file_path, and returns them as a Key fit for SodiumOxide.
	pub fn get(key_file_path: &str) -> Result<Key> {
		let mut key_file = File::open(&key_file_path)?;
		let mut key = Key([0u8; KEYBYTES]);
		key_file.read_exact(&mut key.0)?;
		Ok(key)
	}
}

// Acquire the active signature or key exchange algorithm for OQS. Defined in
// one place to reduce code duplication.
fn get_q_sig_algo() -> Sig {
	Sig::new(QSIGN_ALGO).expect("Unable to acquire quantum SIG algo.")
}

fn get_q_kem_algo() -> Kem {
	Kem::new(QKEM_ALGO).expect("Unable to acquire quantum KEM algo.")
}

// File format:
// [qkey][classical_key]
// where:
// qkey: [q_sig_key][q_kem_key]
// classical_key: [c_sig_key][c_kem_key]

// Calls the other modules to handle composite keypairs. Classically encrypted
// wrapped in quantum, in cascade.
pub mod hybrid {
	use super::*;

	pub fn gen(pkey_path: &str, skey_path: &str) -> Result<()> {
		quantum::gen(pkey_path, skey_path)?;
		_classical::hyb_gen(pkey_path, skey_path, true)?;
		Ok(())
	}
	pub fn get_pub(pkey_path: &str) -> Result<(quantum::QuantumPKey, classical::ClassicalPKey)> {
		Ok((
			quantum::get_pub(pkey_path)?,
			_classical::hyb_get_pub(pkey_path, true)?,
		))
	}
	pub fn get_priv(skey_path: &str) -> Result<(quantum::QuantumSKey, classical::ClassicalSKey)> {
		Ok((
			quantum::get_priv(skey_path)?,
			_classical::hyb_get_priv(skey_path, true)?,
		))
	}
}

pub mod quantum {
	use super::*;
	pub type QuantumSKey = (sig::SecretKey, kem::SecretKey);
	pub type QuantumPKey = (sig::PublicKey, kem::PublicKey);
	// Generate a quantum pair consisting of a signature keypair and a KEM
	// keypair. Write them both to the files passed. Signature goes first, then
	// KEM key.
	pub fn gen(pkey_path: &str, skey_path: &str) -> Result<()> {
		let kem = get_q_kem_algo();
		let sig = get_q_sig_algo();
		let (mut pkey_f, mut skey_f) = (File::create(pkey_path)?, File::create(skey_path)?);
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
	// Retrieve the 2 public keys from within a private quantum keypair file,
	// and return them.
	pub fn get_pub(pkey_path: &str) -> Result<QuantumPKey> {
		let kem = get_q_kem_algo();
		let sig = get_q_sig_algo();
		let mut pkey_f = File::open(pkey_path)?;
		let mut q_sig = Vec::with_capacity(sig.length_public_key());
		q_sig.resize(sig.length_public_key(), 0);
		let mut q_kem = Vec::with_capacity(kem.length_public_key());
		q_sig.resize(kem.length_public_key(), 0);
		pkey_f.read_exact(&mut q_sig[..])?;
		pkey_f.read_exact(&mut q_kem[..])?;
		Ok((
			sig.public_key_from_bytes(&q_sig[..]).unwrap().to_owned(),
			kem.public_key_from_bytes(&q_kem[..]).unwrap().to_owned(),
		))
	}
	// Retrieve the 2 private keys from within a private quantum keypair file,
	// and return them.
	pub fn get_priv(skey_path: &str) -> Result<QuantumSKey> {
		let kem = get_q_kem_algo();
		let sig = get_q_sig_algo();
		let mut skey_f = File::open(skey_path)?;
		let mut q_sig = Vec::with_capacity(sig.length_secret_key());
		q_sig.resize(sig.length_secret_key(), 0);
		let mut q_kem = Vec::with_capacity(kem.length_secret_key());
		q_kem.resize(kem.length_secret_key(), 0);
		skey_f.read_exact(&mut q_sig[..])?;
		skey_f.read_exact(&mut q_kem[..])?;
		Ok((
			sig.secret_key_from_bytes(&q_sig[..]).unwrap().to_owned(),
			kem.secret_key_from_bytes(&q_kem[..]).unwrap().to_owned(),
		))
	}
}

// Exported module
pub mod classical {
	use super::*;
	pub use _classical::{gen, get_priv, get_pub, ClassicalPKey, ClassicalSKey};
}

// Local access module
mod _classical {
	use super::*;
	pub type ClassicalSKey = (sign::SecretKey, kx::SecretKey);
	pub type ClassicalPKey = (sign::PublicKey, kx::PublicKey);
	// The length needed to jump over the quantum section of a hybrid public key
	fn hybrid_pub_jump() -> u64 {
		let kem = get_q_kem_algo();
		let sig = get_q_sig_algo();
		(sig.length_public_key() + kem.length_public_key()) as u64
	}
	// The length needed to jump over the quantum section of a hybrid private key
	fn hybrid_priv_jump() -> u64 {
		let kem = get_q_kem_algo();
		let sig = get_q_sig_algo();
		(sig.length_secret_key() + kem.length_secret_key()) as u64
	}
	// Generate a public-private classical keypair consisting of a signing key,
	// and KEM key
	pub fn gen(pkey_path: &str, skey_path: &str) -> Result<()> {
		hyb_gen(pkey_path, skey_path, false)
	}
	// If this is a hybrid key file we need to append to the file at the path
	// passed. Otherwise we will overwrite what is already there.
	pub fn hyb_gen(pkey_path: &str, skey_path: &str, hyb: bool) -> Result<()> {
		let (mut pkey_f, mut skey_f) = if hyb {
			(
				OpenOptions::new().append(true).open(pkey_path)?,
				OpenOptions::new().append(true).open(skey_path)?,
			)
		} else {
			(File::create(pkey_path)?, File::create(skey_path)?)
		};
		let (sig_pkey, sig_skey) = sign::gen_keypair();
		let (pkey, skey) = kx::gen_keypair();
		pkey_f.write_all(&sig_pkey.0)?;
		pkey_f.write_all(&pkey.0)?;
		skey_f.write_all(&sig_skey.0)?;
		skey_f.write_all(&skey.0)?;
		Ok(())
	}
	// Retrieve the public portion of a public-private keypair. 2 keys in total;
	// one for signing and one for key exchange.
	pub fn get_pub(pkey_path: &str) -> Result<ClassicalPKey> {
		hyb_get_pub(pkey_path, false)
	}
	// If this is a hybrid hey file we need to jump over the quantum section
	// before reading; as to not read in the wrong keys.
	pub fn hyb_get_pub(pkey_path: &str, hyb: bool) -> Result<ClassicalPKey> {
		let mut pkey_f = File::open(pkey_path)?;
		if hyb {
			pkey_f.seek(SeekFrom::Start(hybrid_pub_jump()))?;
		}
		let mut c_sig = [0u8; sign::PUBLICKEYBYTES];
		let mut c_kem = [0u8; kx::PUBLICKEYBYTES];
		pkey_f.read_exact(&mut c_sig[..])?;
		pkey_f.read_exact(&mut c_kem[..])?;
		Ok((sign::PublicKey(c_sig), kx::PublicKey(c_kem)))
	}
	// Retrieve the private portion of a public-private keypair. 2 keys in total;
	// one for signing and one for key exchange.
	pub fn get_priv(skey_path: &str) -> Result<ClassicalSKey> {
		hyb_get_priv(skey_path, false)
	}
	// If this is a hybrid hey file we need to jump over the quantum section
	// before reading; as to not read in the wrong keys.
	pub fn hyb_get_priv(skey_path: &str, hyb: bool) -> Result<ClassicalSKey> {
		let mut skey_f = File::open(skey_path)?;
		if hyb {
			skey_f.seek(SeekFrom::Start(hybrid_priv_jump()))?;
		}
		let mut c_sig = [0u8; sign::SECRETKEYBYTES];
		let mut c_kem = [0u8; kx::SECRETKEYBYTES];
		skey_f.read_exact(&mut c_sig[..])?;
		skey_f.read_exact(&mut c_kem[..])?;
		Ok((sign::SecretKey(c_sig), kx::SecretKey(c_kem)))
	}
}
