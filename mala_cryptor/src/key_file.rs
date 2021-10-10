use crate::enc_algos_in_use::*;
use algo_singleton::*;
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

pub fn gen_symmetric_keyfile(key_file_path: &str) -> Result<()> {
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

mod algo_singleton {
	use super::*;
	static mut SIG: Option<Sig> = None;
	static mut KEM: Option<Kem> = None;
	pub fn get_sig() -> &'static Sig {
		unsafe {
			if let None = SIG {
				SIG = Some(Sig::new(QSIGN_ALGO).expect("Unable to acquire quantum SIG algo."));
				SIG.as_ref().unwrap()
			} else {
				SIG.as_ref().unwrap()
			}
		}
	}

	pub fn get_kem() -> &'static Kem {
		unsafe {
			if let None = KEM {
				KEM = Some(Kem::new(QKEM_ALGO).expect("Unable to acquire quantum KEM algo."));
				KEM.as_ref().unwrap()
			} else {
				KEM.as_ref().unwrap()
			}
		}
	}
}

// File format:
// [qkey][classical_key]
// where:
// qkey: [q_sig_key][q_kem_key]
// classical_key: [c_sig_key][c_kem_key]
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

	pub fn gen(pkey_path: &str, skey_path: &str) -> Result<()> {
		let (mut pkey_f, mut skey_f) = (File::create(pkey_path)?, File::create(skey_path)?);
		let (sig_pkey, sig_skey) = get_sig()
			.keypair()
			.expect("Unable to generate quantum signature keypair.");
		let (pkey, skey) = get_kem()
			.keypair()
			.expect("Unable to generate quantum keypair.");
		pkey_f.write_all(&sig_pkey.into_vec())?;
		pkey_f.write_all(&pkey.into_vec())?;
		skey_f.write_all(&sig_skey.into_vec())?;
		skey_f.write_all(&skey.into_vec())?;
		Ok(())
	}

	pub fn get_pub(pkey_path: &str) -> Result<QuantumPKey> {
		let mut pkey_f = File::open(pkey_path)?;
		let mut q_sig = Vec::with_capacity(get_sig().length_public_key());
		q_sig.resize(get_sig().length_public_key(), 0);
		let mut q_kem = Vec::with_capacity(get_kem().length_public_key());
		q_sig.resize(get_kem().length_public_key(), 0);
		pkey_f.read_exact(&mut q_sig[..])?;
		pkey_f.read_exact(&mut q_kem[..])?;
		Ok((
			get_sig()
				.public_key_from_bytes(&q_sig[..])
				.unwrap()
				.to_owned(),
			get_kem()
				.public_key_from_bytes(&q_kem[..])
				.unwrap()
				.to_owned(),
		))
	}

	pub fn get_priv(skey_path: &str) -> Result<QuantumSKey> {
		let mut skey_f = File::open(skey_path)?;
		let mut q_sig = Vec::with_capacity(get_sig().length_secret_key());
		q_sig.resize(get_sig().length_secret_key(), 0);
		let mut q_kem = Vec::with_capacity(get_kem().length_secret_key());
		q_kem.resize(get_kem().length_secret_key(), 0);
		skey_f.read_exact(&mut q_sig[..])?;
		skey_f.read_exact(&mut q_kem[..])?;
		Ok((
			get_sig()
				.secret_key_from_bytes(&q_sig[..])
				.unwrap()
				.to_owned(),
			get_kem()
				.secret_key_from_bytes(&q_kem[..])
				.unwrap()
				.to_owned(),
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
		(get_sig().length_public_key() + get_kem().length_public_key()) as u64
	}
	// The length needed to jump over the quantum section of a hybrid private key
	fn hybrid_priv_jump() -> u64 {
		(get_sig().length_secret_key() + get_kem().length_secret_key()) as u64
	}
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
