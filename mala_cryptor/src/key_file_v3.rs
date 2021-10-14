use crate::enc_algos_in_use;
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

pub trait KeyQuad<A, B, C, D> {
	fn gen(&mut self, pkey_path: &str, skey_path: &str) -> Result<()>;
	fn get_pub(&self, pkey_path: &str) -> Result<(A, B)>;
	fn get_sec(&self, skey_path: &str) -> Result<(C, D)>;
}

pub type QuantumSKeyPair = (sig::SecretKey, kem::SecretKey);
pub type QuantumPKeyPair = (sig::PublicKey, kem::PublicKey);

pub struct QuantumKeyQuad {
	public_keypair: Option<QuantumPKeyPair>,
	secret_keypair: Option<QuantumSKeyPair>,
	sig_alg: sig::Sig,
	kem_alg: kem::Kem,
}

impl QuantumKeyQuad {
	fn new() -> QuantumKeyQuad {
		QuantumKeyQuad {
			public_keypair: None,
			secret_keypair: None,
			sig_alg: enc_algos_in_use::get_q_sig_algo(),
			kem_alg: enc_algos_in_use::get_q_kem_algo(),
		}
	}
}

impl KeyQuad<sig::PublicKey, kem::PublicKey, sig::SecretKey, kem::SecretKey> for QuantumKeyQuad {
	fn gen(&mut self, pkey_path: &str, skey_path: &str) -> Result<()> {
		let (mut pkey_f, mut skey_f) = (File::create(pkey_path)?, File::create(skey_path)?);
		let (sig_pkey, sig_skey) = self
			.sig_alg
			.keypair()
			.expect("Unable to generate quantum signature keypair.");
		let (kem_pkey, kem_skey) = self
			.kem_alg
			.keypair()
			.expect("Unable to generate quantum KEM keypair.");
		pkey_f.write_all(&sig_pkey.as_ref().to_vec())?;
		pkey_f.write_all(&kem_pkey.as_ref().to_vec())?;
		skey_f.write_all(&sig_skey.as_ref().to_vec())?;
		skey_f.write_all(&kem_skey.as_ref().to_vec())?;
		self.public_keypair = Some((sig_pkey, kem_pkey));
		self.secret_keypair = Some((sig_skey, kem_skey));
		Ok(())
	}
	fn get_pub(&self, pkey_path: &str) -> Result<(sig::PublicKey, kem::PublicKey)> {
		unimplemented!();
	}
	fn get_sec(&self, skey_path: &str) -> Result<(sig::SecretKey, kem::SecretKey)> {
		unimplemented!();
	}
}
