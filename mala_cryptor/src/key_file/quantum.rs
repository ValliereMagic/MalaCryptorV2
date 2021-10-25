use super::key_file::*;
use crate::enc_algos_in_use;
use oqs::kem;
use oqs::sig;
use std::io::Result;
use std::rc::Rc;
struct Signature {
	sig: sig::Sig,
	pub_offset: u64,
	sec_offset: u64,
}
impl Signature {
	fn new(pub_offset: u64, sec_offset: u64) -> Signature {
		Signature {
			sig: enc_algos_in_use::get_q_sig_algo(),
			pub_offset: pub_offset,
			sec_offset: sec_offset,
		}
	}
}
// Adapt Signature to the Keypair trait
impl KeyPair<sig::PublicKey, sig::SecretKey> for Signature {
	fn gen_keypair(&self) -> (sig::PublicKey, sig::SecretKey) {
		self.sig
			.keypair()
			.expect("Unable to generate quantum keypair.")
	}
	fn pub_to_bytes(&self, pub_k: &sig::PublicKey) -> Vec<u8> {
		pub_k.as_ref().to_owned()
	}
	fn bytes_to_pub(&self, bytes: &[u8]) -> sig::PublicKey {
		self.sig
			.public_key_from_bytes(bytes)
			.expect("Unable to convert bytes to quantum signature.")
			.to_owned()
	}
	fn sec_to_bytes(&self, sec_k: &sig::SecretKey) -> Vec<u8> {
		sec_k.as_ref().to_owned()
	}
	fn bytes_to_sec(&self, bytes: &[u8]) -> sig::SecretKey {
		self.sig
			.secret_key_from_bytes(bytes)
			.expect("Unable to convert bytes to quantum signature.")
			.to_owned()
	}
	fn pub_offset(&self) -> u64 {
		self.pub_offset
	}
	fn sec_offset(&self) -> u64 {
		self.sec_offset
	}
	fn pub_key_len(&self) -> usize {
		self.sig.length_public_key()
	}
	fn sec_key_len(&self) -> usize {
		self.sig.length_secret_key()
	}
}

struct KeyExchange {
	sig: Rc<Signature>,
	kem: kem::Kem,
	pub_offset: u64,
	sec_offset: u64,
}
impl KeyExchange {
	fn new(sig: Rc<Signature>, pub_offset: u64, sec_offset: u64) -> KeyExchange {
		KeyExchange {
			sig: sig,
			kem: enc_algos_in_use::get_q_kem_algo(),
			pub_offset: pub_offset,
			sec_offset: sec_offset,
		}
	}
}

impl<'a> KeyPair<kem::PublicKey, kem::SecretKey> for KeyExchange {
	fn gen_keypair(&self) -> (kem::PublicKey, kem::SecretKey) {
		self.kem
			.keypair()
			.expect("Unable to generate quantum keypair.")
	}
	fn pub_to_bytes(&self, pub_k: &kem::PublicKey) -> Vec<u8> {
		pub_k.as_ref().to_owned()
	}
	fn bytes_to_pub(&self, bytes: &[u8]) -> kem::PublicKey {
		self.kem
			.public_key_from_bytes(bytes)
			.expect("Unable to convert bytes to quantum signature.")
			.to_owned()
	}
	fn sec_to_bytes(&self, sec_k: &kem::SecretKey) -> Vec<u8> {
		sec_k.as_ref().to_owned()
	}
	fn bytes_to_sec(&self, bytes: &[u8]) -> kem::SecretKey {
		self.kem
			.secret_key_from_bytes(bytes)
			.expect("Unable to convert bytes to quantum signature.")
			.to_owned()
	}
	fn pub_offset(&self) -> u64 {
		self.sig.pub_key_len() as u64 + self.pub_offset
	}
	fn sec_offset(&self) -> u64 {
		self.sig.sec_key_len() as u64 + self.sec_offset
	}
	fn pub_key_len(&self) -> usize {
		self.kem.length_public_key()
	}
	fn sec_key_len(&self) -> usize {
		self.kem.length_secret_key()
	}
}

pub struct QuantumKeyQuad {
	sig: Rc<Signature>,
	kem: KeyExchange,
}

impl QuantumKeyQuad {
	pub fn new() -> QuantumKeyQuad {
		let sig = Rc::new(Signature::new(0, 0));
		let sig_2 = Rc::clone(&sig);
		QuantumKeyQuad {
			sig: sig,
			kem: KeyExchange::new(sig_2, 0, 0),
		}
	}
	pub fn new_hyb(pub_offset: u64, sec_offset: u64) -> QuantumKeyQuad {
		let sig = Rc::new(Signature::new(pub_offset, sec_offset));
		let sig_2 = Rc::clone(&sig);
		QuantumKeyQuad {
			sig: sig,
			kem: KeyExchange::new(sig_2, pub_offset, sec_offset),
		}
	}
}

impl KeyQuad<sig::PublicKey, kem::PublicKey, sig::SecretKey, kem::SecretKey> for QuantumKeyQuad {
	fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
		gen(&(*self.sig), pkey_path, skey_path)?;
		gen(&self.kem, pkey_path, skey_path)
	}
	fn get_pub(&self, pkey_path: &str) -> Result<(sig::PublicKey, kem::PublicKey)> {
		let sig = match get(KeyVariant::Public(Zst::new()), &(*self.sig), pkey_path)? {
			KeyVariant::Public(p) => p,
			_ => unreachable!(),
		};
		let kem = match get(KeyVariant::Public(Zst::new()), &self.kem, pkey_path)? {
			KeyVariant::Public(p) => p,
			_ => unreachable!(),
		};
		Ok((sig, kem))
	}
	fn get_sec(&self, skey_path: &str) -> Result<(sig::SecretKey, kem::SecretKey)> {
		let sig = match get(KeyVariant::Secret(Zst::new()), &(*self.sig), skey_path)? {
			KeyVariant::Secret(s) => s,
			_ => unreachable!(),
		};
		let kem = match get(KeyVariant::Secret(Zst::new()), &self.kem, skey_path)? {
			KeyVariant::Secret(s) => s,
			_ => unreachable!(),
		};
		Ok((sig, kem))
	}
	fn total_pub_size_bytes(&self) -> usize {
		self.kem.pub_key_len() + self.sig.pub_key_len()
	}
	fn total_sec_size_bytes(&self) -> usize {
		self.kem.sec_key_len() + self.sig.sec_key_len()
	}
}

#[test]
fn test_quantum() {
	use std::fs;
	let q = QuantumKeyQuad::new();
	q.gen("/tmp/pub_key_q_test", "/tmp/sec_key_q_test").unwrap();
	let sig = enc_algos_in_use::get_q_sig_algo();
	let kem = enc_algos_in_use::get_q_kem_algo();
	// Pub
	let publ = q.get_pub("/tmp/pub_key_q_test").unwrap();
	assert_eq!(publ.0.as_ref().len(), sig.length_public_key());
	assert_eq!(publ.1.as_ref().len(), kem.length_public_key());
	// Sec
	let sec = q.get_sec("/tmp/sec_key_q_test").unwrap();
	assert_eq!(sec.0.as_ref().len(), sig.length_secret_key());
	assert_eq!(sec.1.as_ref().len(), kem.length_secret_key());
	fs::remove_file("/tmp/pub_key_q_test").unwrap();
	fs::remove_file("/tmp/sec_key_q_test").unwrap();
}
