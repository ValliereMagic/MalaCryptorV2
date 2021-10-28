use super::base::*;
use crate::enc_algos_in_use;
use oqs::kem;
use oqs::sig;
use std::rc::Rc;

// Quantum KeyPair using liboqs via liboqs-rust.

pub struct QSignature {
	// Base
	signature: Signature,
	sig: sig::Sig,
}
impl QSignature {
	fn new(pub_offset: u64, sec_offset: u64) -> QSignature {
		QSignature {
			signature: Signature::new(pub_offset, sec_offset),
			sig: enc_algos_in_use::get_q_sig_algo(),
		}
	}
}
// Adapt QSignature to the Keypair trait
impl IKeyPair<sig::PublicKey, sig::SecretKey> for Rc<QSignature> {
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
		self.signature.pub_offset()
	}
	fn sec_offset(&self) -> u64 {
		self.signature.sec_offset()
	}
	fn pub_key_len(&self) -> usize {
		self.sig.length_public_key()
	}
	fn sec_key_len(&self) -> usize {
		self.sig.length_secret_key()
	}
}

pub struct QKeyExchange {
	// Base
	key_exchange: KeyExchange,
	sig: Rc<QSignature>,
	kem: kem::Kem,
}
impl QKeyExchange {
	fn new(sig: Rc<QSignature>, pub_offset: u64, sec_offset: u64) -> QKeyExchange {
		QKeyExchange {
			key_exchange: KeyExchange::new(pub_offset, sec_offset),
			sig,
			kem: enc_algos_in_use::get_q_kem_algo(),
		}
	}
}

impl<'a> IKeyPair<kem::PublicKey, kem::SecretKey> for QKeyExchange {
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
		self.sig.pub_key_len() as u64 + self.key_exchange.pub_offset()
	}
	fn sec_offset(&self) -> u64 {
		self.sig.sec_key_len() as u64 + self.key_exchange.sec_offset()
	}
	fn pub_key_len(&self) -> usize {
		self.kem.length_public_key()
	}
	fn sec_key_len(&self) -> usize {
		self.kem.length_secret_key()
	}
}

pub type QuantumKeyQuad = KeyQuad<
	sig::PublicKey,
	sig::SecretKey,
	kem::PublicKey,
	kem::SecretKey,
	Rc<QSignature>,
	QKeyExchange,
>;

impl QuantumKeyQuad {
	pub fn new() -> QuantumKeyQuad {
		let sig = Rc::new(QSignature::new(0, 0));
		let sig_2 = Rc::clone(&sig);
		KeyQuad::_new(sig, QKeyExchange::new(sig_2, 0, 0))
	}
	pub fn new_hyb(pub_offset: u64, sec_offset: u64) -> QuantumKeyQuad {
		let sig = Rc::new(QSignature::new(pub_offset, sec_offset));
		let sig_2 = Rc::clone(&sig);
		KeyQuad::_new(sig, QKeyExchange::new(sig_2, pub_offset, sec_offset))
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
