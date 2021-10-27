use super::base::*;
use sodiumoxide::crypto::{kx, sign};
use std::convert::TryInto;

// Classical KeyPair using libsodium via SodiumOxide.

impl IKeyPair<sign::PublicKey, sign::SecretKey> for Signature {
	// Generate a public and private key A, and B.
	fn gen_keypair(&self) -> (sign::PublicKey, sign::SecretKey) {
		sign::gen_keypair()
	}
	// Take a public key, and turn it into bytes
	fn pub_to_bytes(&self, pub_k: &sign::PublicKey) -> Vec<u8> {
		Vec::from(pub_k.0.to_owned())
	}
	// inverse, back to a public key
	fn bytes_to_pub(&self, bytes: &[u8]) -> sign::PublicKey {
		sign::PublicKey(
			bytes[..sign::PUBLICKEYBYTES]
				.try_into()
				.expect("Unable to convert back to signature public key."),
		)
	}
	fn sec_to_bytes(&self, sec_k: &sign::SecretKey) -> Vec<u8> {
		Vec::from(sec_k.0.to_owned())
	}
	fn bytes_to_sec(&self, bytes: &[u8]) -> sign::SecretKey {
		sign::SecretKey(
			bytes[..sign::SECRETKEYBYTES]
				.try_into()
				.expect("Unable to convert back to signature secret key."),
		)
	}
	// offset into the file to read / write a public key
	fn pub_offset(&self) -> u64 {
		self.pub_offset()
	}
	// offset into the file to read / write a secret key
	fn sec_offset(&self) -> u64 {
		self.sec_offset()
	}
	// The length in bytes of a public key
	fn pub_key_len(&self) -> usize {
		sign::PUBLICKEYBYTES
	}
	// The length in bytes of a secret key
	fn sec_key_len(&self) -> usize {
		sign::SECRETKEYBYTES
	}
}

impl IKeyPair<kx::PublicKey, kx::SecretKey> for KeyExchange {
	// Generate a public and private key A, and B.
	fn gen_keypair(&self) -> (kx::PublicKey, kx::SecretKey) {
		kx::gen_keypair()
	}
	// Take a public key, and turn it into bytes
	fn pub_to_bytes(&self, pub_k: &kx::PublicKey) -> Vec<u8> {
		Vec::from(pub_k.0.to_owned())
	}
	// inverse, back to a public key
	fn bytes_to_pub(&self, bytes: &[u8]) -> kx::PublicKey {
		kx::PublicKey(
			bytes[..kx::PUBLICKEYBYTES]
				.try_into()
				.expect("Unable to convert back to signature public key."),
		)
	}
	fn sec_to_bytes(&self, sec_k: &kx::SecretKey) -> Vec<u8> {
		Vec::from(sec_k.0.to_owned())
	}
	fn bytes_to_sec(&self, bytes: &[u8]) -> kx::SecretKey {
		kx::SecretKey(
			bytes[..kx::SECRETKEYBYTES]
				.try_into()
				.expect("Unable to convert back to signature public key."),
		)
	}
	// offset into the file to read / write a public key
	fn pub_offset(&self) -> u64 {
		self.pub_offset() + sign::PUBLICKEYBYTES as u64
	}
	// offset into the file to read / write a secret key
	fn sec_offset(&self) -> u64 {
		self.sec_offset() + sign::SECRETKEYBYTES as u64
	}
	// The length in bytes of a public key
	fn pub_key_len(&self) -> usize {
		kx::PUBLICKEYBYTES
	}
	// The length in bytes of a secret key
	fn sec_key_len(&self) -> usize {
		kx::SECRETKEYBYTES
	}
}

pub type ClassicalKeyQuad = KeyQuad<
	sign::PublicKey,
	sign::SecretKey,
	kx::PublicKey,
	kx::SecretKey,
	Signature,
	KeyExchange,
>;

impl ClassicalKeyQuad {
	pub fn new() -> ClassicalKeyQuad {
		KeyQuad::_new(Signature::new(0, 0), KeyExchange::new(0, 0))
	}
	pub fn new_hyb(pub_offset: u64, sec_offset: u64) -> ClassicalKeyQuad {
		KeyQuad::_new(
			Signature::new(pub_offset, sec_offset),
			KeyExchange::new(pub_offset, sec_offset),
		)
	}
}

#[test]
fn test_classical() {
	use std::fs;
	let c = ClassicalKeyQuad::new();
	c.gen("/tmp/pub_key_c_test", "/tmp/sec_key_c_test").unwrap();
	// Pub
	let publ = c.get_pub("/tmp/pub_key_c_test").unwrap();
	assert_eq!(publ.0.as_ref().len(), sign::PUBLICKEYBYTES);
	assert_eq!(publ.1.as_ref().len(), kx::PUBLICKEYBYTES);
	// Sec
	let sec = c.get_sec("/tmp/sec_key_c_test").unwrap();
	assert_eq!(sec.0.as_ref().len(), sign::SECRETKEYBYTES);
	assert_eq!(sec.1.as_ref().len(), kx::SECRETKEYBYTES);
	fs::remove_file("/tmp/pub_key_c_test").unwrap();
	fs::remove_file("/tmp/sec_key_c_test").unwrap();
}
