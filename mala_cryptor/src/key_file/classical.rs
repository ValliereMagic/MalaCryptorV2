use super::key_file::*;
use sodiumoxide::crypto::{kx, sign};
use std::convert::TryInto;
use std::io::Result;
struct Signature {
	pub_offset: u64,
	sec_offset: u64,
}

impl Signature {
	pub fn new(pub_offset: u64, sec_offset: u64) -> Signature {
		Signature {
			pub_offset: pub_offset,
			sec_offset: sec_offset,
		}
	}
}

impl KeyPair<sign::PublicKey, sign::SecretKey> for Signature {
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
		self.pub_offset
	}
	// offset into the file to read / write a secret key
	fn sec_offset(&self) -> u64 {
		self.sec_offset
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

struct KeyExchange {
	pub_offset: u64,
	sec_offset: u64,
}

impl KeyExchange {
	pub fn new(pub_offset: u64, sec_offset: u64) -> KeyExchange {
		KeyExchange {
			pub_offset: pub_offset,
			sec_offset: sec_offset,
		}
	}
}

impl KeyPair<kx::PublicKey, kx::SecretKey> for KeyExchange {
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
		self.pub_offset + sign::PUBLICKEYBYTES as u64
	}
	// offset into the file to read / write a secret key
	fn sec_offset(&self) -> u64 {
		self.sec_offset + sign::SECRETKEYBYTES as u64
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

pub struct ClassicalKeyQuad {
	sign: Signature,
	kem: KeyExchange,
}

impl ClassicalKeyQuad {
	pub fn new() -> ClassicalKeyQuad {
		ClassicalKeyQuad {
			sign: Signature::new(0, 0),
			kem: KeyExchange::new(0, 0),
		}
	}
	pub fn new_hyb(pub_offset: u64, sec_offset: u64) -> ClassicalKeyQuad {
		ClassicalKeyQuad {
			sign: Signature::new(pub_offset, sec_offset),
			kem: KeyExchange::new(pub_offset, sec_offset),
		}
	}
}

impl KeyQuad<sign::PublicKey, kx::PublicKey, sign::SecretKey, kx::SecretKey> for ClassicalKeyQuad {
	// Generate a public and private keyquad composed of a signature public and
	// secret pair as well as a key exchange public and secret pair
	fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
		gen(&self.sign, pkey_path, skey_path)?;
		gen(&self.kem, pkey_path, skey_path)
	}
	// Retrieve the public portion of the keypairs from the file paths passed
	fn get_pub(&self, pkey_path: &str) -> Result<(sign::PublicKey, kx::PublicKey)> {
		let sig = match get(KeyVariant::Public(Zst::new()), &self.sign, pkey_path)? {
			KeyVariant::Public(p) => p,
			_ => unreachable!(),
		};
		let kem = match get(KeyVariant::Public(Zst::new()), &self.kem, pkey_path)? {
			KeyVariant::Public(p) => p,
			_ => unreachable!(),
		};
		Ok((sig, kem))
	}
	fn get_sec(&self, skey_path: &str) -> Result<(sign::SecretKey, kx::SecretKey)> {
		let sig = match get(KeyVariant::Secret(Zst::new()), &self.sign, skey_path)? {
			KeyVariant::Secret(s) => s,
			_ => unreachable!(),
		};
		let kem = match get(KeyVariant::Secret(Zst::new()), &self.kem, skey_path)? {
			KeyVariant::Secret(s) => s,
			_ => unreachable!(),
		};
		Ok((sig, kem))
	}
	// The total size that the file will be for each of the key parts. This is
	// used for composition key files where multiple different keypairs are
	// stored in the same file.
	fn total_pub_size_bytes(&self) -> usize {
		sign::PUBLICKEYBYTES + kx::PUBLICKEYBYTES
	}
	fn total_sec_size_bytes(&self) -> usize {
		sign::SECRETKEYBYTES + kx::SECRETKEYBYTES
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
