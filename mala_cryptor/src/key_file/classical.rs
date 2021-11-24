use super::base::*;
use libsodium_sys::*;
use std::convert::TryInto;

pub type SodiumSigPub = [u8; crypto_sign_PUBLICKEYBYTES as usize];
pub type SodiumSigSec = [u8; crypto_sign_SECRETKEYBYTES as usize];
pub type SodiumKEMPub = [u8; crypto_kx_PUBLICKEYBYTES as usize];
pub type SodiumKEMSec = [u8; crypto_kx_SECRETKEYBYTES as usize];

trait Create {
	fn default() -> Self;
}

impl Create for SodiumSigSec {
	fn default() -> Self {
		[0u8; crypto_sign_SECRETKEYBYTES as usize]
	}
}

// Classical KeyPair using libsodium via SodiumOxide.

impl IKeyPair<SodiumSigPub, SodiumSigSec> for Signature {
	// Generate a public and private key A, and B.
	fn gen_keypair(&self) -> (SodiumSigPub, SodiumSigSec) {
		unsafe {
			let (mut pk, mut sk) = (SodiumSigPub::default(), SodiumSigSec::default());
			crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
			(pk, sk)
		}
	}
	// Take a public key, and turn it into bytes
	fn pub_to_bytes(&self, pub_k: &SodiumSigPub) -> Vec<u8> {
		Vec::from(pub_k.to_owned())
	}
	// inverse, back to a public key
	fn bytes_to_pub(&self, bytes: &[u8]) -> SodiumSigPub {
		bytes[..crypto_sign_PUBLICKEYBYTES as usize]
			.try_into()
			.expect("Unable to convert back to signature public key.")
	}
	fn sec_to_bytes(&self, sec_k: &SodiumSigSec) -> Vec<u8> {
		Vec::from(sec_k.to_owned())
	}
	fn bytes_to_sec(&self, bytes: &[u8]) -> SodiumSigSec {
		bytes[..crypto_sign_SECRETKEYBYTES as usize]
			.try_into()
			.expect("Unable to convert back to signature secret key.")
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
		crypto_sign_PUBLICKEYBYTES as usize
	}
	// The length in bytes of a secret key
	fn sec_key_len(&self) -> usize {
		crypto_sign_SECRETKEYBYTES as usize
	}
}

impl IKeyPair<SodiumKEMPub, SodiumKEMSec> for KeyExchange {
	// Generate a public and private key A, and B.
	fn gen_keypair(&self) -> (SodiumKEMPub, SodiumKEMSec) {
		unsafe {
			let (mut pk, mut sk) = (SodiumKEMPub::default(), SodiumKEMSec::default());
			crypto_kx_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
			(pk, sk)
		}
	}
	// Take a public key, and turn it into bytes
	fn pub_to_bytes(&self, pub_k: &SodiumKEMPub) -> Vec<u8> {
		Vec::from(pub_k.to_owned())
	}
	// inverse, back to a public key
	fn bytes_to_pub(&self, bytes: &[u8]) -> SodiumKEMPub {
		bytes[..crypto_kx_PUBLICKEYBYTES as usize]
			.try_into()
			.expect("Unable to convert back to signature public key.")
	}
	fn sec_to_bytes(&self, sec_k: &SodiumKEMSec) -> Vec<u8> {
		Vec::from(sec_k.to_owned())
	}
	fn bytes_to_sec(&self, bytes: &[u8]) -> SodiumKEMSec {
		bytes[..crypto_kx_SECRETKEYBYTES as usize]
			.try_into()
			.expect("Unable to convert back to signature public key.")
	}
	// offset into the file to read / write a public key
	fn pub_offset(&self) -> u64 {
		self.pub_offset() + crypto_sign_PUBLICKEYBYTES as u64
	}
	// offset into the file to read / write a secret key
	fn sec_offset(&self) -> u64 {
		self.sec_offset() + crypto_sign_SECRETKEYBYTES as u64
	}
	// The length in bytes of a public key
	fn pub_key_len(&self) -> usize {
		crypto_kx_PUBLICKEYBYTES as usize
	}
	// The length in bytes of a secret key
	fn sec_key_len(&self) -> usize {
		crypto_kx_SECRETKEYBYTES as usize
	}
}

pub type ClassicalKeyQuad =
	KeyQuad<SodiumSigPub, SodiumSigSec, SodiumKEMPub, SodiumKEMSec, Signature, KeyExchange>;

impl IKeyQuadCreator<SodiumSigPub, SodiumSigSec, SodiumKEMPub, SodiumKEMSec, Signature, KeyExchange>
	for ClassicalKeyQuad
{
	fn new() -> ClassicalKeyQuad {
		KeyQuad::create(Signature::new(0, 0), KeyExchange::new(0, 0))
	}
	fn hyb_new(pub_offset: u64, sec_offset: u64) -> ClassicalKeyQuad {
		KeyQuad::create(
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
	assert_eq!(publ.0.as_ref().len(), crypto_sign_PUBLICKEYBYTES as usize);
	assert_eq!(publ.1.as_ref().len(), crypto_kx_PUBLICKEYBYTES as usize);
	// Sec
	let sec = c.get_sec("/tmp/sec_key_c_test").unwrap();
	assert_eq!(sec.0.as_ref().len(), crypto_sign_SECRETKEYBYTES as usize);
	assert_eq!(sec.1.as_ref().len(), crypto_kx_SECRETKEYBYTES as usize);
	fs::remove_file("/tmp/pub_key_c_test").unwrap();
	fs::remove_file("/tmp/sec_key_c_test").unwrap();
}
