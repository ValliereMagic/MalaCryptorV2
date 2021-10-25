use super::key_file::*;
use super::{classical, quantum};
use oqs::kem;
use oqs::sig;
use sodiumoxide::crypto::{kx, sign};
use std::io::Result;
use std::rc::Rc;
pub struct HybridKeyQuad {
	q: Rc<quantum::QuantumKeyQuad>,
	c: classical::ClassicalKeyQuad,
}
impl HybridKeyQuad {
	pub fn new() -> HybridKeyQuad {
		let q = Rc::new(quantum::QuantumKeyQuad::new_hyb(0, 0));
		let q2 = Rc::clone(&q);
		HybridKeyQuad {
			q: q,
			c: classical::ClassicalKeyQuad::new_hyb(
				q2.total_pub_size_bytes() as u64,
				q2.total_sec_size_bytes() as u64,
			),
		}
	}
}

impl
	KeyQuad<
		(sig::PublicKey, sign::PublicKey),
		(kem::PublicKey, kx::PublicKey),
		(sig::SecretKey, sign::SecretKey),
		(kem::SecretKey, kx::SecretKey),
	> for HybridKeyQuad
{
	// Generate a public and private keyquad composed of a signature public and
	// secret pair as well as a key exchange public and secret pair
	fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
		self.q.gen(pkey_path, skey_path)?;
		self.c.gen(pkey_path, skey_path)
	}
	// Retrieve the public portion of the keypairs from the file paths passed
	fn get_pub(
		&self,
		pkey_path: &str,
	) -> Result<(
		(sig::PublicKey, sign::PublicKey),
		(kem::PublicKey, kx::PublicKey),
	)> {
		let q = self.q.get_pub(pkey_path)?;
		let c = self.c.get_pub(pkey_path)?;
		Ok(((q.0, c.0), (q.1, c.1)))
	}
	fn get_sec(
		&self,
		skey_path: &str,
	) -> Result<(
		(sig::SecretKey, sign::SecretKey),
		(kem::SecretKey, kx::SecretKey),
	)> {
		let q = self.q.get_sec(skey_path)?;
		let c = self.c.get_sec(skey_path)?;
		Ok(((q.0, c.0), (q.1, c.1)))
	}
	// The total size that the file will be for each of the key parts. This is
	// used for composition key files where multiple different keypairs are
	// stored in the same file.
	fn total_pub_size_bytes(&self) -> usize {
		self.q.total_pub_size_bytes() + self.c.total_pub_size_bytes()
	}
	fn total_sec_size_bytes(&self) -> usize {
		self.q.total_sec_size_bytes() + self.c.total_sec_size_bytes()
	}
}

#[test]
fn test_hybrid() {
	use crate::enc_algos_in_use;
	use std::fs;
	let c = HybridKeyQuad::new();
	c.gen("/tmp/pub_key_h_test", "/tmp/sec_key_h_test").unwrap();
	// Pub
	let publ = c.get_pub("/tmp/pub_key_h_test").unwrap();
	let sig = enc_algos_in_use::get_q_sig_algo();
	let kem = enc_algos_in_use::get_q_kem_algo();
	assert_eq!(publ.0 .0.as_ref().len(), sig.length_public_key());
	assert_eq!(publ.0 .1.as_ref().len(), sign::PUBLICKEYBYTES);
	assert_eq!(publ.1 .0.as_ref().len(), kem.length_public_key());
	assert_eq!(publ.1 .1.as_ref().len(), kx::PUBLICKEYBYTES);
	// Sec
	let sec = c.get_sec("/tmp/sec_key_h_test").unwrap();
	assert_eq!(sec.0 .0.as_ref().len(), sig.length_secret_key());
	assert_eq!(sec.0 .1.as_ref().len(), sign::SECRETKEYBYTES);
	assert_eq!(sec.1 .0.as_ref().len(), kem.length_secret_key());
	assert_eq!(sec.1 .1.as_ref().len(), kx::SECRETKEYBYTES);
	fs::remove_file("/tmp/pub_key_h_test").unwrap();
	fs::remove_file("/tmp/sec_key_h_test").unwrap();
}
