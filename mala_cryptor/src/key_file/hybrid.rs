#[test]
fn test_hybrid() {
	use super::base::*;
	use super::{classical::*, quantum::*};
	use crate::enc_algos_in_use;
	use sodiumoxide::crypto::{kx, sign};
	use std::fs;
	let q = QuantumKeyQuad::new();
	let c = ClassicalKeyQuad::hyb_new(
		q.total_pub_size_bytes() as u64,
		q.total_sec_size_bytes() as u64,
	);
	q.gen("/tmp/pub_key_h_test", "/tmp/sec_key_h_test").unwrap();
	c.gen("/tmp/pub_key_h_test", "/tmp/sec_key_h_test").unwrap();
	let sig = enc_algos_in_use::get_q_sig_algo();
	let kem = enc_algos_in_use::get_q_kem_algo();
	// Pub
	let publ = q.get_pub("/tmp/pub_key_h_test").unwrap();
	assert_eq!(publ.0.as_ref().len(), sig.length_public_key());
	assert_eq!(publ.1.as_ref().len(), kem.length_public_key());
	// Sec
	let sec = q.get_sec("/tmp/sec_key_h_test").unwrap();
	assert_eq!(sec.0.as_ref().len(), sig.length_secret_key());
	assert_eq!(sec.1.as_ref().len(), kem.length_secret_key());
	// Pub
	let publ = c.get_pub("/tmp/pub_key_h_test").unwrap();
	assert_eq!(publ.0.as_ref().len(), sign::PUBLICKEYBYTES);
	assert_eq!(publ.1.as_ref().len(), kx::PUBLICKEYBYTES);
	// Sec
	let sec = c.get_sec("/tmp/sec_key_h_test").unwrap();
	assert_eq!(sec.0.as_ref().len(), sign::SECRETKEYBYTES);
	assert_eq!(sec.1.as_ref().len(), kx::SECRETKEYBYTES);
	fs::remove_file("/tmp/pub_key_h_test").unwrap();
	fs::remove_file("/tmp/sec_key_h_test").unwrap();
}
