use crate::enc_algos_in_use;
use oqs::kem;
use oqs::sig;
use sodiumoxide::crypto::{
	kx, secretstream::gen_key, secretstream::Key, secretstream::KEYBYTES, sign,
};
use std::cell::UnsafeCell;
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

// Defines the public interface for generating and retrieving Key Sets public
// keys are pairs of signing and kem keys, and likewise for their secret
// counterparts.
pub trait KeyQuad<'a, A, B, C, D> {
	fn gen(&'a self, pkey_path: &str, skey_path: &str) -> Result<()>;
	fn get_pub(&'a self, pkey_path: &str) -> Result<&'a (A, B)>;
	fn get_sec(&'a self, skey_path: &str) -> Result<&'a (C, D)>;
}

// Defines the private interface for generating a hybrid key; where a file will
// have multiple keypairs within it. Hence the get functions allow for a byte
// offset into the file where the keypair should begin.
trait HybridQuad<A, B, C, D> {
	fn gen(&self, pkey: &mut File, skey: &mut File) -> Result<()>;
	fn get_pub(&self, pkey: &mut File, offset: u64) -> Result<&(A, B)>;
	fn get_sec(&self, skey: &mut File, offset: u64) -> Result<&(C, D)>;
}

pub mod hybrid {
	use super::*;
	// A hybrid KeyQuad is composed of the 2 quads making up the composure:
	// [quantum and classical]. It also caches the read result from them as
	// references once they have been acquired. Because of this, only 1 key can
	// be loaded. On subsequent calls, to get_pub and get_sec the previously
	// read keys will be returned.
	pub struct HybridKeyQuad<'a> {
		quantum_quad: quantum::QuantumKeyQuad,
		classical_quad: classical::ClassicalKeyQuad,
		pub_keyquad: UnsafeCell<
			Option<(
				&'a quantum::QuantumPKeyPair,
				&'a classical::ClassicalPKeyPair,
			)>,
		>,
		sec_keyquad: UnsafeCell<
			Option<(
				&'a quantum::QuantumSKeyPair,
				&'a classical::ClassicalSKeyPair,
			)>,
		>,
	}

	impl<'a> HybridKeyQuad<'a> {
		pub fn new() -> HybridKeyQuad<'a> {
			HybridKeyQuad {
				quantum_quad: quantum::QuantumKeyQuad::new(),
				classical_quad: classical::ClassicalKeyQuad::new(),
				pub_keyquad: UnsafeCell::new(None),
				sec_keyquad: UnsafeCell::new(None),
			}
		}
	}

	impl<'a>
		KeyQuad<
			'a,
			&'a quantum::QuantumPKeyPair,
			&'a classical::ClassicalPKeyPair,
			&'a quantum::QuantumSKeyPair,
			&'a classical::ClassicalSKeyPair,
		> for HybridKeyQuad<'a>
	{
		// Appropriately generates both composite keys, and puts them in the
		// same file. Using an offset for the second key-set.
		fn gen(&'a self, pkey_path: &str, skey_path: &str) -> Result<()> {
			self.quantum_quad.gen(pkey_path, skey_path)?;
			let (mut pkey_f, mut skey_f) = (
				OpenOptions::new().append(true).open(pkey_path)?,
				OpenOptions::new().append(true).open(skey_path)?,
			);
			HybridQuad::gen(&self.classical_quad, &mut pkey_f, &mut skey_f)
		}
		// Appropriately retrieves both composite keys, and caches the result
		// within self. Using an offset to acquire the second key
		fn get_pub(
			&'a self,
			pkey_path: &str,
		) -> Result<&(
			&'a quantum::QuantumPKeyPair,
			&'a classical::ClassicalPKeyPair,
		)> {
			unsafe {
				if let None = *self.pub_keyquad.get() {
					let q = self.quantum_quad.get_pub(pkey_path)?;
					let mut pkey_f = File::open(pkey_path)?;
					let c = HybridQuad::get_pub(
						&self.classical_quad,
						&mut pkey_f,
						self.quantum_quad.pub_key_size(),
					)?;
					*self.pub_keyquad.get() = Some((q, c));
					Ok((*self.pub_keyquad.get()).as_ref().unwrap())
				} else {
					Ok((*self.pub_keyquad.get()).as_ref().unwrap())
				}
			}
		}
		// Same as pub, different key types
		fn get_sec(
			&'a self,
			skey_path: &str,
		) -> Result<&(
			&'a quantum::QuantumSKeyPair,
			&'a classical::ClassicalSKeyPair,
		)> {
			unsafe {
				if let None = *self.sec_keyquad.get() {
					let q = self.quantum_quad.get_sec(skey_path)?;
					let mut pkey_f = File::open(skey_path)?;
					let c = HybridQuad::get_sec(
						&self.classical_quad,
						&mut pkey_f,
						self.quantum_quad.sec_key_size(),
					)?;
					*self.sec_keyquad.get() = Some((q, c));
					Ok((*self.sec_keyquad.get()).as_ref().unwrap())
				} else {
					Ok((*self.sec_keyquad.get()).as_ref().unwrap())
				}
			}
		}
	}
	#[test]
	fn test_hybrid() {
		use std::fs;
		let c = HybridKeyQuad::new();
		KeyQuad::gen(&c, "/tmp/pub_key_h_test", "/tmp/sec_key_h_test").unwrap();
		// Pub
		let publ = KeyQuad::get_pub(&c, "/tmp/pub_key_h_test").unwrap();
		let sig = enc_algos_in_use::get_q_sig_algo();
		let kem = enc_algos_in_use::get_q_kem_algo();
		assert_eq!(publ.0 .0.as_ref().len(), sig.length_public_key());
		assert_eq!(publ.0 .1.as_ref().len(), kem.length_public_key());
		assert_eq!(publ.1 .0.as_ref().len(), sign::PUBLICKEYBYTES);
		assert_eq!(publ.1 .1.as_ref().len(), kx::PUBLICKEYBYTES);
		// Sec
		let sec = KeyQuad::get_sec(&c, "/tmp/sec_key_h_test").unwrap();
		assert_eq!(sec.0 .0.as_ref().len(), sig.length_secret_key());
		assert_eq!(sec.0 .1.as_ref().len(), kem.length_secret_key());
		assert_eq!(sec.1 .0.as_ref().len(), sign::SECRETKEYBYTES);
		assert_eq!(sec.1 .1.as_ref().len(), kx::SECRETKEYBYTES);
		fs::remove_file("/tmp/pub_key_h_test").unwrap();
		fs::remove_file("/tmp/sec_key_h_test").unwrap();
	}
}

pub mod quantum {
	use super::*;
	pub type QuantumSKeyPair = (sig::SecretKey, kem::SecretKey);
	pub type QuantumPKeyPair = (sig::PublicKey, kem::PublicKey);
	pub struct QuantumKeyQuad {
		public_keypair: UnsafeCell<Option<QuantumPKeyPair>>,
		secret_keypair: UnsafeCell<Option<QuantumSKeyPair>>,
		sig_alg: sig::Sig,
		kem_alg: kem::Kem,
	}

	// Doesn't need to implement HybridQuad because it is always the front key
	// in the file
	impl QuantumKeyQuad {
		pub fn new() -> QuantumKeyQuad {
			QuantumKeyQuad {
				public_keypair: UnsafeCell::new(None),
				secret_keypair: UnsafeCell::new(None),
				sig_alg: enc_algos_in_use::get_q_sig_algo(),
				kem_alg: enc_algos_in_use::get_q_kem_algo(),
			}
		}
		pub fn pub_key_size(&self) -> u64 {
			(self.sig_alg.length_public_key() + self.kem_alg.length_public_key()) as u64
		}

		pub fn sec_key_size(&self) -> u64 {
			(self.sig_alg.length_secret_key() + self.kem_alg.length_secret_key()) as u64
		}
	}

	impl<'a> KeyQuad<'a, sig::PublicKey, kem::PublicKey, sig::SecretKey, kem::SecretKey>
		for QuantumKeyQuad
	{
		// Create keypairs, cache, and store in files at the passed paths
		fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
			let (mut pkey_f, mut skey_f) = (File::create(pkey_path)?, File::create(skey_path)?);
			let (sig_pkey, sig_skey) = self
				.sig_alg
				.keypair()
				.expect("Unable to generate quantum signature keypair.");
			let (kem_pkey, kem_skey) = self
				.kem_alg
				.keypair()
				.expect("Unable to generate quantum KEM keypair.");
			pkey_f.write_all(&sig_pkey.as_ref())?;
			pkey_f.write_all(&kem_pkey.as_ref())?;
			skey_f.write_all(&sig_skey.as_ref())?;
			skey_f.write_all(&kem_skey.as_ref())?;
			unsafe {
				*self.public_keypair.get() = Some((sig_pkey, kem_pkey));
				*self.secret_keypair.get() = Some((sig_skey, kem_skey));
			}
			Ok(())
		}
		// If this hasn't been previously generated, read in the keypair, cache
		// it for future use, and then only return the stored result.
		fn get_pub(&self, pkey_path: &str) -> Result<&(sig::PublicKey, kem::PublicKey)> {
			unsafe {
				if let None = *self.public_keypair.get() {
					let mut pkey_f = File::open(pkey_path)?;
					let mut sig_pkey_buff = vec![0u8; self.sig_alg.length_public_key()];
					let mut kem_pkey_buff = vec![0u8; self.kem_alg.length_public_key()];
					pkey_f.read_exact(&mut sig_pkey_buff)?;
					pkey_f.read_exact(&mut kem_pkey_buff)?;
					*self.public_keypair.get() = Some((
						self.sig_alg
							.public_key_from_bytes(&sig_pkey_buff)
							.unwrap()
							.to_owned(),
						self.kem_alg
							.public_key_from_bytes(&kem_pkey_buff)
							.unwrap()
							.to_owned(),
					));
					Ok((*self.public_keypair.get()).as_ref().unwrap())
				} else {
					Ok((*self.public_keypair.get()).as_ref().unwrap())
				}
			}
		}
		// See get_pub comments
		fn get_sec(&self, skey_path: &str) -> Result<&(sig::SecretKey, kem::SecretKey)> {
			unsafe {
				if let None = *self.secret_keypair.get() {
					let mut skey_f = File::open(skey_path)?;
					let mut sig_skey_buff = vec![0u8; self.sig_alg.length_secret_key()];
					let mut kem_skey_buff = vec![0u8; self.kem_alg.length_secret_key()];
					skey_f.read_exact(&mut sig_skey_buff)?;
					skey_f.read_exact(&mut kem_skey_buff)?;
					*self.secret_keypair.get() = Some((
						self.sig_alg
							.secret_key_from_bytes(&sig_skey_buff)
							.unwrap()
							.to_owned(),
						self.kem_alg
							.secret_key_from_bytes(&kem_skey_buff)
							.unwrap()
							.to_owned(),
					));
					Ok((*self.secret_keypair.get()).as_ref().unwrap())
				} else {
					Ok((*self.secret_keypair.get()).as_ref().unwrap())
				}
			}
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
}

pub mod classical {
	use super::*;
	pub use _classical::{ClassicalKeyQuad, ClassicalPKeyPair, ClassicalSKeyPair};
}

mod _classical {
	use super::*;
	pub type ClassicalSKeyPair = (sign::SecretKey, kx::SecretKey);
	pub type ClassicalPKeyPair = (sign::PublicKey, kx::PublicKey);

	pub struct ClassicalKeyQuad {
		public_keypair: UnsafeCell<Option<ClassicalPKeyPair>>,
		secret_keypair: UnsafeCell<Option<ClassicalSKeyPair>>,
	}

	impl ClassicalKeyQuad {
		pub fn new() -> ClassicalKeyQuad {
			ClassicalKeyQuad {
				public_keypair: UnsafeCell::new(None),
				secret_keypair: UnsafeCell::new(None),
			}
		}
	}
	// Can get away with only implementing hybrid, and then calling them from
	// KeyQuad with an offset of 0.
	impl<'a> KeyQuad<'a, sign::PublicKey, kx::PublicKey, sign::SecretKey, kx::SecretKey>
		for ClassicalKeyQuad
	{
		fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
			let (mut pkey_f, mut skey_f) = (File::create(pkey_path)?, File::create(skey_path)?);
			HybridQuad::gen(self, &mut pkey_f, &mut skey_f)
		}
		fn get_pub(&self, pkey_path: &str) -> Result<&(sign::PublicKey, kx::PublicKey)> {
			let mut pkey_f = File::open(pkey_path)?;
			HybridQuad::get_pub(self, &mut pkey_f, 0)
		}
		fn get_sec(&self, skey_path: &str) -> Result<&(sign::SecretKey, kx::SecretKey)> {
			let mut skey_f = File::open(skey_path)?;
			HybridQuad::get_sec(self, &mut skey_f, 0)
		}
	}

	impl HybridQuad<sign::PublicKey, kx::PublicKey, sign::SecretKey, kx::SecretKey>
		for ClassicalKeyQuad
	{
		// Must play well by taking a file reference. It could be appending to
		// an existing file.
		fn gen(&self, pkey: &mut File, skey: &mut File) -> Result<()> {
			let (sig_pkey, sig_skey) = sign::gen_keypair();
			let (kem_pkey, kem_skey) = kx::gen_keypair();
			pkey.write_all(&sig_pkey.0)?;
			pkey.write_all(&kem_pkey.0)?;
			skey.write_all(&sig_skey.0)?;
			skey.write_all(&kem_skey.0)?;
			unsafe {
				*self.public_keypair.get() = Some((sig_pkey, kem_pkey));
				*self.secret_keypair.get() = Some((sig_skey, kem_skey));
			}
			Ok(())
		}
		// Seek to the offset, read in, cache and return. If cached; just return
		fn get_pub(
			&self,
			pkey: &mut File,
			offset: u64,
		) -> Result<&(sign::PublicKey, kx::PublicKey)> {
			unsafe {
				if let None = *self.public_keypair.get() {
					pkey.seek(SeekFrom::Start(offset))?;
					let mut sig_pkey_buff = [0u8; sign::PUBLICKEYBYTES];
					let mut kx_pkey_buff = [0u8; kx::PUBLICKEYBYTES];
					pkey.read_exact(&mut sig_pkey_buff)?;
					pkey.read_exact(&mut kx_pkey_buff)?;
					*self.public_keypair.get() =
						Some((sign::PublicKey(sig_pkey_buff), kx::PublicKey(kx_pkey_buff)));
					Ok((*self.public_keypair.get()).as_ref().unwrap())
				} else {
					Ok((*self.public_keypair.get()).as_ref().unwrap())
				}
			}
		}
		// See get_pub comments
		fn get_sec(
			&self,
			skey: &mut File,
			offset: u64,
		) -> Result<&(sign::SecretKey, kx::SecretKey)> {
			unsafe {
				if let None = *self.secret_keypair.get() {
					skey.seek(SeekFrom::Start(offset))?;
					let mut sig_skey_buff = [0u8; sign::SECRETKEYBYTES];
					let mut kx_skey_buff = [0u8; kx::SECRETKEYBYTES];
					skey.read_exact(&mut sig_skey_buff)?;
					skey.read_exact(&mut kx_skey_buff)?;
					*self.secret_keypair.get() =
						Some((sign::SecretKey(sig_skey_buff), kx::SecretKey(kx_skey_buff)));
					Ok((*self.secret_keypair.get()).as_ref().unwrap())
				} else {
					Ok((*self.secret_keypair.get()).as_ref().unwrap())
				}
			}
		}
	}
	#[test]
	fn test_classical() {
		use std::fs;
		let c = ClassicalKeyQuad::new();
		KeyQuad::gen(&c, "/tmp/pub_key_c_test", "/tmp/sec_key_c_test").unwrap();
		// Pub
		let publ = KeyQuad::get_pub(&c, "/tmp/pub_key_c_test").unwrap();
		assert_eq!(publ.0.as_ref().len(), sign::PUBLICKEYBYTES);
		assert_eq!(publ.1.as_ref().len(), kx::PUBLICKEYBYTES);
		// Sec
		let sec = KeyQuad::get_sec(&c, "/tmp/sec_key_c_test").unwrap();
		assert_eq!(sec.0.as_ref().len(), sign::SECRETKEYBYTES);
		assert_eq!(sec.1.as_ref().len(), kx::SECRETKEYBYTES);
		fs::remove_file("/tmp/pub_key_c_test").unwrap();
		fs::remove_file("/tmp/sec_key_c_test").unwrap();
	}
}
