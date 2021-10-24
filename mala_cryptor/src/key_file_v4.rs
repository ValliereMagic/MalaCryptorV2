use crate::enc_algos_in_use;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Result;
use std::io::SeekFrom;
use std::rc::Rc;

trait KeyPair<A, B> {
	// Generate a public and private key A, and B.
	fn gen_keypair(&self) -> (A, B);
	// Take a public key, and turn it into bytes
	fn pub_to_bytes(&self, pub_k: &A) -> Vec<u8>;
	// inverse, back to a public key
	fn bytes_to_pub(&self, bytes: &[u8]) -> A;
	fn sec_to_bytes(&self, sec_k: &B) -> Vec<u8>;
	fn bytes_to_sec(&self, bytes: &[u8]) -> B;
	// offset into the file to read / write a public key
	fn pub_offset(&self) -> u64;
	// offset into the file to read / write a secret key
	fn sec_offset(&self) -> u64;
	// The length in bytes of a public key
	fn pub_key_len(&self) -> usize;
	// The length in bytes of a secret key
	fn sec_key_len(&self) -> usize;
}

trait KeyQuad<A, B, C, D> {
	// Generate a public and private keyquad composed of a signature public and
	// secret pair as well as a key exchange public and secret pair
	fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()>;
	// Retrieve the public portion of the keypairs from the file paths passed
	fn get_pub(&self, pkey_path: &str) -> Result<(A, B)>;
	fn get_sec(&self, skey_path: &str) -> Result<(C, D)>;
	// The total size that the file will be for each of the key parts. This is
	// used for composition key files where multiple different keypairs are
	// stored in the same file.
	fn total_pub_size_bytes(&self) -> usize;
	fn total_sec_size_bytes(&self) -> usize;
}

// Generate a keypair and place their public and secret components into their
// separate files as passed.
fn gen<A, B, T>(pair: &T, pkey_path: &str, skey_path: &str) -> Result<()>
where
	T: KeyPair<A, B>,
{
	// Open the files
	let mut pkey_f = OpenOptions::new()
		.read(true)
		.write(true)
		.create(true)
		.open(pkey_path)?;
	pkey_f.seek(SeekFrom::Start(pair.pub_offset()))?;
	let mut skey_f = OpenOptions::new()
		.read(true)
		.write(true)
		.create(true)
		.open(skey_path)?;
	skey_f.seek(SeekFrom::Start(pair.sec_offset()))?;
	// Generate the keypair, and write out the keys to their separate files.
	let keypair = pair.gen_keypair();
	// This could be async
	pkey_f.write_all(&pair.pub_to_bytes(&keypair.0))?;
	skey_f.write_all(&pair.sec_to_bytes(&keypair.1))?;
	Ok(())
}

// Specify which type of key to retrieve from the file for the generic get function.
enum KeyVariant<A, B> {
	Public(A),
	Secret(B),
}

// Zero sized type for Key Variant. Allowing to create it without any extra size
struct Zst;

impl Zst {
	pub fn new() -> Zst {
		Zst {}
	}
}

// Retrieve a public OR private key depending on the variant of KeyVariant
// Passed; result is the same variant as the KeyVariant passed in.
fn get<A, B, T>(
	variant: KeyVariant<Zst, Zst>,
	pair: &T,
	pkey_path: &str,
) -> Result<KeyVariant<A, B>>
where
	T: KeyPair<A, B>,
{
	let mut file = OpenOptions::new().read(true).open(pkey_path)?;
	match variant {
		KeyVariant::Public(_) => {
			file.seek(SeekFrom::Start(pair.pub_offset()))?;
			let mut buff = vec![0u8; pair.pub_key_len()];
			file.read_exact(&mut buff)?;
			Ok(KeyVariant::Public(pair.bytes_to_pub(&buff)))
		}
		KeyVariant::Secret(_) => {
			file.seek(SeekFrom::Start(pair.sec_offset()))?;
			let mut buff = vec![0u8; pair.sec_key_len()];
			file.read_exact(&mut buff)?;
			Ok(KeyVariant::Secret(pair.bytes_to_sec(&buff)))
		}
	}
}

pub mod hybrid {
	use super::*;
	pub struct HybridKeyQuad {
		q: quantum::QuantumKeyQuad,
	}
	impl HybridKeyQuad {
		fn new() -> HybridKeyQuad {
			HybridKeyQuad {
				q: quantum::QuantumKeyQuad::new(0),
			}
		}
	}
}

pub mod quantum {
	use super::*;
	use oqs::kem;
	use oqs::sig;
	pub type QuantumSKeyPair = (sig::SecretKey, kem::SecretKey);
	pub type QuantumPKeyPair = (sig::PublicKey, kem::PublicKey);
	struct Signature {
		sig: sig::Sig,
		base_offset: u64,
	}
	impl Signature {
		fn new(base_offset: u64) -> Signature {
			Signature {
				sig: enc_algos_in_use::get_q_sig_algo(),
				base_offset: base_offset,
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
			self.base_offset
		}
		fn sec_offset(&self) -> u64 {
			self.base_offset
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
		base_offset: u64,
	}
	impl KeyExchange {
		fn new(sig: Rc<Signature>, base_offset: u64) -> KeyExchange {
			KeyExchange {
				sig: sig,
				kem: enc_algos_in_use::get_q_kem_algo(),
				base_offset: base_offset,
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
			self.sig.pub_key_len() as u64 + self.base_offset
		}
		fn sec_offset(&self) -> u64 {
			self.sig.sec_key_len() as u64 + self.base_offset
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
		pub fn new(base_offset: u64) -> QuantumKeyQuad {
			let sig = Rc::new(Signature::new(base_offset));
			let sig_2 = Rc::clone(&sig);
			QuantumKeyQuad {
				sig: sig,
				kem: KeyExchange::new(sig_2, base_offset),
			}
		}
	}

	impl KeyQuad<sig::PublicKey, kem::PublicKey, sig::SecretKey, kem::SecretKey> for QuantumKeyQuad {
		fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
			gen(&(*self.sig), pkey_path, skey_path)?;
			gen(&self.kem, pkey_path, skey_path)?;
			Ok(())
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
}
