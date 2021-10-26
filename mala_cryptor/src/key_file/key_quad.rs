use super::key_pair::*;
use std::io::Result;
use std::marker::PhantomData;

pub trait KeyQuad<A, B, C, D> {
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

pub struct BaseKeyQuad<A, B, C, D, E, F>
where
	E: KeyPair<A, B>,
	F: KeyPair<C, D>,
{
	sign: E,
	kem: F,
	phantom_a: PhantomData<A>,
	phantom_b: PhantomData<B>,
	phantom_c: PhantomData<C>,
	phantom_d: PhantomData<D>,
}

impl<A, B, C, D, E, F> BaseKeyQuad<A, B, C, D, E, F>
where
	E: KeyPair<A, B>,
	F: KeyPair<C, D>,
{
	pub fn _new(sign: E, kem: F) -> BaseKeyQuad<A, B, C, D, E, F> {
		BaseKeyQuad {
			sign: sign,
			kem: kem,
			phantom_a: PhantomData,
			phantom_b: PhantomData,
			phantom_c: PhantomData,
			phantom_d: PhantomData,
		}
	}
}

impl<A, B, C, D, E, F> KeyQuad<A, C, B, D> for BaseKeyQuad<A, B, C, D, E, F>
where
	E: KeyPair<A, B>,
	F: KeyPair<C, D>,
{
	// Generate a public and private keyquad composed of a signature public and
	// secret pair as well as a key exchange public and secret pair
	fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
		gen(&self.sign, pkey_path, skey_path)?;
		gen(&self.kem, pkey_path, skey_path)
	}
	// Retrieve the public portion of the keypairs from the file paths passed
	fn get_pub(&self, pkey_path: &str) -> Result<(A, C)> {
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
	fn get_sec(&self, skey_path: &str) -> Result<(B, D)> {
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
		self.sign.pub_key_len() + self.kem.pub_key_len()
	}
	fn total_sec_size_bytes(&self) -> usize {
		self.sign.sec_key_len() + self.kem.sec_key_len()
	}
}
