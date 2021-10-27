use super::key_pair::*;
use std::io::Result;
use std::marker::PhantomData;

// Generic functions representing the set of 2 KeyPairs used for asymmetric
// encryption in mala_cryptor `KeyQuad`; which are a Signature Pair, and
// KeyExchange pair. The Interface allows specialization of KeyQuads with
// concrete types, as well as reducing a lot of code use.

// It was designed to allow different algorithms to be used in mala_cryptor in
// the future with very little code change. [re-implementing KeyPair for each of
// them]

pub trait IKeyQuad<A, B, C, D> {
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

pub struct KeyQuad<A, B, C, D, E, F>
where
	E: IKeyPair<A, B>,
	F: IKeyPair<C, D>,
{
	sign: E,
	kem: F,
	phantom_a: PhantomData<A>,
	phantom_b: PhantomData<B>,
	phantom_c: PhantomData<C>,
	phantom_d: PhantomData<D>,
}

impl<A, B, C, D, E, F> KeyQuad<A, B, C, D, E, F>
where
	E: IKeyPair<A, B>,
	F: IKeyPair<C, D>,
{
	pub fn _new(sign: E, kem: F) -> KeyQuad<A, B, C, D, E, F> {
		KeyQuad {
			sign: sign,
			kem: kem,
			phantom_a: PhantomData,
			phantom_b: PhantomData,
			phantom_c: PhantomData,
			phantom_d: PhantomData,
		}
	}
}

impl<A, B, C, D, E, F> IKeyQuad<A, C, B, D> for KeyQuad<A, B, C, D, E, F>
where
	E: IKeyPair<A, B>,
	F: IKeyPair<C, D>,
{
	// Generate a public and private keyquad composed of a signature public and
	// secret pair as well as a key exchange public and secret pair
	fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
		gen(&self.sign, pkey_path, skey_path)?;
		gen(&self.kem, pkey_path, skey_path)
	}
	// Retrieve the public portion of the keypairs from the file paths passed
	fn get_pub(&self, pkey_path: &str) -> Result<(A, C)> {
		let sig = match get(KeyVariant::Public(()), &self.sign, pkey_path)? {
			KeyVariant::Public(p) => p,
			_ => unreachable!(),
		};
		let kem = match get(KeyVariant::Public(()), &self.kem, pkey_path)? {
			KeyVariant::Public(p) => p,
			_ => unreachable!(),
		};
		Ok((sig, kem))
	}
	fn get_sec(&self, skey_path: &str) -> Result<(B, D)> {
		let sig = match get(KeyVariant::Secret(()), &self.sign, skey_path)? {
			KeyVariant::Secret(s) => s,
			_ => unreachable!(),
		};
		let kem = match get(KeyVariant::Secret(()), &self.kem, skey_path)? {
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