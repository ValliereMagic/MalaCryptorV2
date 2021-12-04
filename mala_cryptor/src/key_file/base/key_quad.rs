use super::key_pair::*;
use std::io::Result;
use std::marker::PhantomData;

// Generic functions representing the set of 2 KeyPairs used for asymmetric
// encryption in mala_cryptor `KeyQuad`; which are a Signature Pair, and
// KeyExchange pair. The Interface allows specialization of KeyQuads with
// concrete types, as well as reducing a lot of code reuse.

// It was designed to allow different algorithms to be used in mala_cryptor in
// the future with very little code change. [re-implementing KeyPair for each of
// them]

pub trait IKeyQuad<SigPub, SigSec, KemPub, KemSec> {
	// Generate a public and private keyquad composed of a signature public and
	// secret pair as well as a key exchange public and secret pair
	fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()>;
	// Retrieve the public portion of the keypairs from the file paths passed
	fn get_pub(&self, pkey_path: &str) -> Result<(SigPub, KemPub)>;
	fn get_sec(&self, skey_path: &str) -> Result<(SigSec, KemSec)>;
	// The total size that the file will be for each of the key parts. This is
	// used for composition key files where multiple different keypairs are
	// stored in the same file.
	fn total_pub_size_bytes(&self) -> usize;
	fn total_sec_size_bytes(&self) -> usize;
}

// Specifies the standard way of creating a KeyQuad. A variant that has an
// offset for hybrid encryption where multiple rounds are done; and a basic
// variant with offsets of 0.
pub trait IKeyQuadCreator<SigPub, SigSec, KemPub, KemSec, SigKeyPair, KemKeyPair>
where
	SigKeyPair: IKeyPair<SigPub, SigSec>,
	KemKeyPair: IKeyPair<KemPub, KemSec>,
{
	#[allow(clippy::new_ret_no_self)]
	fn new() -> KeyQuad<SigPub, SigSec, KemPub, KemSec, SigKeyPair, KemKeyPair>;
	fn hyb_new(
		pub_offset: u64,
		sec_offset: u64,
	) -> KeyQuad<SigPub, SigSec, KemPub, KemSec, SigKeyPair, KemKeyPair>;
}

// Generic KeyQuad struct extensible by any specific implementation
pub struct KeyQuad<SigPub, SigSec, KemPub, KemSec, SigKeyPair, KemKeyPair>
where
	SigKeyPair: IKeyPair<SigPub, SigSec>,
	KemKeyPair: IKeyPair<KemPub, KemSec>,
{
	sign: SigKeyPair,
	kem: KemKeyPair,
	phantom_a: PhantomData<SigPub>,
	phantom_b: PhantomData<SigSec>,
	phantom_c: PhantomData<KemPub>,
	phantom_d: PhantomData<KemSec>,
}

// Base creation of a KeyQuad. Used by specific implementations to bootstrap
// themselves
impl<SigPub, SigSec, KemPub, KemSec, SigKeyPair, KemKeyPair>
	KeyQuad<SigPub, SigSec, KemPub, KemSec, SigKeyPair, KemKeyPair>
where
	SigKeyPair: IKeyPair<SigPub, SigSec>,
	KemKeyPair: IKeyPair<KemPub, KemSec>,
{
	pub fn create(
		sign: SigKeyPair,
		kem: KemKeyPair,
	) -> KeyQuad<SigPub, SigSec, KemPub, KemSec, SigKeyPair, KemKeyPair> {
		KeyQuad {
			sign,
			kem,
			phantom_a: PhantomData,
			phantom_b: PhantomData,
			phantom_c: PhantomData,
			phantom_d: PhantomData,
		}
	}
}

// Universal implementation of the different operations that a KeyQuad needs to
// perform
impl<SigPub, SigSec, KemPub, KemSec, SigKeyPair, KemKeyPair>
	IKeyQuad<SigPub, SigSec, KemPub, KemSec>
	for KeyQuad<SigPub, SigSec, KemPub, KemSec, SigKeyPair, KemKeyPair>
where
	SigKeyPair: IKeyPair<SigPub, SigSec>,
	KemKeyPair: IKeyPair<KemPub, KemSec>,
{
	// Generate a public and private keyquad composed of a signature public and
	// secret pair as well as a key exchange public and secret pair
	fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
		gen(&self.sign, pkey_path, skey_path)?;
		gen(&self.kem, pkey_path, skey_path)
	}
	// Retrieve the public portion of the keypairs from the file paths passed
	fn get_pub(&self, pkey_path: &str) -> Result<(SigPub, KemPub)> {
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
	fn get_sec(&self, skey_path: &str) -> Result<(SigSec, KemSec)> {
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
