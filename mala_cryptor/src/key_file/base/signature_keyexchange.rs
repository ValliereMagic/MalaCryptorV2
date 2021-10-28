// The KeyPair trait is usually implemented for two different types of keypairs.
// KeyPairs for exchanging keys, and KeyPairs for signing data. These structs
// hold the base data required for all Signature and KeyExchange systems to be
// adapted for mala_cryptor.

// The offsets are used for hybrid combination keypairs. where multiple
// different keys are stored in a single file to create a hybrid keypair. For
// the best example is hybrid encryption used for mala_cryptor. A quantum
// keypair and classical keypair are combined and used together. 

// If the outer quantum encryption algorithm is broken / is unsecure for
// example, the data is still encrypted with the classical pair within; still
// protecting the data.

// Base Signature expandable by composition as necessary
pub struct Signature {
	pub_offset: u64,
	sec_offset: u64,
}
impl Signature {
	pub fn new(pub_offset: u64, sec_offset: u64) -> Signature {
		Signature {
			pub_offset,
			sec_offset,
		}
	}
	pub fn pub_offset(&self) -> u64 {
		self.pub_offset
	}
	pub fn sec_offset(&self) -> u64 {
		self.sec_offset
	}
}
// Base KeyExchange expandable by composition as necessary
pub struct KeyExchange {
	pub_offset: u64,
	sec_offset: u64,
}

impl KeyExchange {
	pub fn new(pub_offset: u64, sec_offset: u64) -> KeyExchange {
		KeyExchange {
			pub_offset,
			sec_offset,
		}
	}
	pub fn pub_offset(&self) -> u64 {
		self.pub_offset
	}
	pub fn sec_offset(&self) -> u64 {
		self.sec_offset
	}
}
