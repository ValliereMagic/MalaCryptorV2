// Base Signature expandable by composition as necessary
pub struct Signature {
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
			pub_offset: pub_offset,
			sec_offset: sec_offset,
		}
	}
	pub fn pub_offset(&self) -> u64 {
		self.pub_offset
	}
	pub fn sec_offset(&self) -> u64 {
		self.sec_offset
	}
}
