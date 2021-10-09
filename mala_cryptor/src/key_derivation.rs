use sodiumoxide::crypto::{
	pwhash, pwhash::Salt, pwhash::MEMLIMIT_SENSITIVE, pwhash::OPSLIMIT_SENSITIVE,
	secretstream::Key, secretstream::KEYBYTES,
};

pub fn key_derive_from_pass(pass: &str, salt: Option<Salt>) -> (Salt, Key) {
	let mut key = Key([0u8; KEYBYTES]);
	let salt = match salt {
		Some(salt) => salt,
		None => pwhash::gen_salt(),
	};
	pwhash::derive_key(
		&mut key.0,
		&pass.as_bytes(),
		&salt,
		OPSLIMIT_SENSITIVE,
		MEMLIMIT_SENSITIVE,
	)
	.expect("Unable to derive key from password");
	(salt, key)
}
