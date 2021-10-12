use crate::file_symmetric_encryption;
use crate::key_file::*;
use std::io::{Error, ErrorKind, Result};

pub fn encrypt_quantum(
	dest_pkey_path: &str,
	skey_path: &str,
	pkey_path: &str,
	file_in_path: &str,
	file_out_path: &str,
) -> Result<()> {
	let dest_pkey = quantum::get_pub(dest_pkey_path)?;
	let skey = quantum::get_priv(skey_path)?;
	let pkey = quantum::get_pub(pkey_path)?;
	
	unimplemented!();
}
