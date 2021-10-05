mod file_symmetric_encryption;
mod key_derivation;

use clap::{App, AppSettings};
use file_symmetric_encryption::{decrypt_file_with_password, encrypt_file_with_password};
use rpassword::prompt_password_stdout;
use std::io::{Error, ErrorKind, Result};

enum Mode {
	Encrypt,
	Decrypt,
}

fn main() -> Result<()> {
	let matches = App::new("mala_cryptor")
		.version("0.1.0")
		.author("ValliereMagic")
		.about("A command line file cryptography tool")
		.args_from_usage(
			"-e, --encrypt=[FILENAME] 'specify a file to encrypt' \n
			-d, --decrypt=[FILENAME] 'specify a file to decrypt' \n
			-o, --output=[FILENAME] 'the target file to write the resultant file to'",
		)
		.setting(AppSettings::ArgRequiredElseHelp)
		.get_matches();
	// Figure out what the user wants to do...
	let (mode, in_file) = if let Some(encrypt) = matches.value_of("encrypt") {
		(Mode::Encrypt, encrypt)
	} else if let Some(decrypt) = matches.value_of("decrypt") {
		(Mode::Decrypt, decrypt)
	} else {
		return Err(Error::new(
			ErrorKind::Other,
			"Either encrypt or decrypt must be specified.",
		));
	};
	let out_file: &str = match matches.value_of("output") {
		Some(o) => o,
		None => {
			return Err(Error::new(
				ErrorKind::Other,
				"Output file must be specified.",
			));
		}
	};
	// Get the password from the user
	let pass = prompt_password_stdout("Enter the file password: ").unwrap();
	match mode {
		Mode::Encrypt => {
			encrypt_file_with_password(in_file, out_file, &pass)?;
		}
		Mode::Decrypt => {
			decrypt_file_with_password(in_file, out_file, &pass)?;
		}
	}
	Ok(())
}
