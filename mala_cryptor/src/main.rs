mod file_symmetric_encryption;
mod key_derivation;
mod key_file;

use clap::{App, AppSettings, SubCommand};
use file_symmetric_encryption::{decrypt_file_with_password, encrypt_file_with_password};
use rpassword::prompt_password_stdout;
use std::io::{Error, ErrorKind, Result};

fn main() -> Result<()> {
	let matches = App::new("mala_cryptor")
		.version("0.1.0")
		.author("ValliereMagic")
		.about("A command line file cryptography tool")
		.setting(AppSettings::ArgRequiredElseHelp)
		.subcommand(SubCommand::with_name("sym").setting(AppSettings::ArgRequiredElseHelp)
				.about("symmetric file encryption with a key_file or password")
				.args_from_usage(
					"-e, --encrypt=[FILENAME] 'specify a file to encrypt'
					-d, --decrypt=[FILENAME] 'specify a file to decrypt'
					-o, --output=[FILENAME] 'the target file to write the resultant file to'",
				))
		.subcommand(SubCommand::with_name("pub").setting(AppSettings::ArgRequiredElseHelp)
				.about("Public-Private key file encryption")
				.args_from_usage(
					"-m, --mode=[MODE] 'specify the mode to use. Options: [quantum, classic, hybrid]'
					-e, --encrypt=[FILENAME] 'specify a file to encrypt'
					-d, --decrypt=[FILENAME] 'specify a file to decrypt'
					-p, --private=[FILENAME] 'specify a public key file'
					-s, --secret=[FILENAME] 'specify a secret key file'
					-r, --recipient=[FILENAME] 'specify the recipient's public key'"
				))
		.get_matches();
	// Figure out what the user wants to do...
	if let Some(matches) = matches.subcommand_matches("sym") {
		enum Mode {
			Encrypt,
			Decrypt,
		}
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
	} else if let Some(_) = matches.subcommand_matches("pub") {
		println!("Not yet implemented!");
	}
	Ok(())
}
