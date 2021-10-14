mod enc_algos_in_use;
mod file_asymmetric_encryption;
mod file_symmetric_encryption;
mod key_derivation;
mod global_constants;
mod key_file;
mod key_file_v3;

use clap::{App, AppSettings, SubCommand};
use file_symmetric_encryption::*;
use key_file::*;
use oqs;
use rpassword::prompt_password_stdout;
use sodiumoxide;
use std::io::{Error, ErrorKind, Result};

fn main() -> Result<()> {
	oqs::init();
	sodiumoxide::init().expect("Unable to initialize libsodium.");
	let matches = App::new("mala_cryptor")
		.version("0.2.0")
		.author("ValliereMagic")
		.about("A command line file cryptography tool")
		.setting(AppSettings::ArgRequiredElseHelp)
		// Symmetric File encryption (With password or file)
		.subcommand(SubCommand::with_name("sym")
				.setting(AppSettings::ArgRequiredElseHelp)
				.about("symmetric file encryption with a key_file or password")
				// Encryption of files
				.subcommand(SubCommand::with_name("enc")
						.setting(AppSettings::ArgRequiredElseHelp)
						.about("encrypt a file")
						.args_from_usage(
							"-k, --key_file=[FILENAME] 'specify a key file to use (if not specified, you will be prompted for a password)'
							-i, --in_file=[FILENAME] 'specify a file to encrypt'
							-o, --out_file=[FILENAME] 'specify an output filename'"
						)
				)
				// Decryption of files
				.subcommand(SubCommand::with_name("dec")
						.setting(AppSettings::ArgRequiredElseHelp)
						.about("decrypt a file")
						.args_from_usage(
							"-k, --key_file=[FILENAME] 'specify a key file to use (if not specified, you will be prompted for a password)'
							-i, --in_file=[FILENAME] 'specify a file to decrypt'
							-o, --out_file=[FILENAME] 'specify an output filename'"
						)
				)
				// Generation of a keyfile
				.subcommand(SubCommand::with_name("gen")
						.setting(AppSettings::ArgRequiredElseHelp)
						.about("Generate a symmetric keyfile")
						.arg_from_usage("-o, --out_file=[FILENAME] 'specify an output filename'")
				)
		)
		// Public-Private keypair encryption (With keyfiles)
		.subcommand(SubCommand::with_name("pub")
				.setting(AppSettings::ArgRequiredElseHelp)
				.about("Public-Private key file encryption")
				// Keypair generation
				.subcommand(SubCommand::with_name("gen")
						.setting(AppSettings::ArgRequiredElseHelp)
						.about("Generate a public-private keypair")
						.args_from_usage(
							"-m, --mode=['q', 'c', 'h'] 'specify type of keypair to generate: q: quantum, c: classical, h: hybrid (both, in cascade)'
							-s, --secret_key=[Output FILENAME] 'specify the output secret key filename'
							-p, --public_key=[Output FILENAME] 'specify the output public key filename'"
						)
				)
				// Encryption and Signing
				.subcommand(SubCommand::with_name("enc")
						.setting(AppSettings::ArgRequiredElseHelp)
						.about("Encrypt a file using a public key [and sign]")
						.args_from_usage(
							"-m, --mode=['q', 'c', 'h'] 'specify type of keypair to generate: q: quantum, c: classical, h: hybrid (both, in cascade)'
							-d, --destination=[Input FILENAME] 'specify the public key of the recipient'
							-s, --secret_key=[Input FILENAME] 'specify the secret key to sign with'
							-p, --public_key=[Input FILENAME] 'specify our public key for key exchange'
							-i, --in_file=[FILENAME] 'specify a file to encrypt'
							-o, --out_file=[FILENAME] 'specify an output filename'"
						)
				)
				// Decryption and Signing
				.subcommand(SubCommand::with_name("dec")
						.setting(AppSettings::ArgRequiredElseHelp)
						.about("Decrypt a file using a public key [and verify signature]")
						.args_from_usage(
							"-m, --mode=['q', 'c', 'h'] 'specify type of keypair to generate: q: quantum, c: classical, h: hybrid (both, in cascade)'
							-f, --from=[Input FILENAME] 'specify the public key of the sender'
							-s, --secret_key=[Input FILENAME] 'specify the secret key to sign with'
							-p, --public_key=[Input FILENAME] 'specify our public key for key exchange'
							-i, --in_file=[FILENAME] 'specify a file to encrypt'
							-o, --out_file=[FILENAME] 'specify an output filename'"
						)
				)
		)
		.get_matches();
	// The user is doing symmetric encryption
	if let Some(sym) = matches.subcommand_matches("sym") {
		// Get the options from clap (need to do for both enc and dec)
		fn get_outfile_options<'a>(options: &'a clap::ArgMatches) -> Result<&'a str> {
			match options.value_of("out_file") {
				Some(f) => Ok(f),
				None => {
					return Err(Error::new(
						ErrorKind::Other,
						"Output file must be specified.",
					));
				}
			}
		}
		fn get_sym_options<'a>(
			options: &'a clap::ArgMatches,
		) -> Result<(Option<&'a str>, &'a str, &'a str)> {
			// Get the options from the user
			let key_file = options.value_of("key_file");
			let in_file = match options.value_of("in_file") {
				Some(f) => f,
				None => {
					return Err(Error::new(
						ErrorKind::Other,
						"Input file must be specified.",
					));
				}
			};
			Ok((key_file, in_file, get_outfile_options(options)?))
		}
		// User is encrypting a file
		if let Some(enc) = sym.subcommand_matches("enc") {
			let (key_file, in_file, out_file) = get_sym_options(enc)?;
			if let Some(key_file_path) = key_file {
				encrypt_file_with_key(in_file, out_file, symmetric::get(key_file_path)?)?;
			} else {
				// Get the password from the user
				let pass = prompt_password_stdout("Enter the file password: ").unwrap();
				encrypt_file_with_password(in_file, out_file, &pass)?;
			}
		// User is decrypting a file
		} else if let Some(dec) = sym.subcommand_matches("dec") {
			let (key_file, in_file, out_file) = get_sym_options(dec)?;
			if let Some(key_file_path) = key_file {
				decrypt_file_with_key(in_file, out_file, symmetric::get(key_file_path)?)?;
			} else {
				// Get the password from the user
				let pass = prompt_password_stdout("Enter the file password: ").unwrap();
				decrypt_file_with_password(in_file, out_file, &pass)?;
			}
		// User is generating a keyfile
		} else if let Some(gen) = sym.subcommand_matches("gen") {
			let out_file = get_outfile_options(gen)?;
			symmetric::gen(&out_file)?;
		}
	// The User is doing public key encryption
	} else if let Some(public) = matches.subcommand_matches("pub") {
		if let Some(gen) = public.subcommand_matches("gen") {
			let secret_key = match gen.value_of("secret_key") {
				Some(s) => s,
				None => {
					return Err(Error::new(
						ErrorKind::Other,
						"A Secret Key file must be specified.",
					));
				}
			};
			let public_key = match gen.value_of("public_key") {
				Some(p) => p,
				None => {
					return Err(Error::new(
						ErrorKind::Other,
						"A Public Key file must be specified.",
					));
				}
			};
			match gen.value_of("mode") {
				Some(m) => {
					let m = m.trim();
					if m.len() > 1 {
						return Err(Error::new(ErrorKind::Other, "Invalid Mode specified."));
					}
					match m.chars().next().unwrap() {
						'q' => quantum::gen(public_key, secret_key)?,
						'c' => classical::gen(public_key, secret_key)?,
						'h' => hybrid::gen(public_key, secret_key)?,
						_ => {
							return Err(Error::new(ErrorKind::Other, "Invalid Mode specified."));
						}
					}
				}
				None => return Err(Error::new(ErrorKind::Other, "A mode must be specified.")),
			};
		}
	}
	Ok(())
}
