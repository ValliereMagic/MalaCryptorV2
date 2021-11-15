mod enc;
mod enc_algos_in_use;
mod global_constants;
mod key_derivation;
mod key_file;
use clap::{crate_version, App, AppSettings, SubCommand};
use enc::*;
use key_file::*;
use rpassword::prompt_password_stdout;
use std::fs;
use std::io::{Error, ErrorKind, Result};

fn main() -> Result<()> {
	oqs::init();
	sodiumoxide::init().expect("Unable to initialize libsodium.");
	let matches = App::new("mala_cryptor")
		.version(crate_version!())
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
							-f, --from=[Input FILENAME] 'specify the public key of the sender [to verify the signature]'
							-s, --secret_key=[Input FILENAME] 'specify the secret key to decrypt the file'
							-p, --public_key=[Input FILENAME] 'specify our public key for key exchange'
							-i, --in_file=[FILENAME] 'specify a file to decrypt'
							-o, --out_file=[FILENAME] 'specify an output filename'"
						)
				)
		)
		.get_matches();
	// Helper function for all subcommands
	// Retrieve a key string, creating an error otherwise.
	fn get_key<'a>(matches: &'a clap::ArgMatches, key: &str, err_txt: &str) -> Result<&'a str> {
		match matches.value_of(key) {
			Some(s) => Ok(s),
			None => Err(Error::new(ErrorKind::Other, err_txt)),
		}
	}
	// The user is doing symmetric encryption
	if let Some(sym) = matches.subcommand_matches("sym") {
		// Symmetric key options helper function
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
			Ok((
				key_file,
				in_file,
				get_key(options, "out_file", "Output file must be specified")?,
			))
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
			let out_file = get_key(gen, "out_file", "Output file must be specified")?;
			symmetric::gen(out_file)?;
		}
	// The User is doing public key encryption
	} else if let Some(public) = matches.subcommand_matches("pub") {
		// Functions for retrieving public-secret key info from clap
		enum Mode {
			Quantum,
			Classical,
			Hybrid,
		}
		// Take the mode string, and error check it, then return it as an enum
		fn get_mode(matches: &clap::ArgMatches) -> Result<Mode> {
			let error_text = "Invalid Mode specified.";
			let m = matches
				.value_of("mode")
				.ok_or_else(|| Error::new(ErrorKind::Other, error_text))?
				.trim();
			return if m.len() > 1 {
				Err(Error::new(ErrorKind::Other, error_text))
			} else {
				let mode: char = m.chars().next().unwrap();
				match mode {
					'q' => Ok(Mode::Quantum),
					'c' => Ok(Mode::Classical),
					'h' => Ok(Mode::Hybrid),
					_ => return Err(Error::new(ErrorKind::Other, error_text)),
				}
			};
		}
		// ordering: (key, secret_key, public_key, in_file, out_file)
		fn get_info<'a>(
			matches: &'a clap::ArgMatches,
			key: &str,
		) -> Result<(&'a str, &'a str, &'a str, &'a str, &'a str)> {
			let key = get_key(
				matches,
				key,
				&format!("A {} key file must be specified.", key),
			)?;
			let secret_key = get_key(
				matches,
				"secret_key",
				"A Secret Key file must be specified.",
			)?;
			let public_key = get_key(
				matches,
				"public_key",
				"A Public Key file must be specified.",
			)?;
			let in_file = get_key(matches, "in_file", "Input file must be specified")?;
			let out_file = get_key(matches, "out_file", "Output file must be specified")?;
			Ok((key, secret_key, public_key, in_file, out_file))
		}
		// Logic
		if let Some(gen) = public.subcommand_matches("gen") {
			let secret_key = get_key(gen, "secret_key", "A Secret Key file must be specified.")?;
			let public_key = get_key(gen, "public_key", "A Public Key file must be specified.")?;
			match get_mode(gen)? {
				Mode::Quantum => {
					let q = QuantumKeyQuad::new();
					q.gen(public_key, secret_key)?
				}
				Mode::Classical => {
					let c = ClassicalKeyQuad::new();
					c.gen(public_key, secret_key)?
				}
				Mode::Hybrid => {
					let q = QuantumKeyQuad::new();
					let c = ClassicalKeyQuad::hyb_new(
						q.total_pub_size_bytes() as u64,
						q.total_sec_size_bytes() as u64,
					);
					q.gen(public_key, secret_key)?;
					c.gen(public_key, secret_key)?;
				}
			}
		} else if let Some(enc) = public.subcommand_matches("enc") {
			let (dest_key, secret_key, public_key, in_file, out_file) =
				get_info(enc, "destination")?;
			match get_mode(enc)? {
				Mode::Quantum => {
					let q = AsyCryptor::new(QuantumKeyQuad::new());
					q.encrypt_file(dest_key, secret_key, public_key, in_file, out_file)?
				}
				Mode::Classical => {
					let c = AsyCryptor::new(ClassicalKeyQuad::new());
					c.encrypt_file(dest_key, secret_key, public_key, in_file, out_file)?
				}
				Mode::Hybrid => {
					let q = QuantumKeyQuad::new();
					let c = AsyCryptor::new(ClassicalKeyQuad::hyb_new(
						q.total_pub_size_bytes() as u64,
						q.total_sec_size_bytes() as u64,
					));
					let q = AsyCryptor::new(q);
					let temp_file = out_file.to_owned() + ".intermediate";
					c.encrypt_file(dest_key, secret_key, public_key, in_file, &temp_file)?;
					q.encrypt_file(dest_key, secret_key, public_key, &temp_file, out_file)?;
					fs::remove_file(temp_file)?;
				}
			}
		} else if let Some(dec) = public.subcommand_matches("dec") {
			let (from_key, secret_key, public_key, in_file, out_file) = get_info(dec, "from")?;
			match get_mode(dec)? {
				Mode::Quantum => {
					let q = AsyCryptor::new(QuantumKeyQuad::new());
					q.decrypt_file(from_key, secret_key, public_key, in_file, out_file)?
				}
				Mode::Classical => {
					let c = AsyCryptor::new(ClassicalKeyQuad::new());
					c.decrypt_file(from_key, secret_key, public_key, in_file, out_file)?
				}
				Mode::Hybrid => {
					let q = QuantumKeyQuad::new();
					let c = AsyCryptor::new(ClassicalKeyQuad::hyb_new(
						q.total_pub_size_bytes() as u64,
						q.total_sec_size_bytes() as u64,
					));
					let q = AsyCryptor::new(q);
					let temp_file = out_file.to_owned() + ".intermediate";
					q.decrypt_file(from_key, secret_key, public_key, in_file, &temp_file)?;
					c.decrypt_file(from_key, secret_key, public_key, &temp_file, out_file)?;
				}
			}
		}
	}
	Ok(())
}
