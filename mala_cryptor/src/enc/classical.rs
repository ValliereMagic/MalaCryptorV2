use super::*;
use crate::key_file::*;
use sodiumoxide::crypto::kx;
use sodiumoxide::crypto::sign;
use std::convert::TryInto;

impl
	IAsyCryptable<
		kx::SessionKey,
		(),
		kx::PublicKey,
		kx::SecretKey,
		sign::PublicKey,
		sign::SecretKey,
		sign::Signature,
	> for ClassicalKeyQuad
{
	// Shared secret based functions
	fn uses_cipher_text(&self) -> bool {
		false
	}
	fn create_shared_secret(
		&self,
		dest_pkey: &kx::PublicKey,
		our_pkey: &kx::PublicKey,
		our_skey: &kx::SecretKey,
	) -> (kx::SessionKey, Option<()>) {
		let (_, ss) = kx::client_session_keys(our_pkey, our_skey, dest_pkey)
			.expect("Unable to derive shared secret.");
		(ss, None)
	}
	fn retrieve_shared_secret(
		&self,
		our_skey: &kx::SecretKey,
		our_pkey: &kx::PublicKey,
		sender_pkey: &kx::PublicKey,
		_ciphertext: Option<&()>,
	) -> kx::SessionKey {
		let (ss, _) = kx::server_session_keys(our_pkey, our_skey, sender_pkey)
			.expect("Unable to retrieve shared secret.");
		ss
	}
	// Serializers and Metadata
	fn ciphertext_to_bytes<'a>(&self, _ct: &'a ()) -> &'a [u8] {
		unreachable!();
	}
	fn ciphertext_from_bytes(&self, _bytes: &[u8]) {
		unreachable!();
	}
	fn ciphertext_length(&self) -> usize {
		unreachable!();
	}
	fn shared_secret_to_bytes<'a>(&self, ss: &'a kx::SessionKey) -> &'a [u8] {
		ss.as_ref()
	}
	// Signature based functions
	fn sign(&self, data: &[u8], key: &sign::SecretKey) -> sign::Signature {
		sign::sign_detached(data, key)
	}
	fn verify(&self, message: &[u8], signature: &sign::Signature, key: &sign::PublicKey) -> bool {
		sign::verify_detached(signature, message, key)
	}
	// Serializers and Metadata
	fn signature_length(&self) -> i64 {
		sign::SIGNATUREBYTES as i64
	}
	fn signature_to_bytes<'a>(&self, signature: &'a sign::Signature) -> &'a [u8] {
		signature.as_ref()
	}
	fn signature_from_bytes(&self, bytes: &[u8]) -> sign::Signature {
		sign::Signature::new(
			bytes.to_owned()[0..sign::SIGNATUREBYTES]
				.try_into()
				.expect("Signature bytes not long enough."),
		)
	}
}
