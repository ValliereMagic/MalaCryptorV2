use super::*;
use crate::key_file::*;

impl IAsyCryptable for QuantumKeyQuad {
    type KEMSharedSecret = oqs::kem::SharedSecret;
    type KEMCipherText = oqs::kem::Ciphertext;
    type Signature = oqs::sig::Signature;
    // Shared secret based functions
    fn uses_cipher_text(&self) -> bool {
        true
    }
    fn create_shared_secret(
        &self,
        dest_pkey: &oqs::kem::PublicKey,
        _our_pkey: &oqs::kem::PublicKey,
        _our_skey: &oqs::kem::SecretKey,
    ) -> (oqs::kem::SharedSecret, Option<oqs::kem::Ciphertext>) {
        let (ct, ss) = get_q_kem_algo().encapsulate(dest_pkey).unwrap();
        (ss, Some(ct))
    }
    fn retrieve_shared_secret(
        &self,
        our_skey: &oqs::kem::SecretKey,
        _our_pkey: &oqs::kem::PublicKey,
        _sender_pkey: &oqs::kem::PublicKey,
        ciphertext: Option<&oqs::kem::Ciphertext>,
    ) -> oqs::kem::SharedSecret {
        get_q_kem_algo()
            .decapsulate(our_skey, ciphertext.expect("Ciphertext must be passed"))
            .expect("Unable to get shared secret.")
    }
    // Serializers and Metadata
    fn ciphertext_to_bytes<'a>(&self, ct: &'a oqs::kem::Ciphertext) -> &'a [u8] {
        ct.as_ref()
    }
    fn ciphertext_from_bytes(&self, bytes: &[u8]) -> oqs::kem::Ciphertext {
        get_q_kem_algo()
            .ciphertext_from_bytes(bytes)
            .expect("Unable to extract KEM ciphertext from file.")
            .to_owned()
    }
    fn ciphertext_length(&self) -> usize {
        get_q_kem_algo().length_ciphertext()
    }
    fn shared_secret_to_bytes<'a>(&self, ss: &'a oqs::kem::SharedSecret) -> &'a [u8] {
        ss.as_ref()
    }
    // Signature based functions
    fn sign(&self, data: &[u8], key: &oqs::sig::SecretKey) -> oqs::sig::Signature {
        get_q_sig_algo()
            .sign(data, key)
            .expect("Unable to sign digest")
    }
    fn verify(
        &self,
        message: &[u8],
        signature: &oqs::sig::Signature,
        key: &oqs::sig::PublicKey,
    ) -> bool {
        match get_q_sig_algo().verify(message, signature, key) {
            Ok(()) => true,
            Err(_) => false,
        }
    }
    // Serializers and Metadata
    fn signature_length(&self) -> i64 {
        get_q_sig_algo().length_signature() as i64
    }
    fn signature_to_bytes<'a>(&self, signature: &'a oqs::sig::Signature) -> &'a [u8] {
        signature.as_ref()
    }
    fn signature_from_bytes(&self, bytes: &[u8]) -> oqs::sig::Signature {
        get_q_sig_algo()
            .signature_from_bytes(bytes)
            .expect("Unable to extract signature from file.")
            .to_owned()
    }
}
