use super::*;
use crate::key_file::*;

use pqcrypto_classicmceliece::ffi::*;
use pqcrypto_dilithium::ffi::*;

type QSignature = [u8; PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES];

impl Create for QSignature {
    fn default() -> Self {
        [0u8; PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES]
    }
}

type QKEMCipherText = [u8; PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES];

impl Create for QKEMCipherText {
    fn default() -> Self {
        [0u8; PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES]
    }
}

impl IAsyCryptable for QuantumKeyQuad {
    type KEMSharedSecret = SecretMem<PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_BYTES>;
    type KEMCipherText = [u8; PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    type Signature = QSignature;
    // Shared secret based functions
    fn uses_cipher_text(&self) -> bool {
        true
    }
    fn create_shared_secret(
        &self,
        dest_pkey: &Self::KemPub,
        _our_pkey: &Self::KemPub,
        _our_skey: &Self::KemSec,
    ) -> (Self::KEMSharedSecret, Option<Self::KEMCipherText>) {
        let mut ct = Self::KEMCipherText::default();
        let mut ss = Self::KEMSharedSecret::default();
        unsafe {
            match PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(
                ct.as_mut_ptr(),
                ss.as_mut_ptr(),
                dest_pkey.as_ptr(),
            ) {
                0 => (ss, Some(ct)),
                _ => panic!("Suspicious client quantum public key, bailing out."),
            }
        }
    }
    fn retrieve_shared_secret(
        &self,
        our_skey: &Self::KemSec,
        _our_pkey: &Self::KemPub,
        _sender_pkey: &Self::KemPub,
        ciphertext: Option<&Self::KEMCipherText>,
    ) -> Self::KEMSharedSecret {
        let mut ss = Self::KEMSharedSecret::default();
        unsafe {
            match PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec(
                ss.as_mut_ptr(),
                ciphertext.expect("Ciphertext must be passed.").as_ptr(),
                our_skey.as_ptr(),
            ) {
                0 => ss,
                _ => panic!("Suspicious server quantum public key, bailing out."),
            }
        }
    }
    // Serializers and Metadata
    fn ciphertext_bytes<'a>(&self, ct: &'a Self::KEMCipherText) -> &'a [u8] {
        ct.as_ref()
    }
    fn ciphertext_bytes_mut<'a>(&self, ct: &'a mut Self::KEMCipherText) -> &'a mut [u8] {
        ct.as_mut()
    }
    fn ciphertext_length(&self) -> usize {
        PQCLEAN_MCELIECE8192128_CLEAN_CRYPTO_CIPHERTEXTBYTES
    }
    fn shared_secret_to_bytes<'a>(&self, ss: &'a Self::KEMSharedSecret) -> &'a [u8] {
        ss.as_ref()
    }
    // Signature based functions
    fn sign(&self, data: &[u8], key: &Self::SigSec) -> Self::Signature {
        unsafe {
            let mut sig_len: usize = PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES;
            let mut signature = Self::Signature::default();
            match PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(
                signature.as_mut_ptr(),
                &mut sig_len as *mut _,
                &data[0] as *const _,
                data.len(),
                key.as_ptr(),
            ) {
                0 => (),
                _ => panic!("Our private key is suspicious, bailing out."),
            }
            signature
        }
    }
    fn verify(&self, message: &[u8], signature: &Self::Signature, key: &Self::SigPub) -> bool {
        unsafe {
            match PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(
                signature.as_ptr(),
                signature.len(),
                message.as_ptr(),
                message.len(),
                key.as_ptr(),
            ) {
                0 => true,
                _ => false,
            }
        }
    }
    // Serializers and Metadata
    fn signature_length(&self) -> i64 {
        PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_BYTES as i64
    }
    fn signature_bytes<'a>(&self, signature: &'a Self::Signature) -> &'a [u8] {
        signature.as_ref()
    }
    fn signature_bytes_mut<'a>(&self, signature: &'a mut Self::Signature) -> &'a mut [u8] {
        signature.as_mut()
    }
}

#[test]
fn test_quantum() {
    use crate::key_file::*;
    use std::fs::*;
    use std::io::prelude::*;
    let mut to_encrypt = [0u8; 40_000];
    {
        let mut source_file = File::open("/dev/urandom").unwrap();
        let mut dest_file = File::create("/tmp/test_enc_q").unwrap();
        source_file.read_exact(&mut to_encrypt).unwrap();
        dest_file.write_all(&to_encrypt).unwrap();
    }
    let q = QuantumKeyQuad::new();

    q.gen("/tmp/pub_key_q_source", "/tmp/sec_key_q_source")
        .unwrap();
    q.gen("/tmp/pub_key_q_dest", "/tmp/sec_key_q_dest").unwrap();

    use crate::AsyCryptor;

    let q_cryptor = AsyCryptor::new(q);
    q_cryptor
        .encrypt_file(
            "/tmp/pub_key_q_dest",
            "/tmp/sec_key_q_source",
            "/tmp/pub_key_q_source",
            "/tmp/test_enc_q",
            "/tmp/test_enc_q.enc",
        )
        .unwrap();
    q_cryptor
        .decrypt_file(
            "/tmp/pub_key_q_source",
            "/tmp/sec_key_q_dest",
            "/tmp/pub_key_q_dest",
            "/tmp/test_enc_q.enc",
            "/tmp/test_enc_q.dec",
        )
        .unwrap();
    let mut decrypted = [0u8; 40_000];
    {
        let mut dest_file = File::open("/tmp/test_enc_q.dec").unwrap();
        dest_file.read_exact(&mut decrypted).unwrap();
    }

    // cleanup
    remove_file("/tmp/test_enc_q").unwrap();
    remove_file("/tmp/pub_key_q_source").unwrap();
    remove_file("/tmp/sec_key_q_source").unwrap();
    remove_file("/tmp/pub_key_q_dest").unwrap();
    remove_file("/tmp/sec_key_q_dest").unwrap();
    remove_file("/tmp/test_enc_q.dec").unwrap();

    assert_eq!(to_encrypt, decrypted);
}
