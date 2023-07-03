use super::*;
use crate::key_file::*;
use libsodium_sys::*;
use std::ptr;

type SodiumSignature = [u8; crypto_sign_BYTES as usize];
const USIZE_CRYPTO_KX_SESSIONKEYBYTES: usize = crypto_kx_SESSIONKEYBYTES as usize;
type SodiumSessionKey = SecretMem<USIZE_CRYPTO_KX_SESSIONKEYBYTES>;

impl Create for SodiumSignature {
    fn default() -> Self {
        [0u8; crypto_sign_BYTES as usize]
    }
}

impl Create for () {
    fn default() -> Self {
        ()
    }
}

impl IAsyCryptable for ClassicalKeyQuad {
    type KEMSharedSecret = SodiumSessionKey;
    type KEMCipherText = ();
    type Signature = SodiumSignature;
    // Shared secret based functions
    fn uses_cipher_text(&self) -> bool {
        false
    }
    fn create_shared_secret(
        &self,
        dest_pkey: &SodiumKEMPub,
        our_pkey: &SodiumKEMPub,
        our_skey: &SodiumKEMSec,
    ) -> (SodiumSessionKey, Option<()>) {
        unsafe {
            let (mut rx, mut tx) = (SodiumSessionKey::default(), SodiumSessionKey::default());
            match crypto_kx_client_session_keys(
                rx.as_mut_ptr(),
                tx.as_mut_ptr(),
                our_pkey.as_ptr(),
                our_skey.as_ptr(),
                dest_pkey.as_ptr(),
            ) {
                0 => (),
                _ => panic!("Suspicious client public key, bailing out."),
            }
            (tx, None)
        }
    }
    fn retrieve_shared_secret(
        &self,
        our_skey: &SodiumKEMSec,
        our_pkey: &SodiumKEMPub,
        sender_pkey: &SodiumKEMPub,
        _ciphertext: Option<&()>,
    ) -> SodiumSessionKey {
        unsafe {
            let (mut rx, mut tx) = (SodiumSessionKey::default(), SodiumSessionKey::default());
            match crypto_kx_server_session_keys(
                rx.as_mut_ptr(),
                tx.as_mut_ptr(),
                our_pkey.as_ptr(),
                our_skey.as_ptr(),
                sender_pkey.as_ptr(),
            ) {
                0 => (),
                _ => panic!("Suspicious server public key, bailing out."),
            }
            rx
        }
    }
    // Serializers and Metadata
    fn ciphertext_bytes<'a>(&self, _ct: &'a Self::KEMCipherText) -> &'a [u8] {
        unreachable!();
    }
    fn ciphertext_bytes_mut<'a>(&self, _ct: &'a mut Self::KEMCipherText) -> &'a mut [u8] {
        unreachable!();
    }
    fn ciphertext_length(&self) -> usize {
        unreachable!();
    }
    fn shared_secret_to_bytes<'a>(&self, ss: &'a SodiumSessionKey) -> &'a [u8] {
        ss.as_ref()
    }
    // Signature based functions
    fn sign(&self, data: &[u8], key: &SodiumSigSec) -> SodiumSignature {
        unsafe {
            let mut sig = SodiumSignature::default();
            match crypto_sign_detached(
                sig.as_mut_ptr(),
                ptr::null_mut(),
                data.as_ptr(),
                data.len() as _,
                key.as_ptr(),
            ) {
                0 => (),
                _ => panic!("Our private key is suspicious, bailing out."),
            }
            sig
        }
    }
    fn verify(&self, message: &[u8], signature: &SodiumSignature, key: &SodiumSigPub) -> bool {
        unsafe {
            matches!(
                crypto_sign_verify_detached(
                    signature.as_ptr(),
                    message.as_ptr(),
                    message.len() as _,
                    key.as_ptr(),
                ),
                0
            )
        }
    }
    // Serializers and Metadata
    fn signature_length(&self) -> i64 {
        crypto_sign_BYTES as i64
    }
    fn signature_bytes<'a>(&self, signature: &'a Self::Signature) -> &'a [u8] {
        signature.as_ref()
    }
    fn signature_bytes_mut<'a>(&self, signature: &'a mut Self::Signature) -> &'a mut [u8] {
        signature.as_mut()
    }
}

#[test]
fn test_classical() {
    use crate::key_file::*;
    use std::fs::*;
    use std::io::prelude::*;
    let mut to_encrypt = [0u8; 40_000];
    {
        let mut source_file = File::open("/dev/urandom").unwrap();
        let mut dest_file = File::create("/tmp/test_enc_c").unwrap();
        source_file.read_exact(&mut to_encrypt).unwrap();
        dest_file.write_all(&to_encrypt).unwrap();
    }
    let c = ClassicalKeyQuad::new();

    c.gen("/tmp/pub_key_c_source", "/tmp/sec_key_c_source")
        .unwrap();
    c.gen("/tmp/pub_key_c_dest", "/tmp/sec_key_c_dest").unwrap();

    use crate::AsyCryptor;

    let c_cryptor = AsyCryptor::new(c);
    c_cryptor
        .encrypt_file(
            "/tmp/pub_key_c_dest",
            "/tmp/sec_key_c_source",
            "/tmp/pub_key_c_source",
            "/tmp/test_enc_c",
            "/tmp/test_enc_c.enc",
        )
        .unwrap();
    c_cryptor
        .decrypt_file(
            "/tmp/pub_key_c_source",
            "/tmp/sec_key_c_dest",
            "/tmp/pub_key_c_dest",
            "/tmp/test_enc_c.enc",
            "/tmp/test_enc_c.dec",
        )
        .unwrap();
    let mut decrypted = [0u8; 40_000];
    {
        let mut dest_file = File::open("/tmp/test_enc_c.dec").unwrap();
        dest_file.read_exact(&mut decrypted).unwrap();
    }

    // cleanup
    remove_file("/tmp/test_enc_c").unwrap();
    remove_file("/tmp/pub_key_c_source").unwrap();
    remove_file("/tmp/sec_key_c_source").unwrap();
    remove_file("/tmp/pub_key_c_dest").unwrap();
    remove_file("/tmp/sec_key_c_dest").unwrap();
    remove_file("/tmp/test_enc_c.dec").unwrap();

    assert_eq!(to_encrypt, decrypted);
}
