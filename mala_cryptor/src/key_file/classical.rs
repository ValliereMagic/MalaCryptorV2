use super::base::*;
use libsodium_sys::*;

pub type SodiumSigPub = [u8; crypto_sign_PUBLICKEYBYTES as usize];
const USIZE_crypto_sign_SECRETKEYBYTES: usize = crypto_sign_SECRETKEYBYTES as usize;
pub type SodiumSigSec = SecretMem<USIZE_crypto_sign_SECRETKEYBYTES>;
pub type SodiumKEMPub = [u8; crypto_kx_PUBLICKEYBYTES as usize];
const USIZE_crypto_kx_SECRETKEYBYTES: usize = crypto_kx_SECRETKEYBYTES as usize;
pub type SodiumKEMSec = SecretMem<USIZE_crypto_kx_SECRETKEYBYTES>;

impl Create for SodiumSigPub {
    fn default() -> Self {
        [0u8; crypto_sign_PUBLICKEYBYTES as usize]
    }
}

// Classical KeyPair using libsodium via SodiumOxide.

impl IKeyPairCreator for Signature {
    type Pub = SodiumSigPub;
    type Sec = SodiumSigSec;
    // Create a new keypair
    fn new(pub_offset: u64, sec_offset: u64) -> Self {
        Signature::new(pub_offset, sec_offset)
    }
    // Generate a public and private key A, and B.
    fn gen_keypair() -> (Self::Pub, Self::Sec) {
        unsafe {
            let (mut pk, mut sk) = (<SodiumSigPub as Create>::default(), SodiumSigSec::default());
            crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
            (pk, sk)
        }
    }
    // Take a public key, and turn it into bytes
    fn pub_bytes<'a>(pub_k: &'a Self::Pub) -> &'a [u8] {
        pub_k
    }
    // inverse, back to a public key
    fn pub_bytes_mut<'a>(pub_k: &'a mut Self::Pub) -> &'a mut [u8] {
        pub_k
    }
    fn sec_bytes<'a>(sec_k: &'a Self::Sec) -> &'a [u8] {
        &sec_k[0..]
    }
    fn sec_bytes_mut<'a>(sec_k: &'a mut Self::Sec) -> &'a mut [u8] {
        &mut sec_k[0..]
    }
    // offset into the file to read / write a public key
    fn pub_offset(&self) -> u64 {
        self.pub_offset()
    }
    // offset into the file to read / write a secret key
    fn sec_offset(&self) -> u64 {
        self.sec_offset()
    }
    // The length in bytes of a public key
    fn pub_key_len() -> usize {
        crypto_sign_PUBLICKEYBYTES as usize
    }
    // The length in bytes of a secret key
    fn sec_key_len() -> usize {
        crypto_sign_SECRETKEYBYTES as usize
    }
}

impl IKeyPairCreator for KeyExchange {
    type Pub = SodiumKEMPub;
    type Sec = SodiumKEMSec;
    // Create a new keypair
    fn new(pub_offset: u64, sec_offset: u64) -> Self {
        KeyExchange::new(pub_offset, sec_offset)
    }
    // Generate a public and private key A, and B.
    fn gen_keypair() -> (Self::Pub, Self::Sec) {
        unsafe {
            let (mut pk, mut sk) = (<SodiumKEMPub as Create>::default(), SodiumKEMSec::default());
            crypto_kx_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
            (pk, sk)
        }
    }
    // Take a public key, and turn it into bytes
    fn pub_bytes<'a>(pub_k: &'a Self::Pub) -> &'a [u8] {
        pub_k
    }
    // inverse, back to a public key
    fn pub_bytes_mut<'a>(pub_k: &'a mut Self::Pub) -> &'a mut [u8] {
        pub_k
    }
    fn sec_bytes<'a>(sec_k: &'a Self::Sec) -> &'a [u8] {
        &sec_k[0..]
    }
    fn sec_bytes_mut<'a>(sec_k: &'a mut Self::Sec) -> &'a mut [u8] {
        &mut sec_k[0..]
    }
    // offset into the file to read / write a public key
    fn pub_offset(&self) -> u64 {
        self.pub_offset() + crypto_sign_PUBLICKEYBYTES as u64
    }
    // offset into the file to read / write a secret key
    fn sec_offset(&self) -> u64 {
        self.sec_offset() + crypto_sign_SECRETKEYBYTES as u64
    }
    // The length in bytes of a public key
    fn pub_key_len() -> usize {
        crypto_kx_PUBLICKEYBYTES as usize
    }
    // The length in bytes of a secret key
    fn sec_key_len() -> usize {
        crypto_kx_SECRETKEYBYTES as usize
    }
}

pub type ClassicalKeyQuad = KeyQuad<Signature, KeyExchange>;

#[test]
fn test_classical() {
    use std::fs;
    let c = ClassicalKeyQuad::new();
    c.gen("/tmp/pub_key_c_test", "/tmp/sec_key_c_test").unwrap();
    // Pub
    let publ = c.get_pub("/tmp/pub_key_c_test").unwrap();
    assert_eq!(publ.0.as_ref().len(), crypto_sign_PUBLICKEYBYTES as usize);
    assert_eq!(publ.1.as_ref().len(), crypto_kx_PUBLICKEYBYTES as usize);
    // Sec
    let sec = c.get_sec("/tmp/sec_key_c_test").unwrap();
    assert_eq!(sec.0.as_ref().len(), crypto_sign_SECRETKEYBYTES as usize);
    assert_eq!(sec.1.as_ref().len(), crypto_kx_SECRETKEYBYTES as usize);
    fs::remove_file("/tmp/pub_key_c_test").unwrap();
    fs::remove_file("/tmp/sec_key_c_test").unwrap();
}
