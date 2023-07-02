use super::base::*;
use pqcrypto_dilithium::ffi::*;
use pqcrypto_kyber::ffi::*;

pub type DilithiumSigPub = [u8; PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES];
pub type DilithiumSigSec = SecretMem<PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES>;
pub type KyberKEMPub = [u8; PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
pub type KyberKEMSec = SecretMem<PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES>;

impl Create for DilithiumSigPub {
    fn default() -> Self {
        [0u8; PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES]
    }
}

impl Create for KyberKEMPub {
    fn default() -> Self {
        [0u8; PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES]
    }
}

pub struct QSignature(Signature);

// Adapt QSignature to the Keypair trait
impl IKeyPairCreator for QSignature {
    type Pub = DilithiumSigPub;
    type Sec = DilithiumSigSec;
    // Create a new keypair
    fn new(pub_offset: u64, sec_offset: u64) -> Self {
        QSignature {
            0: Signature::new(pub_offset, sec_offset),
        }
    }
    fn gen_keypair() -> (Self::Pub, Self::Sec) {
        let mut public_key = Self::Pub::default();
        let mut secret_key = Self::Sec::default();
        unsafe {
            PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(
                public_key.as_mut_ptr(),
                secret_key.as_mut_ptr(),
            );
        }
        return (public_key, secret_key);
    }
    fn pub_bytes<'a>(pub_k: &'a Self::Pub) -> &'a [u8] {
        pub_k
    }
    fn pub_bytes_mut<'a>(pub_k: &'a mut Self::Pub) -> &'a mut [u8] {
        pub_k
    }
    fn sec_bytes<'a>(sec_k: &'a Self::Sec) -> &'a [u8] {
        &sec_k[0..]
    }
    fn sec_bytes_mut<'a>(sec_k: &'a mut Self::Sec) -> &'a mut [u8] {
        &mut sec_k[0..]
    }
    fn pub_offset(&self) -> u64 {
        self.0.pub_offset()
    }
    fn sec_offset(&self) -> u64 {
        self.0.sec_offset()
    }
    fn pub_key_len() -> usize {
        PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES
    }
    fn sec_key_len() -> usize {
        PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES
    }
}

pub struct QKeyExchange(KeyExchange);

impl IKeyPairCreator for QKeyExchange {
    type Pub = KyberKEMPub;
    type Sec = KyberKEMSec;
    // Create a new keypair
    fn new(pub_offset: u64, sec_offset: u64) -> Self {
        QKeyExchange {
            0: KeyExchange::new(pub_offset, sec_offset),
        }
    }
    fn gen_keypair() -> (Self::Pub, Self::Sec) {
        let mut public_key = Self::Pub::default();
        let mut secret_key = Self::Sec::default();
        unsafe {
            PQCLEAN_KYBER102490S_CLEAN_crypto_kem_keypair(
                public_key.as_mut_ptr(),
                secret_key.as_mut_ptr(),
            );
        }
        return (public_key, secret_key);
    }
    fn pub_bytes<'a>(pub_k: &'a Self::Pub) -> &'a [u8] {
        pub_k
    }
    fn pub_bytes_mut<'a>(pub_k: &'a mut Self::Pub) -> &'a mut [u8] {
        pub_k
    }
    fn sec_bytes<'a>(sec_k: &'a Self::Sec) -> &'a [u8] {
        &sec_k[0..]
    }
    fn sec_bytes_mut<'a>(sec_k: &'a mut Self::Sec) -> &'a mut [u8] {
        &mut sec_k[0..]
    }
    fn pub_offset(&self) -> u64 {
        self.0.pub_offset() + PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES as u64
    }
    fn sec_offset(&self) -> u64 {
        self.0.sec_offset() + PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES as u64
    }
    fn pub_key_len() -> usize {
        PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES
    }
    fn sec_key_len() -> usize {
        PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES
    }
}

pub type QuantumKeyQuad = KeyQuad<QSignature, QKeyExchange>;

#[test]
fn test_quantum() {
    use std::fs;
    let q = QuantumKeyQuad::new();
    q.gen("/tmp/pub_key_q_test", "/tmp/sec_key_q_test").unwrap();
    // Pub
    let publ = q.get_pub("/tmp/pub_key_q_test").unwrap();
    assert_eq!(
        publ.0.as_ref().len(),
        PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES
    );
    assert_eq!(
        publ.1.as_ref().len(),
        PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES
    );
    // Sec
    let sec = q.get_sec("/tmp/sec_key_q_test").unwrap();
    assert_eq!(
        sec.0.as_ref().len(),
        PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES
    );
    assert_eq!(
        sec.1.as_ref().len(),
        PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES
    );
    fs::remove_file("/tmp/pub_key_q_test").unwrap();
    fs::remove_file("/tmp/sec_key_q_test").unwrap();
}
