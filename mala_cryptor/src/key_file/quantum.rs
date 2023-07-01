use super::base::*;
use libsodium_sys::*;
use pqcrypto_dilithium::ffi::*;
use pqcrypto_kyber::ffi::*;

pub struct DilithiumSigPub(Box<[u8; PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES]>);

impl DilithiumSigPub {
    pub fn new() -> Self {
        let mut inner = Box::new([0u8; PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_PUBLICKEYBYTES]);
        unsafe {
            sodium_mlock(inner.as_mut_ptr() as _, inner.len());
        }
        DilithiumSigPub(inner)
    }
}

impl Drop for DilithiumSigPub {
    fn drop(&mut self) {
        unsafe {
            sodium_munlock(self.0.as_mut_ptr() as _, self.0.len());
        }
    }
}

pub struct DilithiumSigSec(Box<[u8; PQCLEAN_DILITHIUM5_CLEAN_CRYPTO_SECRETKEYBYTES]>);
pub struct KyberKEMPub([u8; PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES]);
pub struct KyberKEMSec([u8; PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES]);
pub struct QSignature(Signature);

// Adapt QSignature to the Keypair trait
impl IKeyPair for QSignature {
    type Pub = DilithiumSigPub;
    type Sec = DilithiumSigSec;
    // Create a new keypair
    fn new(pub_offset: u64, sec_offset: u64) -> Self {
        QSignature {
            0: Signature::new(pub_offset, sec_offset),
        }
    }
    fn gen_keypair(&self) -> (Self::Pub, Self::Sec) {
        let public_key: Self::Pub = Box::new();
    }
    fn pub_to_bytes(&self, pub_k: &Self::Pub) -> Vec<u8> {
        pub_k.as_bytes().to_owned()
    }
    fn bytes_to_pub(&self, bytes: &[u8]) -> Self::Pub {
        dilithium5::PublicKey::from_bytes(&bytes[0..dilithium5::public_key_bytes()])
            .expect("Not enough bytes to construct a dilithium5 public key.")
    }
    fn sec_to_bytes(&self, sec_k: &Self::Sec) -> Vec<u8> {
        sec_k.as_bytes().to_owned()
    }
    fn bytes_to_sec(&self, bytes: &[u8]) -> Self::Sec {
        dilithium5::SecretKey::from_bytes(&bytes[0..dilithium5::secret_key_bytes()])
            .expect("Not enough bytes to construct a dilithium5 secret key.")
    }
    fn pub_offset(&self) -> u64 {
        self.0.pub_offset()
    }
    fn sec_offset(&self) -> u64 {
        self.0.sec_offset()
    }
    fn pub_key_len(&self) -> usize {
        dilithium5::public_key_bytes()
    }
    fn sec_key_len(&self) -> usize {
        dilithium5::secret_key_bytes()
    }
}

pub struct QKeyExchange(KeyExchange);

impl IKeyPair for QKeyExchange {
    type Pub = kyber1024::PublicKey;
    type Sec = kyber1024::SecretKey;
    // Create a new keypair
    fn new(pub_offset: u64, sec_offset: u64) -> Self {
        QKeyExchange {
            0: KeyExchange::new(pub_offset, sec_offset),
        }
    }
    fn gen_keypair(&self) -> (kem::PublicKey, kem::SecretKey) {
        self.kem
            .keypair()
            .expect("Unable to generate quantum keypair.")
    }
    fn pub_to_bytes(&self, pub_k: &kem::PublicKey) -> Vec<u8> {
        pub_k.as_ref().to_owned()
    }
    fn bytes_to_pub(&self, bytes: &[u8]) -> kem::PublicKey {
        self.kem
            .public_key_from_bytes(bytes)
            .expect("Unable to convert bytes to quantum signature.")
            .to_owned()
    }
    fn sec_to_bytes(&self, sec_k: &kem::SecretKey) -> Vec<u8> {
        sec_k.as_ref().to_owned()
    }
    fn bytes_to_sec(&self, bytes: &[u8]) -> kem::SecretKey {
        self.kem
            .secret_key_from_bytes(bytes)
            .expect("Unable to convert bytes to quantum signature.")
            .to_owned()
    }
    fn pub_offset(&self) -> u64 {
        self.sig.length_public_key() as u64 + self.key_exchange.pub_offset()
    }
    fn sec_offset(&self) -> u64 {
        self.sig.length_secret_key() as u64 + self.key_exchange.sec_offset()
    }
    fn pub_key_len(&self) -> usize {
        self.kem.length_public_key()
    }
    fn sec_key_len(&self) -> usize {
        self.kem.length_secret_key()
    }
}

pub type QuantumKeyQuad = KeyQuad<QSignature, QKeyExchange>;

#[test]
fn test_quantum() {
    use std::fs;
    let q = QuantumKeyQuad::new();
    q.gen("/tmp/pub_key_q_test", "/tmp/sec_key_q_test").unwrap();
    let sig = enc_algos_in_use::get_q_sig_algo();
    let kem = enc_algos_in_use::get_q_kem_algo();
    // Pub
    let publ = q.get_pub("/tmp/pub_key_q_test").unwrap();
    assert_eq!(publ.0.as_ref().len(), sig.length_public_key());
    assert_eq!(publ.1.as_ref().len(), kem.length_public_key());
    // Sec
    let sec = q.get_sec("/tmp/sec_key_q_test").unwrap();
    assert_eq!(sec.0.as_ref().len(), sig.length_secret_key());
    assert_eq!(sec.1.as_ref().len(), kem.length_secret_key());
    fs::remove_file("/tmp/pub_key_q_test").unwrap();
    fs::remove_file("/tmp/sec_key_q_test").unwrap();
}
