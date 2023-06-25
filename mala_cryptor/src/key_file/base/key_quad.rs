use super::key_pair::*;
use std::io::Result;

// Generic functions representing the set of 2 KeyPairs used for asymmetric
// encryption in mala_cryptor `KeyQuad`; which are a Signature Pair, and
// KeyExchange pair. The Interface allows specialization of KeyQuads with
// concrete types, as well as reducing a lot of code reuse.

// It was designed to allow different algorithms to be used in mala_cryptor in
// the future with very little code change. [re-implementing KeyPair for each of
// them]

pub trait IKeyQuad {
    type SigPub;
    type SigSec;
    type KemPub;
    type KemSec;
    // Generate a public and private keyquad composed of a signature public and
    // secret pair as well as a key exchange public and secret pair
    fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()>;
    // Retrieve the public portion of the keypairs from the file paths passed
    fn get_pub(&self, pkey_path: &str) -> Result<(Self::SigPub, Self::KemPub)>;
    fn get_sec(&self, skey_path: &str) -> Result<(Self::SigSec, Self::KemSec)>;
    // The total size that the file will be for each of the key parts. This is
    // used for composition key files where multiple different keypairs are
    // stored in the same file.
    fn total_pub_size_bytes(&self) -> usize;
    fn total_sec_size_bytes(&self) -> usize;
}

// Generic KeyQuad struct extensible by any specific implementation
pub struct KeyQuad<SigKeyPair, KemKeyPair>
where
    SigKeyPair: IKeyPair,
    KemKeyPair: IKeyPair,
{
    sign: SigKeyPair,
    kem: KemKeyPair,
}

// Base creation of a KeyQuad.
impl<SigKeyPair, KemKeyPair> KeyQuad<SigKeyPair, KemKeyPair>
where
    SigKeyPair: IKeyPair,
    KemKeyPair: IKeyPair,
{
    pub fn new() -> Self {
        KeyQuad {
            sign: SigKeyPair::new(0, 0),
            kem: KemKeyPair::new(0, 0),
        }
    }

    pub fn hyb_new(pub_offset: u64, sec_offset: u64) -> Self {
        KeyQuad {
            sign: SigKeyPair::new(pub_offset, sec_offset),
            kem: KemKeyPair::new(pub_offset, sec_offset),
        }
    }
}

// Universal implementation of the different operations that a KeyQuad needs to
// perform
impl<SigKeyPair, KemKeyPair> IKeyQuad for KeyQuad<SigKeyPair, KemKeyPair>
where
    SigKeyPair: IKeyPair,
    KemKeyPair: IKeyPair,
{
    type SigPub = SigKeyPair::Pub;
    type SigSec = SigKeyPair::Sec;
    type KemPub = KemKeyPair::Pub;
    type KemSec = KemKeyPair::Sec;
    // Generate a public and private keyquad composed of a signature public and
    // secret pair as well as a key exchange public and secret pair
    fn gen(&self, pkey_path: &str, skey_path: &str) -> Result<()> {
        gen(&self.sign, pkey_path, skey_path)?;
        gen(&self.kem, pkey_path, skey_path)
    }
    // Retrieve the public portion of the keypairs from the file paths passed
    fn get_pub(&self, pkey_path: &str) -> Result<(Self::SigPub, Self::KemPub)> {
        let sig = match get(KeyVariant::Pub, &self.sign, pkey_path)? {
            KeyVariant::Public(p) => p,
            _ => unreachable!(),
        };
        let kem = match get(KeyVariant::Pub, &self.kem, pkey_path)? {
            KeyVariant::Public(p) => p,
            _ => unreachable!(),
        };
        Ok((sig, kem))
    }
    fn get_sec(&self, skey_path: &str) -> Result<(Self::SigSec, Self::KemSec)> {
        let sig = match get(KeyVariant::Sec, &self.sign, skey_path)? {
            KeyVariant::Secret(s) => s,
            _ => unreachable!(),
        };
        let kem = match get(KeyVariant::Sec, &self.kem, skey_path)? {
            KeyVariant::Secret(s) => s,
            _ => unreachable!(),
        };
        Ok((sig, kem))
    }
    // The total size that the file will be for each of the key parts. This is
    // used for composition key files where multiple different keypairs are
    // stored in the same file.
    fn total_pub_size_bytes(&self) -> usize {
        self.sign.pub_key_len() + self.kem.pub_key_len()
    }
    fn total_sec_size_bytes(&self) -> usize {
        self.sign.sec_key_len() + self.kem.sec_key_len()
    }
}
