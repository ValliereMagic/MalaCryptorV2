use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Result;
use std::io::SeekFrom;

// Generic functions as well as the interface needed to call them. These
// functions allow the generation, and pulling of keypairs from files.

pub trait IKeyPair {
    type Pub;
    type Sec;
    // Generate a public and private key A, and B.
    fn gen_keypair(&self) -> (Self::Pub, Self::Sec);
    // Take a public key, and turn it into bytes
    fn pub_to_bytes(&self, pub_k: &Self::Pub) -> Vec<u8>;
    // inverse, back to a public key
    fn bytes_to_pub(&self, bytes: &[u8]) -> Self::Pub;
    fn sec_to_bytes(&self, sec_k: &Self::Sec) -> Vec<u8>;
    fn bytes_to_sec(&self, bytes: &[u8]) -> Self::Sec;
    // offset into the file to read / write a public key
    fn pub_offset(&self) -> u64;
    // offset into the file to read / write a secret key
    fn sec_offset(&self) -> u64;
    // The length in bytes of a public key
    fn pub_key_len(&self) -> usize;
    // The length in bytes of a secret key
    fn sec_key_len(&self) -> usize;
}

// Generate a keypair and place their public and secret components into their
// separate files as passed.
pub fn gen<T>(pair: &T, pkey_path: &str, skey_path: &str) -> Result<()>
where
    T: IKeyPair,
{
    // Open the files
    let mut pkey_f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(pkey_path)?;
    pkey_f.seek(SeekFrom::Start(pair.pub_offset()))?;
    let mut skey_f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(skey_path)?;
    skey_f.seek(SeekFrom::Start(pair.sec_offset()))?;
    // Generate the keypair, and write out the keys to their separate files.
    let keypair = pair.gen_keypair();
    pkey_f.write_all(&pair.pub_to_bytes(&keypair.0))?;
    skey_f.write_all(&pair.sec_to_bytes(&keypair.1))?;
    Ok(())
}

// Specify which type of key to retrieve from the file for the generic get function.
pub enum KeyVariant<T>
where
    T: IKeyPair,
{
    Pub,
    Public(T::Pub),
    Sec,
    Secret(T::Sec),
}

// Retrieve a public OR private key depending on the variant of KeyVariant
// Passed; result is the variant holding the data requested.
pub fn get<T>(variant: KeyVariant<T>, pair: &T, pkey_path: &str) -> Result<KeyVariant<T>>
where
    T: IKeyPair,
{
    let mut file = OpenOptions::new().read(true).open(pkey_path)?;
    match variant {
        KeyVariant::Pub => {
            file.seek(SeekFrom::Start(pair.pub_offset()))?;
            let mut buff = vec![0u8; pair.pub_key_len()];
            file.read_exact(&mut buff)?;
            Ok(KeyVariant::Public(pair.bytes_to_pub(&buff)))
        }
        KeyVariant::Sec => {
            file.seek(SeekFrom::Start(pair.sec_offset()))?;
            let mut buff = vec![0u8; pair.sec_key_len()];
            file.read_exact(&mut buff)?;
            Ok(KeyVariant::Secret(pair.bytes_to_sec(&buff)))
        }
        _ => unreachable!(),
    }
}
