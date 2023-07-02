use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Result;
use std::io::SeekFrom;

// Generic functions as well as the interface needed to call them. These
// functions allow the generation, and pulling of keypairs from files.

pub trait Create {
    fn default() -> Self;
}

pub trait IKeyPairCreator {
    type Pub: Create;
    type Sec: Create;
    // Create a new keypair creator
    fn new(pub_offset: u64, sec_offset: u64) -> Self;
    // Generate a public and private key A, and B.
    fn gen_keypair() -> (Self::Pub, Self::Sec);
    // Take a public key, and get access to it's bytes
    fn pub_bytes<'a>(pub_k: &'a Self::Pub) -> &'a [u8];
    fn pub_bytes_mut<'a>(pub_k: &'a mut Self::Pub) -> &'a mut [u8];
    // Take a secret key, and get access to it's bytes
    fn sec_bytes<'a>(sec_k: &'a Self::Sec) -> &'a [u8];
    fn sec_bytes_mut<'a>(sec_k: &'a mut Self::Sec) -> &'a mut [u8];
    // offset into the file to read / write a public key
    fn pub_offset(&self) -> u64;
    // offset into the file to read / write a secret key
    fn sec_offset(&self) -> u64;
    // The length in bytes of a public key
    fn pub_key_len() -> usize;
    // The length in bytes of a secret key
    fn sec_key_len() -> usize;
}

// Generate a keypair and place their public and secret components into their
// separate files as passed.
pub fn gen<T>(creator: &T, pkey_path: &str, skey_path: &str) -> Result<()>
where
    T: IKeyPairCreator,
{
    // Open the files
    let mut pkey_f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(pkey_path)?;
    pkey_f.seek(SeekFrom::Start(creator.pub_offset()))?;
    let mut skey_f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(skey_path)?;
    skey_f.seek(SeekFrom::Start(creator.sec_offset()))?;
    // Generate the keypair, and write out the keys to their separate files.
    let keypair = T::gen_keypair();
    pkey_f.write_all(T::pub_bytes(&keypair.0))?;
    skey_f.write_all(T::sec_bytes(&keypair.1))?;
    Ok(())
}

// Specify which type of key to retrieve from the file for the generic get function.
pub enum KeyVariant<T>
where
    T: IKeyPairCreator,
{
    Pub,
    Public(T::Pub),
    Sec,
    Secret(T::Sec),
}

// Retrieve a public OR private key depending on the variant of KeyVariant
// Passed; result is the variant holding the data requested.
pub fn get<T>(variant: KeyVariant<T>, creator: &T, pkey_path: &str) -> Result<KeyVariant<T>>
where
    T: IKeyPairCreator,
{
    let mut file = OpenOptions::new().read(true).open(pkey_path)?;
    match variant {
        KeyVariant::Pub => {
            file.seek(SeekFrom::Start(creator.pub_offset()))?;
            let mut pub_key = T::Pub::default();
            file.read_exact(T::pub_bytes_mut(&mut pub_key))?;
            Ok(KeyVariant::Public(pub_key))
        }
        KeyVariant::Sec => {
            file.seek(SeekFrom::Start(creator.sec_offset()))?;
            let mut sec_key = T::Sec::default();
            file.read_exact(T::sec_bytes_mut(&mut sec_key))?;
            Ok(KeyVariant::Secret(sec_key))
        }
        _ => unreachable!(),
    }
}
