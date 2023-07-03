use super::*;
use crate::chunked_file_reader::{ChunkStatus, ChunkedFileReader};
use crate::global_constants::*;
use crate::key_file::*;
use libsodium_sys::*;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::Result;
use std::io::SeekFrom;
use std::mem;
use std::ptr;

// Generic functions required to asymmetrically encrypt a file using the
// AsyCryptor struct.
pub trait IAsyCryptable: IKeyQuad {
    type KEMSharedSecret;
    type KEMCipherText: Create;
    type Signature: Create;
    // Shared secret based functions
    // Specifies whether this IAsyCryptable key exchange mechanism uses a
    // ciphertext for acquiring a shared secret
    fn uses_cipher_text(&self) -> bool;
    // Create a shared secret on the "sender" side... used during the encryption
    // process
    fn create_shared_secret(
        &self,
        dest_pkey: &Self::KemPub,
        our_pkey: &Self::KemPub,
        our_skey: &Self::KemSec,
    ) -> (Self::KEMSharedSecret, Option<Self::KEMCipherText>);
    // Retrieve the shared secret on the "receiver" side... used during the
    // decryption process
    fn retrieve_shared_secret(
        &self,
        our_skey: &Self::KemSec,
        our_pkey: &Self::KemPub,
        sender_pkey: &Self::KemPub,
        ciphertext: Option<&Self::KEMCipherText>,
    ) -> Self::KEMSharedSecret;
    // Serializers and Metadata
    fn ciphertext_bytes<'a>(&self, ct: &'a Self::KEMCipherText) -> &'a [u8];
    fn ciphertext_bytes_mut<'a>(&self, ct: &'a mut Self::KEMCipherText) -> &'a mut [u8];
    fn ciphertext_length(&self) -> usize;
    fn shared_secret_to_bytes<'a>(&self, ss: &'a Self::KEMSharedSecret) -> &'a [u8];
    // Signature based functions
    fn sign(&self, data: &[u8], key: &Self::SigSec) -> Self::Signature;
    fn verify(&self, message: &[u8], signature: &Self::Signature, key: &Self::SigPub) -> bool;
    // Serializers and Metadata
    fn signature_length(&self) -> i64;
    fn signature_bytes<'a>(&self, signature: &'a Self::Signature) -> &'a [u8];
    fn signature_bytes_mut<'a>(&self, signature: &'a mut Self::Signature) -> &'a mut [u8];
}

pub struct AsyCryptor<Cryptable>
where
    Cryptable: IAsyCryptable,
{
    crypt: Cryptable,
}

impl<Cryptable> AsyCryptor<Cryptable>
where
    Cryptable: IAsyCryptable,
{
    pub fn new(crypt: Cryptable) -> AsyCryptor<Cryptable> {
        AsyCryptor { crypt }
    }

    pub fn sign_file(&self, skey_path: &str, file_path: &str) -> Result<()> {
        let skey = self.crypt.get_sec(skey_path)?;
        // Open up the files
        let mut file = OpenOptions::new().read(true).write(true).open(file_path)?;
        // Digest, and sign the encrypted file
        let signature = self.crypt.sign(&digest(&mut file, None)?, &skey.0);
        file.write_all(self.crypt.signature_bytes(&signature))?;
        Ok(())
    }

    pub fn verify_file(&self, sender_pub_key_path: &str, file_path: &str) -> Result<()> {
        let sender_pkey = self.crypt.get_pub(sender_pub_key_path)?;
        let mut file = OpenOptions::new().read(true).write(true).open(file_path)?;
        // Seek to the beginning of the signature
        let signature_offset = self.crypt.signature_length();
        file.seek(SeekFrom::End(-signature_offset))?;
        let mut signature = Cryptable::Signature::default();
        file.read_exact(self.crypt.signature_bytes_mut(&mut signature))?;
        // Seek back to the beginning of the file
        file.rewind()?;
        // Digest the file up to the signature
        let digest = digest(&mut file, Some(signature_offset))?;
        // Check whether the signature matches
        match self.crypt.verify(&digest, &signature, &sender_pkey.0) {
            true => (),
            false => {
                panic!("Signature is bad. Not attempting to continue working with file. Aborting.")
            }
        }
        // Truncate the signature from the end of the file
        file.set_len((file.metadata().unwrap().len() as i64 - signature_offset) as u64)?;
        Ok(())
    }

    pub fn encrypt_file(
        &self,
        dest_pkey_path: &str,
        skey_path: &str,
        pkey_path: &str,
        file_in_path: &str,
        file_out_path: &str,
    ) -> Result<()> {
        let dest_pkey = self.crypt.get_pub(dest_pkey_path)?;
        let skey = self.crypt.get_sec(skey_path)?;
        let our_pub = self.crypt.get_pub(pkey_path)?;
        // Derive the shared secret
        let (ss, ct) = self
            .crypt
            .create_shared_secret(&dest_pkey.1, &our_pub.1, &skey.1);
        // Open up the files
        let (mut file_in, mut file_out) = (
            File::open(file_in_path)?,
            OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(true)
                .open(file_out_path)?,
        );
        // If there is a ciphertext, write it out to the file
        if let Some(ct) = ct {
            file_out.write_all(self.crypt.ciphertext_bytes(&ct))?;
        }
        // Encrypt the source file with the shared secret, and write it to the out
        // file
        let mut sym_key = SodiumSymKey::default();
        sym_key
            .as_mut()
            .write_all(self.crypt.shared_secret_to_bytes(&ss))?;
        encrypt_file(&mut file_in, &mut file_out, sym_key)?;
        self.sign_file(skey_path, file_out_path)
    }

    pub fn decrypt_file(
        &self,
        sender_pub_key_path: &str,
        skey_path: &str,
        pkey_path: &str,
        file_in_path: &str,
        file_out_path: &str,
    ) -> Result<()> {
        // Verify the file is from the sender
        self.verify_file(sender_pub_key_path, file_in_path)?;
        // Retrieve the required keys from files
        let sender_pkey = self.crypt.get_pub(sender_pub_key_path)?;
        let skey = self.crypt.get_sec(skey_path)?;
        let our_pkey = self.crypt.get_pub(pkey_path)?;
        let (mut file_in, mut file_out) = (
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(file_in_path)?,
            File::create(file_out_path)?,
        );
        // Read in the key exchange ciphertext if there is one
        let ct = if self.crypt.uses_cipher_text() {
            let mut kem_ct = Cryptable::KEMCipherText::default();
            file_in.read_exact(self.crypt.ciphertext_bytes_mut(&mut kem_ct))?;
            Some(kem_ct)
        } else {
            None
        };
        // Derive the shared secret
        let ss =
            self.crypt
                .retrieve_shared_secret(&skey.1, &our_pkey.1, &sender_pkey.1, ct.as_ref());
        // Our file pointer is at the beginning of the encrypted file, and we have
        // removed the signature from the end. Time to finally decrypt the file
        let mut sym_key = SodiumSymKey::default();
        sym_key
            .as_mut()
            .write_all(self.crypt.shared_secret_to_bytes(&ss))?;
        decrypt_file(&mut file_in, &mut file_out, sym_key)?;
        // Remove the encrypted in-file; it was modified in the decryption procedure.
        fs::remove_file(file_in_path)?;
        Ok(())
    }
}

type Digest = [u8; crypto_generichash_BYTES_MAX as usize];

fn digest(file: &mut File, signature_avoid: Option<i64>) -> Result<Digest> {
    // Figure out how many chunks we will iterate through
    let mut file_len: i64 = file.metadata().unwrap().len() as i64;
    // If signature_avoid is present, decrease the file_len to remove the
    // signature from being read into the digest.
    if let Some(offset) = signature_avoid {
        file_len -= offset;
        if file_len <= 0 {
            panic!("Digesting negative or zero-sized file.");
        }
    }
    let mut chunked_reader = ChunkedFileReader::new(file, CHUNK_SIZE as u64, Some(file_len as u64));
    let mut state: crypto_generichash_state = unsafe { mem::zeroed() };
    unsafe {
        // Initialize hash
        crypto_generichash_init(
            &mut state as *mut _,
            ptr::null(),
            0,
            crypto_generichash_BYTES_MAX as _,
        );
    }
    let mut buff = [0u8; CHUNK_SIZE];
    // digest the file in chunks
    let mut finalized = false;
    while !finalized {
        let chunk_size = match chunked_reader.read_chunk(&mut buff)? {
            ChunkStatus::Body => CHUNK_SIZE,
            ChunkStatus::Final(c) => {
                finalized = true;
                c as usize
            }
            ChunkStatus::Err(e) => panic!("{}", e),
        };
        unsafe {
            // Add the bytes read to the digest
            crypto_generichash_update(&mut state as *mut _, buff.as_mut_ptr(), chunk_size as _);
        }
    }
    // Generate the final hash
    let mut hash: Digest = unsafe { mem::zeroed() };
    unsafe {
        crypto_generichash_final(&mut state as *mut _, hash.as_mut_ptr(), hash.len());
    }
    Ok(hash)
}
