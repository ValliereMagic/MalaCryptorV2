use crate::chunked_file_reader::*;
use crate::global_constants::*;
use crate::key_derivation;
use crate::key_derivation::key_derive_from_pass;
use crate::key_file::*;
use libsodium_sys::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::{Error, ErrorKind, Result};
use std::mem;
use std::ptr;

// Password based functions
pub fn encrypt_file_with_password(
    file_in_path: &str,
    file_out_path: &str,
    password: &str,
) -> std::io::Result<()> {
    let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
    let (salt, key) = key_derive_from_pass(password, None);
    file_out.write_all(&salt)?;
    encrypt_file(&mut file_in, &mut file_out, key)
}

pub fn decrypt_file_with_password(
    file_in_path: &str,
    file_out_path: &str,
    password: &str,
) -> std::io::Result<()> {
    let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
    let mut salt = key_derivation::SodiumSalt::default();
    file_in.read_exact(&mut salt)?;
    let (_, key) = key_derive_from_pass(password, Some(salt));
    decrypt_file(&mut file_in, &mut file_out, key)
}
// Keyfile based functions
pub fn encrypt_file_with_key(
    file_in_path: &str,
    file_out_path: &str,
    key: SodiumSymKey,
) -> Result<()> {
    let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
    encrypt_file(&mut file_in, &mut file_out, key)
}

pub fn decrypt_file_with_key(
    file_in_path: &str,
    file_out_path: &str,
    key: SodiumSymKey,
) -> Result<()> {
    let (mut file_in, mut file_out) = (File::open(file_in_path)?, File::create(file_out_path)?);
    decrypt_file(&mut file_in, &mut file_out, key)
}
// Base functions
pub fn encrypt_file(file_in: &mut File, file_out: &mut File, key: SodiumSymKey) -> Result<()> {
    let mut state: crypto_secretstream_xchacha20poly1305_state = unsafe { mem::zeroed() };
    let mut header = [0u8; crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize];
    unsafe {
        match crypto_secretstream_xchacha20poly1305_init_push(
            &mut state as *mut _,
            header.as_mut_ptr(),
            key.as_ptr(),
        ) {
            0 => (),
            _ => {
                panic!("Unable to initialize header with key.");
            }
        }
    };
    // Write the stream header to the beginning of the encrypted file
    file_out.write_all(&header)?;
    let mut in_buff = [0u8; CHUNK_SIZE];
    let mut chunked_reader = ChunkedFileReader::new(file_in, in_buff.len() as u64, None);
    let mut out_buff = [0u8; CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES as usize];
    let mut finalized = false;
    while !finalized {
        let (tag, read_bytes) = match chunked_reader.read_chunk(&mut in_buff)? {
            ChunkStatus::Body => (
                crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8,
                in_buff.len(),
            ),
            ChunkStatus::Final(s) => {
                finalized = true;
                (
                    crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8,
                    s as usize,
                )
            }
            ChunkStatus::Err(e) => panic!("{}", e),
        };
        unsafe {
            match crypto_secretstream_xchacha20poly1305_push(
                &mut state as *mut _,
                out_buff.as_mut_ptr(),
                ptr::null_mut(),
                in_buff.as_ptr(),
                read_bytes as _,
                ptr::null(),
                0,
                tag,
            ) {
                0 => (),
                _ => {
                    panic!("Error while encrypting file.");
                }
            }
        };
        // Write out only the bytes we worked on this round of the loop; which
        // may not be the whole buffer.
        file_out.write_all(
            &out_buff[..read_bytes + crypto_secretstream_xchacha20poly1305_ABYTES as usize],
        )?;
    }
    Ok(())
}

pub fn decrypt_file(file_in: &mut File, file_out: &mut File, key: SodiumSymKey) -> Result<()> {
    // Read in the stream header from the file to decrypt
    let mut header = [0u8; crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize];
    file_in.read_exact(&mut header)?;
    let mut state: crypto_secretstream_xchacha20poly1305_state = unsafe { mem::zeroed() };
    unsafe {
        match crypto_secretstream_xchacha20poly1305_init_pull(
            &mut state as *mut _,
            header.as_ptr(),
            key.as_ptr(),
        ) {
            0 => (),
            _ => {
                panic!("Invalid header. Aborting.");
            }
        }
    };
    let mut in_buff = [0u8; CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES as usize];
    let mut out_buff = [0u8; CHUNK_SIZE];
    // Find out how far into the file we are currently seeked, and subtract that
    // from the total, to find out how much of the file is left.
    let length_of_file_from_curr_to_end =
        file_in.metadata().unwrap().len() - file_in.stream_position().unwrap();
    let mut chunked_reader = ChunkedFileReader::new(
        file_in,
        in_buff.len() as u64,
        Some(length_of_file_from_curr_to_end),
    );
    let mut finalized = false;
    while !finalized {
        let read_bytes = match chunked_reader.read_chunk(&mut in_buff)? {
            ChunkStatus::Body => in_buff.len(),
            ChunkStatus::Final(s) => {
                finalized = true;
                s as usize
            }
            ChunkStatus::Err(e) => panic!("{}", e),
        };
        let mut tag: u8 = 0;
        match unsafe {
            crypto_secretstream_xchacha20poly1305_pull(
                &mut state as *mut _,
                out_buff.as_mut_ptr(),
                ptr::null_mut(),
                &mut tag as *mut _,
                in_buff.as_ptr(),
                read_bytes as _,
                ptr::null(),
                0,
            )
        } {
            0 => {
                if tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL as u8 {
                    assert!(finalized);
                } else {
                    assert_eq!(tag, crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as u8);
                }
            }
            _ => {
                return Err(Error::new(
                    ErrorKind::Other,
                    "Error while decrypting file stream, possible tampering or bad key",
                ));
            }
        };
        // Write out only the bytes we worked on this round of the loop; which
        // may not be the whole buffer.
        file_out.write_all(
            &out_buff[..read_bytes - crypto_secretstream_xchacha20poly1305_ABYTES as usize],
        )?;
    }
    Ok(())
}
