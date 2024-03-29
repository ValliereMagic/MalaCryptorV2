use super::key_file::SodiumSymKey;
use crate::key_file::Create;
use libsodium_sys::*;
use std::ffi::CString;
use std::{ptr::write_volatile, sync::atomic};
pub type SodiumSalt = [u8; crypto_pwhash_SALTBYTES as usize];

pub fn key_derive_from_pass(pass: &str, salt: Option<SodiumSalt>) -> (SodiumSalt, SodiumSymKey) {
    unsafe {
        let mut key = SodiumSymKey::default();
        let mut salt = match salt {
            Some(salt) => salt,
            None => {
                let mut salt = SodiumSalt::default();
                randombytes_buf(salt.as_mut_ptr() as *mut _, crypto_pwhash_SALTBYTES as _);
                salt
            }
        };
        let c_repr_pass = CString::new(pass).unwrap();
        let repr_ptr = c_repr_pass.as_ptr();
        if crypto_pwhash(
            key.as_mut_ptr(),
            crypto_secretstream_xchacha20poly1305_KEYBYTES as _,
            repr_ptr,
            pass.len() as _,
            salt.as_mut_ptr(),
            crypto_pwhash_OPSLIMIT_SENSITIVE as _,
            crypto_pwhash_MEMLIMIT_SENSITIVE as _,
            crypto_pwhash_ALG_DEFAULT as _,
        ) != 0
        {
            panic!("Error. Unable to derive symmetric key from password in key_derive. May be out of memory\n");
        }

        {
            // Zero out passed string
            let mut c_bytes = c_repr_pass.into_bytes();
            for c in &mut c_bytes {
                write_volatile(c, u8::default());
            }
            atomic::fence(atomic::Ordering::SeqCst);
            atomic::compiler_fence(atomic::Ordering::SeqCst);
        }

        (salt, key)
    }
}
