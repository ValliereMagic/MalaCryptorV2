use super::Create;
use std::ops::{Deref, DerefMut};

use libsodium_sys::*;

pub struct SecretMem<const N: usize>(Box<[u8; N]>);

impl<const N: usize> SecretMem<N> {
    pub fn new() -> Self {
        let mut inner = Box::new([0u8; N]);
        unsafe {
            sodium_mlock(inner.as_mut_ptr() as _, inner.len());
        }
        SecretMem(inner)
    }
}

impl<const N: usize> Drop for SecretMem<N> {
    fn drop(&mut self) {
        unsafe {
            sodium_munlock(self.0.as_mut_ptr() as _, self.0.len());
        }
    }
}

impl<const N: usize> Create for SecretMem<N> {
    fn default() -> Self {
        SecretMem::new()
    }
}

impl<const N: usize> Deref for SecretMem<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl<const N: usize> DerefMut for SecretMem<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut()
    }
}
