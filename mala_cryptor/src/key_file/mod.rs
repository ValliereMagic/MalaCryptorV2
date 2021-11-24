mod base;
mod classical;
mod hybrid;
mod quantum;
pub mod symmetric;
pub use base::{IKeyQuad, IKeyQuadCreator};
pub use {classical::*, quantum::*};
pub type SymKey = [u8; libsodium_sys::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize];
