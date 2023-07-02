#[test]
fn test_hybrid() {
    use super::base::*;
    use super::{classical::*, quantum::*};
    use libsodium_sys::*;
    use std::fs;
    let q = QuantumKeyQuad::new();
    let c = ClassicalKeyQuad::hyb_new(
        q.total_pub_size_bytes() as u64,
        q.total_sec_size_bytes() as u64,
    );
    q.gen("/tmp/pub_key_h_test", "/tmp/sec_key_h_test").unwrap();
    c.gen("/tmp/pub_key_h_test", "/tmp/sec_key_h_test").unwrap();
    // Pub
    let publ = q.get_pub("/tmp/pub_key_h_test").unwrap();
    assert_eq!(publ.0.as_ref().len(), QSignature::pub_key_len());
    assert_eq!(publ.1.as_ref().len(), QKeyExchange::pub_key_len());
    // Sec
    let sec = q.get_sec("/tmp/sec_key_h_test").unwrap();
    assert_eq!(sec.0.as_ref().len(), QSignature::sec_key_len());
    assert_eq!(sec.1.as_ref().len(), QKeyExchange::sec_key_len());
    // Pub
    let publ = c.get_pub("/tmp/pub_key_h_test").unwrap();
    assert_eq!(publ.0.as_ref().len(), crypto_sign_PUBLICKEYBYTES as usize);
    assert_eq!(publ.1.as_ref().len(), crypto_kx_PUBLICKEYBYTES as usize);
    // Sec
    let sec = c.get_sec("/tmp/sec_key_h_test").unwrap();
    assert_eq!(sec.0.as_ref().len(), crypto_sign_SECRETKEYBYTES as usize);
    assert_eq!(sec.1.as_ref().len(), crypto_kx_SECRETKEYBYTES as usize);
    fs::remove_file("/tmp/pub_key_h_test").unwrap();
    fs::remove_file("/tmp/sec_key_h_test").unwrap();
}
