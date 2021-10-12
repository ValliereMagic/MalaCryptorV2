use oqs::kem;
use oqs::sig;

pub const QKEM_ALGO: kem::Algorithm = kem::Algorithm::ClassicMcEliece6688128f;
pub const QSIGN_ALGO: sig::Algorithm = sig::Algorithm::Dilithium5;

// Acquire the active signature or key exchange algorithm for OQS. Defined in
// one place to reduce code duplication.
pub fn get_q_sig_algo() -> sig::Sig {
	sig::Sig::new(QSIGN_ALGO).expect("Unable to acquire quantum SIG algo.")
}

pub fn get_q_kem_algo() -> kem::Kem {
	kem::Kem::new(QKEM_ALGO).expect("Unable to acquire quantum KEM algo.")
}