use oqs::kem;
use oqs::sig;

pub const QKEM_ALGO: kem::Algorithm = kem::Algorithm::ClassicMcEliece6688128f;
pub const QSIGN_ALGO: sig::Algorithm = sig::Algorithm::Dilithium5;
