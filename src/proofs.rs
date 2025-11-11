// Balance simplification: Proof implementations removed
// This module now keeps essential cryptographic constants for signatures

use curve25519_dalek::RistrettoPoint;
use lazy_static::lazy_static;
use sha3::Sha3_512;

// G: Primary generator point (Ristretto basepoint)
pub use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;

lazy_static! {
    // H: Secondary generator point for signatures (Schnorr scheme)
    // Generated deterministically from G using hash-to-point
    pub static ref H: RistrettoPoint = {
        RistrettoPoint::hash_from_bytes::<Sha3_512>(b"TOS_SIGNATURE_GENERATOR_H")
    };
}
