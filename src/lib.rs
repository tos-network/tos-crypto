// TOS Cryptographic Primitives
//
// This crate provides the core cryptographic primitives used by the TOS Network,
// extracted into an independent library to avoid circular dependencies between
// `tos-common` and `tako/precompiles`.

pub mod elgamal;
pub mod proofs;

// Re-export only the core Schnorr signature types
// Key types (PublicKey, PrivateKey, KeyPair) remain in tos-common for compatibility
pub use elgamal::{hash_and_point_to_scalar, Signature, SIGNATURE_SIZE};

pub use proofs::{G, H};

// Re-export key type internals for tos-common to use
pub use elgamal::{
    CompressedPublicKey, DecompressionError, KeyPair, PrivateKey, PublicKey,
    RISTRETTO_COMPRESSED_SIZE, SCALAR_SIZE,
};

// Re-export curve25519_dalek types for convenience
pub use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Sha3_512;

    /// Test that H generator is backward compatible with legacy definition.
    /// This ensures that signatures created before and after the tos-crypto
    /// extraction remain valid and identical.
    #[test]
    fn h_generator_backward_compatibility() {
        // Legacy definition (pre-split): hardcoded seed "TOS_SIGNATURE_GENERATOR_H"
        let legacy_h = RistrettoPoint::hash_from_bytes::<Sha3_512>(b"TOS_SIGNATURE_GENERATOR_H");

        // New definition (from tos-crypto)
        let current_h = *H;

        assert_eq!(
            legacy_h, current_h,
            "H generator must match legacy definition for signature compatibility"
        );
    }

    /// Test that G generator is the standard Ristretto basepoint
    #[test]
    fn g_generator_is_ristretto_basepoint() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

        assert_eq!(
            G, RISTRETTO_BASEPOINT_POINT,
            "G generator must be the Ristretto basepoint"
        );
    }
}
