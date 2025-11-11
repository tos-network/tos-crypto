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
