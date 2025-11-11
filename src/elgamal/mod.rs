mod signature;

pub use signature::*;

pub use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;

// Constants that are still needed by the remaining code
pub const RISTRETTO_COMPRESSED_SIZE: usize = 32;
pub const SCALAR_SIZE: usize = 32;

// Re-export curve25519_dalek types that are needed
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::Scalar;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint};
use rand::rngs::OsRng;
use zeroize::Zeroize;

#[derive(Clone, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompressedPublicKey(CompressedRistretto);

impl CompressedPublicKey {
    pub fn new(point: CompressedRistretto) -> Self {
        Self(point)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn decompress(&self) -> Result<PublicKey, DecompressionError> {
        let point = self
            .0
            .decompress()
            .ok_or(DecompressionError::InvalidPoint)?;
        if point.is_identity() {
            return Err(DecompressionError::IdentityPoint);
        }
        Ok(PublicKey::from_point(point))
    }
}

// Minimal PublicKey type needed for signatures and pedersen
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(RistrettoPoint);

impl PublicKey {
    pub fn from_point(p: RistrettoPoint) -> Self {
        Self(p)
    }

    pub fn as_point(&self) -> &RistrettoPoint {
        &self.0
    }

    pub fn compress(&self) -> CompressedPublicKey {
        CompressedPublicKey::new(self.0.compress())
    }
}

// Error type for decompression
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecompressionError {
    #[error("point decompression failed")]
    InvalidPoint,
    #[error("identity point rejected")]
    IdentityPoint,
}

// Minimal PrivateKey implementation (for signatures only, no encryption)
#[derive(Clone, Zeroize, serde::Serialize, serde::Deserialize)]
pub struct PrivateKey(Scalar);

impl Default for PrivateKey {
    fn default() -> Self {
        Self::new()
    }
}

impl PrivateKey {
    pub fn new() -> Self {
        Self(Scalar::random(&mut OsRng))
    }

    pub fn from_scalar(scalar: Scalar) -> Self {
        Self(scalar)
    }

    pub fn as_scalar(&self) -> &Scalar {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    #[allow(clippy::result_unit_err)]
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, ()> {
        let scalar = Scalar::from_canonical_bytes(*bytes)
            .into_option()
            .ok_or(())?;
        Ok(Self(scalar))
    }

    pub fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes: [u8; 32] = hex::decode(hex)?
            .as_slice()
            .try_into()
            .map_err(|_| hex::FromHexError::InvalidStringLength)?;
        Self::from_bytes(&bytes).map_err(|_| hex::FromHexError::InvalidStringLength)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    // Generate signature using inverse construction (for compatibility)
    #[allow(non_snake_case)]
    pub fn sign(&self, message: &[u8], public_key: &PublicKey) -> Signature {
        use crate::proofs::H;

        let r = Scalar::random(&mut OsRng);
        let R = (*H) * r;
        let e = hash_and_point_to_scalar(&public_key.compress(), message, &R);
        let s = r + (e * self.0);

        Signature::new(s, e)
    }
}

// Minimal KeyPair implementation
#[derive(Clone)]
pub struct KeyPair {
    public_key: PublicKey,
    private_key: PrivateKey,
}

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyPair {
    pub fn new() -> Self {
        use crate::proofs::H;

        let private_key = PrivateKey::new();
        // Public key: P = H * private_key (standard Schnorr signature)
        let public_key = PublicKey::from_point((*H) * private_key.as_scalar());

        Self {
            public_key,
            private_key,
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn from_private_key(private_key: PrivateKey) -> Result<Self, ()> {
        use crate::proofs::H;

        // Validate non-zero
        if private_key.as_scalar() == &Scalar::ZERO {
            return Err(());
        }

        // Public key: P = H * private_key (standard Schnorr signature)
        let public_key = PublicKey::from_point((*H) * private_key.as_scalar());

        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn get_public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn get_private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn split(self) -> (PublicKey, PrivateKey) {
        (self.public_key, self.private_key)
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.private_key.sign(message, &self.public_key)
    }
}
