use crate::keys::PublicKey;
use bls12_381::{G2Projective, Scalar};
use dusk_bls12_381::BlsScalar;

/// h0 is the hash-to-curve-point function.
/// Hₒ : M -> Gₒ
pub fn h0(msg: &[u8]) -> G2Projective {
    // Now multiply this message by the G2 base point,
    // to generate a G2Affine.

    let g2 = G2Projective::generator();
    let msg_scalar = Scalar::from_bytes(&BlsScalar::hash_to_scalar(msg).to_bytes()).unwrap();

    g2 * msg_scalar
}

// h1 is the hashing function used in the modified BLS
// multi-signature construction.
/// H₁ : G₂ -> R
pub fn h1(pk: &PublicKey) -> Scalar {
    Scalar::from_bytes(&BlsScalar::hash_to_scalar(&pk.to_bytes()).to_bytes()).unwrap()
}
