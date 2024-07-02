use crate::errors::Error;
use crate::hash::{h0, h1};
use crate::signature::Signature;

use bls12_381::{G1Affine, G1Projective, Scalar};
use group::Curve;
use pairing::PairingCurveAffine;

pub struct PublicKey(pub(crate) G1Projective);
pub struct SecretKey(pub(crate) Scalar);

impl SecretKey {
    /// Generates a new [`PublicKey`] from a [`SecretKey`].
    /// Calculated by `pk = g1 * sk`.
    pub fn public_key(&self) -> PublicKey {
        let g_1 = G1Projective::generator();
        PublicKey(g_1 * self.0)
    }

    /// Sign a message, producing a [`Signature`].
    pub fn sign(&self, msg: &[u8]) -> Signature {
        // Hash message
        let h = h0(msg);

        // Multiply point by sk
        let e = h * self.0;
        Signature(e.into())
    }
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 48] {
        let t = self.0.to_affine();
        t.to_compressed()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 48 {
            return Err(Error::InvalidPoint);
        }
        let mut res = [0u8; 48];
        res.as_mut().copy_from_slice(bytes);
        let affine: G1Affine =
            Option::from(G1Affine::from_compressed(&res)).ok_or(Error::InvalidPoint)?;
        Ok(Self(affine.into()))
    }

    /// Verify a [`Signature`] by comparing the results of the two pairing
    /// operations: e(sig, g_1) == e(Hₒ(m), pk).
    pub fn verify(&self, sig: &Signature, msg: &[u8]) -> Result<(), Error> {
        if !self.is_valid() || !sig.is_valid() {
            return Err(Error::InvalidPoint);
        }
        let h0m = h0(msg);

        let p1 = sig.0.pairing_with(&G1Affine::generator());
        let p2 = h0m.to_affine().pairing_with(&self.0.to_affine());

        if p1 == p2 {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn is_valid(&self) -> bool {
        let is_identity: bool = self.0.is_identity().into();
        self.0.to_affine().is_torsion_free().into() && self.0.is_on_curve().into() && !is_identity
    }

    pub fn aggregate(pks: &[PublicKey]) -> Result<Self, Error> {
        if pks.is_empty() {
            return Err(Error::ZeroSizedInput);
        }
        let public_keys_iter = pks.iter();
        let valid_keys = public_keys_iter.fold(true, |acc, next| acc & next.is_valid());
        if !valid_keys {
            return Err(Error::InvalidPoint);
        }

        let sum = pks
            .into_iter()
            .map(|public_key| {
                let t = h1(&public_key);
                let gx = public_key.0 * t;
                G1Projective::from(gx)
            })
            .fold(G1Projective::default(), |acc, next| acc + next);

        let agg_pub = G1Projective::from(sum);
        Ok(Self(agg_pub))
    }
}
