use crate::errors::CryptoError;
use crate::hash::h1;
use crate::keys::PublicKey;
use bls12_381::{G2Affine, G2Projective};

#[derive(Debug)]
pub struct Signature(pub(crate) G2Affine);

impl Signature {
    pub fn is_valid(&self) -> bool {
        let is_identity: bool = self.0.is_identity().into();
        self.0.is_torsion_free().into() && self.0.is_on_curve().into() && !is_identity
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_compressed()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 96 {
            return Err(CryptoError::InvalidPoint);
        }
        let mut res = [0u8; 96];
        res.as_mut().copy_from_slice(bytes);

        match Option::from(G2Affine::from_compressed(&res)) {
            Some(affine) => Ok(Self(affine)),
            None => Err(CryptoError::InvalidPoint)
        }
    }

    pub fn aggregate(sigs: &[Self], public_keys: &[PublicKey]) -> Result<Self, CryptoError> {
        if sigs.is_empty() {
            return Err(CryptoError::ZeroSizedInput);
        }

        let res = sigs
            .into_iter()
            .zip(public_keys.iter())
            .map(|(sig, pk)| {
                let mut sig2 = Signature(sig.0);
                let t = h1(pk);
                sig2.0 = (sig2.0 * t).into();
                sig2
            })
            .fold(G2Projective::identity(), |acc, signature| acc + signature.0);

        Ok(Self(res.into()))
    }
}
