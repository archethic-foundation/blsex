use crate::keys::{PublicKey, SecretKey};
use crate::signature::Signature;

use bls12_381::Scalar;

mod errors;
mod hash;
mod keys;
mod signature;

use rustler::types::{Binary, OwnedBinary};
use rustler::Term;

#[rustler::nif]
pub fn get_public_key(seed: Binary) -> OwnedBinary {
    let secret_key = parse_secret_key(seed.as_slice());
    let public_key = secret_key.public_key().to_bytes();
    let mut bin = OwnedBinary::new(public_key.len()).unwrap();
    bin.as_mut_slice().copy_from_slice(&public_key);
    bin
}

#[rustler::nif]
fn sign(seed: Binary, data: Binary) -> OwnedBinary {
    let secret_key = parse_secret_key(seed.as_slice());
    let signature = secret_key.sign(data.as_slice());
    let signature_bytes = signature.to_bytes();
    let mut bin = OwnedBinary::new(signature_bytes.len()).unwrap();
    bin.as_mut_slice().copy_from_slice(&signature_bytes);
    bin
}

fn parse_secret_key(seed: &[u8]) -> SecretKey {
    let bytes_slice: &[u8; 64] = seed.try_into().unwrap();
    SecretKey(Scalar::from_bytes_wide(bytes_slice))
}

#[rustler::nif]
pub fn verify_signature(public_key: Binary, message: Binary, signature: Binary) -> bool {
    let public_key = parse_public_key(public_key.as_slice());
    let signature = parse_signature(signature.as_slice());
    match public_key.verify(&signature, message.as_slice()) {
        Ok(_) => true,
        _ => false,
    }
}

fn parse_public_key(public_key: &[u8]) -> PublicKey {
    PublicKey::from_bytes(&public_key).unwrap()
}

fn parse_signature(signature: &[u8]) -> Signature {
    Signature::from_bytes(&signature).unwrap()
}

#[rustler::nif]
pub fn aggregate_signatures(signatures: Term, public_keys: Term) -> OwnedBinary {
    let signatures: Vec<Binary> = signatures.decode().unwrap();
    let public_keys: Vec<Binary> = public_keys.decode().unwrap();

    let parsed_signatures = signatures
        .iter()
        .map(|sig| parse_signature(sig.as_slice()))
        .collect::<Vec<Signature>>();

    let parse_public_keys = public_keys
        .iter()
        .map(|x| parse_public_key(x.as_slice()))
        .collect::<Vec<PublicKey>>();

    let aggregated_signature =
        Signature::aggregate(parsed_signatures.as_slice(), parse_public_keys.as_slice()).unwrap();
    let signature_bytes = aggregated_signature.to_bytes();
    let mut bin = OwnedBinary::new(signature_bytes.len()).unwrap();
    bin.as_mut_slice().copy_from_slice(&signature_bytes);
    bin
}

#[rustler::nif]
pub fn aggregate_public_keys(public_keys: Term) -> OwnedBinary {
    let public_keys: Vec<Binary> = public_keys.decode().unwrap();
    let parsed_public_keys = public_keys
        .iter()
        .map(|x| parse_public_key(x.as_slice()))
        .collect::<Vec<_>>();

    let aggregated_public_key = PublicKey::aggregate(parsed_public_keys.as_slice()).unwrap();
    let aggregated_public_key_bytes = aggregated_public_key.to_bytes();
    let mut bin = OwnedBinary::new(aggregated_public_key_bytes.len()).unwrap();
    bin.as_mut_slice()
        .copy_from_slice(&aggregated_public_key_bytes);
    bin
}

rustler::init!(
    "Elixir.BlsEx",
    [
        get_public_key,
        sign,
        verify_signature,
        aggregate_signatures,
        aggregate_public_keys
    ]
);
