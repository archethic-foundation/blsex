use crate::keys::{PublicKey, SecretKey};
use crate::signature::Signature;

use bls12_381::Scalar;
use rayon::prelude::*;

mod errors;
mod hash;
mod keys;
mod signature;

use rustler::types::{Binary, OwnedBinary};
use rustler::{Encoder, Env, Term};

mod atoms {
    rustler::atoms! {
        ok,
        error
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn get_public_key<'a>(env: Env<'a>, seed: Binary) -> Term<'a> {
    match parse_secret_key(seed.as_slice()) {
        Ok(secret_key) => {
            let public_key = secret_key.public_key().to_bytes();
            let mut bin = OwnedBinary::new(public_key.len()).unwrap();
            bin.as_mut_slice().copy_from_slice(&public_key);

            (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
        }
        Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn sign<'a>(env: Env<'a>, seed: Binary, data: Binary) -> Term<'a> {
    match parse_secret_key(seed.as_slice()) {
        Ok(secret_key) => {
            let signature = secret_key.sign(data.as_slice());
            let signature_bytes = signature.to_bytes();

            let mut bin = OwnedBinary::new(signature_bytes.len()).unwrap();
            bin.as_mut_slice().copy_from_slice(&signature_bytes);
            (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
        },
        Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
    }
}

fn parse_secret_key<'a>(seed: &[u8]) -> Result<SecretKey, errors::CryptoError> {
    match seed.try_into() {
        Ok(bytes_slice) => {
            Ok(SecretKey(Scalar::from_bytes_wide(bytes_slice)))
        },
        Err(_) => Err(errors::CryptoError::InvalidSeed)
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn verify_signature<'a>(env: Env<'a>, public_key: Binary, message: Binary, signature: Binary) -> Term<'a> {
    match PublicKey::from_bytes(public_key.as_slice()) {
        Ok(public_key) => {
            match Signature::from_bytes(signature.as_slice()) {
                Ok(signature) => {
                    match public_key.verify(&signature, message.as_slice()) {
                        Ok(_) => (atoms::ok(), true).encode(env),
                        Err(e) => (atoms::error(), e.to_atom(env)).encode(env),
                    }
                },
                Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
            }
        },
        Err(e) => {
            return (atoms::error(), e.to_atom(env)).encode(env)
        }
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn aggregate_signatures<'a>(env: Env<'a>, signatures: Term, public_keys: Term) -> Term<'a> {
    let signatures: Vec<Binary> = signatures.decode().unwrap();
    let public_keys: Vec<Binary> = public_keys.decode().unwrap();

    let parsed_signatures = signatures
        .iter()
        .map(|x| x.as_slice())
        .collect::<Vec<&[u8]>>()
        .par_iter()
        .map(|x| match Signature::from_bytes(x) {
            Ok(sig) => Option::Some(sig),
            Err(_) => Option::None,
        })
        .filter(|o| o.is_some())
        .map(|o| o.unwrap())
        .collect::<Vec<Signature>>();

    let parsed_public_keys = public_keys
        .iter()
        .map(|x| x.as_slice())
        .collect::<Vec<&[u8]>>()
        .par_iter()
        .map(|x| match PublicKey::from_bytes(x) {
            Ok(sig) => Option::Some(sig),
            Err(_) => Option::None,
        })
        .filter(|o| o.is_some())
        .map(|o| o.unwrap())
        .collect::<Vec<PublicKey>>();

    match Signature::aggregate(parsed_signatures.as_slice(), parsed_public_keys.as_slice()) {
        Ok(aggregated_signature) => {
            let signature_bytes = aggregated_signature.to_bytes();
            let mut bin = OwnedBinary::new(signature_bytes.len()).unwrap();
            bin.as_mut_slice().copy_from_slice(&signature_bytes);
            (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
        },
        Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn aggregate_public_keys<'a>(env: Env<'a>, public_keys: Term) -> Term<'a> {
    let public_keys: Vec<Binary> = public_keys.decode().unwrap();

    let parsed_public_keys = public_keys
        .iter()
        .map(|x| x.as_slice())
        .collect::<Vec<&[u8]>>()
        .par_iter()
        .map(|x| match PublicKey::from_bytes(x) {
            Ok(sig) => Option::Some(sig),
            Err(_) => Option::None,
        })
        .filter(|o| o.is_some())
        .map(|o| o.unwrap())
        .collect::<Vec<PublicKey>>();

    match PublicKey::aggregate(parsed_public_keys.as_slice()) {
        Ok(aggregated_public_key) => {
            let aggregated_public_key_bytes = aggregated_public_key.to_bytes();
            let mut bin = OwnedBinary::new(aggregated_public_key_bytes.len()).unwrap();
            bin.as_mut_slice()
                .copy_from_slice(&aggregated_public_key_bytes);
            (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
        },
        Err(e) => (atoms::error(), e.to_atom(env)).encode(env)
    }
}

rustler::init!("Elixir.BlsEx.Native");
