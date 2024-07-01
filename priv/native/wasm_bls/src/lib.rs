use crate::keys::{PublicKey, SecretKey};
use crate::request::{
    PublicKeyAggregationRequest, SignRequest, SignatureAggregateRequest, VerifyAggregatedRequest,
    VerifyRequest,
};
use crate::signature::Signature;
use bls12_381::Scalar;

use extism_pdk::*;

mod errors;
mod hash;
mod keys;
mod request;
mod signature;

#[plugin_fn]
pub fn getPublicKey(seed_str: String) -> FnResult<String> {
    let secret_key = parse_secret_key(seed_str.clone());
    let public_key = secret_key.public_key().to_bytes();
    let public_key_hex = hex::encode(public_key);
    Ok(public_key_hex)
}

#[plugin_fn]
pub fn signData(request: SignRequest) -> FnResult<String> {
    let secret_key = parse_secret_key(request.seed);
    let signature = secret_key.sign(request.data.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());
    Ok(signature_hex)
}

fn parse_secret_key(seed: String) -> SecretKey {
    let bytes = hex::decode(seed).unwrap();
    let bytes_slice: &[u8; 64] = bytes.as_slice().try_into().unwrap();
    SecretKey(Scalar::from_bytes_wide(bytes_slice))
}

#[plugin_fn]
pub fn verifySignature(request: VerifyRequest) -> FnResult<String> {
    let public_key = parse_public_key(request.public_key);
    let signature = parse_signature(request.signature);
    match public_key.verify(&signature, request.data.as_bytes()) {
        Ok(_) => Ok("true".to_string()),
        _ => Ok("false".to_string()),
    }
}

fn parse_public_key(public_key_str: String) -> PublicKey {
    let public_key_bytes = hex::decode(public_key_str).unwrap();
    PublicKey::from_bytes(&public_key_bytes).unwrap()
}

fn parse_signature(signature_str: String) -> Signature {
    let signature_bytes = hex::decode(signature_str).unwrap();
    Signature::from_bytes(&signature_bytes).unwrap()
}

#[plugin_fn]
pub fn aggregateSignatures(request: SignatureAggregateRequest) -> FnResult<String> {
    let signatures = request
        .signatures
        .iter()
        .map(|sig| parse_signature(String::from(sig)))
        .collect::<Vec<Signature>>();

    let public_keys = request
        .public_keys
        .iter()
        .map(|x| parse_public_key(x.to_string()))
        .collect::<Vec<PublicKey>>();

    let aggregated_signature =
        Signature::aggregate(signatures.as_slice(), public_keys.as_slice()).unwrap();
    let signature_hex = hex::encode(aggregated_signature.to_bytes());
    Ok(signature_hex)
}

#[plugin_fn]
pub fn aggregatePublicKeys(request: PublicKeyAggregationRequest) -> FnResult<String> {
    let parsed_public_keys = request
        .public_keys
        .iter()
        .map(|x| parse_public_key(x.to_string()))
        .collect::<Vec<_>>();

    let aggregated_public_key = PublicKey::aggregate(parsed_public_keys.as_slice()).unwrap();

    let apk_hex = hex::encode(aggregated_public_key.to_bytes());
    Ok(apk_hex)
}

#[plugin_fn]
pub fn verifyAggregatedSignature(request: VerifyAggregatedRequest) -> FnResult<String> {
    let signature = parse_signature(request.signature);

    let parsed_public_keys = request
        .public_keys
        .iter()
        .map(|x| parse_public_key(x.to_string()))
        .collect::<Vec<_>>();

    let aggregated_public_key = PublicKey::aggregate(parsed_public_keys.as_slice()).unwrap();
    let result = match aggregated_public_key.verify(&signature, request.data.as_bytes()) {
        Ok(_) => "true",
        Err(_) => "false",
    };
    Ok(result.to_string())
}
