use extism_pdk::*;

#[derive(serde::Deserialize, FromBytes)]
#[encoding(Json)]
pub struct SignRequest {
    pub seed: String,
    pub data: String,
}

#[derive(serde::Deserialize, FromBytes)]
#[encoding(Json)]
pub struct VerifyRequest {
    pub public_key: String,
    pub data: String,
    pub signature: String,
}

#[derive(serde::Deserialize, FromBytes)]
#[encoding(Json)]
pub struct SignatureAggregateRequest {
    pub signatures: Vec<String>,
    pub public_keys: Vec<String>,
}

#[derive(serde::Deserialize, FromBytes)]
#[encoding(Json)]
pub struct VerifyAggregatedRequest {
    pub public_keys: Vec<String>,
    pub data: String,
    pub signature: String,
}

#[derive(serde::Deserialize, FromBytes)]
#[encoding(Json)]
pub struct PublicKeyAggregationRequest {
    pub public_keys: Vec<String>,
}
