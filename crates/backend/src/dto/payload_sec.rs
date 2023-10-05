use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptDataPayload {
    pub data: String,
    pub partner_id: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptDataResponse {
   pub data: String,
   pub tag: String,
   pub secret_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DecryptDataPayload {
    pub keypair_hash: String,
    pub partner_id: u64,
    pub data: String,
    pub tag: String
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DecryptDataResponse {
    pub data: String
}
