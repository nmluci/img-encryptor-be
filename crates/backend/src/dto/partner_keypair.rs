use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PartnerPKPayload {
   pub id: u64,
   pub partner_id: u64,
   pub hash: String,
   pub public_key: String,   
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PartnerPKResponse {
   pub id: u64,
   pub partner_id: u64,
   pub public_key: String,
   pub keypair_hash: String,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct ListPartnerPKResponse {
   pub keys: Vec<PartnerPKResponse>
}