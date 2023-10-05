use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct PartnerKeyPair {
   pub id: u64,
   pub partner_id: u64,
   pub public_key: String,
   pub keypair_hash: String,
   // pub created_at: DateTime<Utc>,
   // pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Deserialize, Serialize, sqlx::FromRow)]
pub struct MasterKeyPair {
   pub id: u64,
   pub public_key: String,
   pub private_key: String,
   pub keypair_hash: String,
   // pub created_at: DateTime<Utc>,
   // pub updated_at: DateTime<Utc>,
}

