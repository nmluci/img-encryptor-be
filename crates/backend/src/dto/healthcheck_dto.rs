
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct HealthCheckDto {
    pub message: String,
    pub unix_timestamp: i64,
    pub timestamp: String
}

