use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecurityError {
   #[error("invalid payload")]
   InvalidPayload,
   #[error("key not found")]
   KeyNotFound,
   #[error("security error: {0}")]
   GenericError(String),
}
