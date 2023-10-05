// use crate::response::api_response::ErrorResponse;
// use axum::http::StatusCode;
// use axum::response::{IntoResponse, Response};
// use log::error;
// use thiserror::Error;

// #[derive(Error, Debug)]
// pub enum KeypairError {
//    #[error("invalid keypair")]
//    Invalid,
//    #[error("no access")]
//    NoAccess,
//    #[error("keypair not found")]
//    NotFound,
//    #[error("keypair integrity check failed: {0}")]
//    IntegrityCheckFailed(String),
//    #[error("keypair error: {0}")]
//    Yabai(String),
//    #[error("failed to create keypair: {0}")]
//    CreationError(String),
// }

// impl IntoResponse for KeypairError {
//    fn into_response(self) -> Response {
//       let status_code = match self {
//          KeypairError::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
//          KeypairError::NotFound => StatusCode::NOT_FOUND,
//          KeypairError::NoAccess => StatusCode::UNAUTHORIZED,
//          KeypairError::IntegrityCheckFailed(_) => StatusCode::GONE,
//          KeypairError::Yabai(_) | KeypairError::CreationError(_) => {
//             StatusCode::INTERNAL_SERVER_ERROR
//          }
//       };

//       error!("err: {}", self);
//       ErrorResponse::send(status_code.as_u16(), 0, Some(self.to_string()))
//    }
// }
