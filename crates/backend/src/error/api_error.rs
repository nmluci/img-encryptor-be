use crate::error::db_error::DBError;
use crate::response::api_response::ErrorResponse;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum ApiError {
   #[error(transparent)]
   JsonDeserialization(#[from] axum::extract::rejection::JsonRejection),
   #[error(transparent)]
   PathDeserialization(#[from] axum::extract::rejection::PathRejection),
   #[error(transparent)]
   QueryDeserialization(#[from] axum::extract::rejection::QueryRejection),
   #[error(transparent)]
   ExtensionsDeserialization(#[from] axum::extract::rejection::ExtensionRejection),
   #[error(transparent)]
   HostDeserialization(#[from] axum::extract::rejection::HostRejection),
   #[error(transparent)]
   BytesDeserialization(#[from] axum::extract::rejection::BytesRejection),
   #[error(transparent)]
   DBError(#[from] DBError),
   // #[error(transparent)]
   // KeypairError(#[from] KeypairError),
   // #[error(transparent)]
   // SecurityError(#[from] SecurityError),
}

impl IntoResponse for ApiError {
   fn into_response(self) -> Response {
      match self {
         ApiError::JsonDeserialization(x) => {
            ErrorResponse::send(x.status().as_u16(), 0, Some(x.body_text())).into_response()
         }
         ApiError::PathDeserialization(x) => {
            ErrorResponse::send(x.status().as_u16(), 0, Some(x.body_text())).into_response()
         }
         ApiError::QueryDeserialization(x) => {
            ErrorResponse::send(x.status().as_u16(), 0, Some(x.body_text())).into_response()
         }
         ApiError::ExtensionsDeserialization(x) => {
            ErrorResponse::send(x.status().as_u16(), 0, Some(x.body_text())).into_response()
         }
         ApiError::HostDeserialization(x) => {
            ErrorResponse::send(x.status().as_u16(), 0, Some(x.body_text())).into_response()
         }
         ApiError::BytesDeserialization(x) => {
            ErrorResponse::send(x.status().as_u16(), 0, Some(x.body_text())).into_response()
         }
         ApiError::DBError(error) => error.into_response(),
         // ApiError::KeypairError(error) => error.into_response(),
         // ApiError::SecurityError(error) => error.into_response(),
      }
   }
}
