use crate::response::api_response::ErrorResponse;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DBError {
    #[error("{0}")]
    Yabaii(String),
    #[error("entity not found")]
    NotFound,
}

impl IntoResponse for DBError {
    fn into_response(self) -> Response {
        let status_code = match self {
            DBError::Yabaii(_) => StatusCode::INTERNAL_SERVER_ERROR,
            DBError::NotFound => StatusCode::NOT_FOUND
        };

        ErrorResponse::send(status_code.as_u16(), 0, Some(self.to_string()))
    }
}