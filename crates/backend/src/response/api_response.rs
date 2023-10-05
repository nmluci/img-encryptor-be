use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ApiResponse<T> {
   #[serde(skip)]
   status: u16,
   data: Option<T>,
   error: Option<ErrorResponse>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ErrorResponse {
   code: u16,
   #[serde(rename = "msg")]
   message: Option<String>,
}

impl<T> ApiResponse<T>
where
   T: Serialize,
{
   pub(crate) fn send(data: T) -> Self {
      ApiResponse {
         status: StatusCode::OK.as_u16(),
         data: Some(data),
         error: None,
      }
   }
}

impl ErrorResponse {
   pub(crate) fn send(status: u16, code: u16, message: Option<String>) -> Response {
      ApiResponse {
         status,
         data: None,
         error: Some(ErrorResponse { code, message }),
      }
      .into_response()
   }
}

impl IntoResponse for ApiResponse<()> {
   fn into_response(self) -> Response {
      (
         StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
         Json(self),
      )
         .into_response()
   }
}
