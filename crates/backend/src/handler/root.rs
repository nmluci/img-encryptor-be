use crate::dto::healthcheck_dto;
use crate::response::api_response::{ApiResponse, ErrorResponse};
use axum::Json;
use axum::response::IntoResponse;
use chrono::Utc;
use hyper::StatusCode;

pub async fn handle_healthcheck() -> Json<ApiResponse<healthcheck_dto::HealthCheckDto>> {
   let time_now = Utc::now();

   Json(ApiResponse::send(healthcheck_dto::HealthCheckDto {
      message: "kyaaNakaWaZettaiDame!".to_string(),
      unix_timestamp: time_now.timestamp_millis(),
      timestamp: time_now.format("%d/%m/%Y %H:%M").to_string(),
   }))
}

pub async fn handle_fallback() -> impl IntoResponse {
   ErrorResponse::send(
      StatusCode::NOT_FOUND.as_u16(),
      404,
      Some("Nein, Everything absolutely legal here!".to_string()),
   )
}
