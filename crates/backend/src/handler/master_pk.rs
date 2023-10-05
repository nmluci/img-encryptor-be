use crate::dto::master_keypair::{ListMasterPKResponse, MasterPKResponse};
use crate::error::api_error::ApiError;
use crate::response::api_response::ApiResponse;
use crate::service::master_pk_service::MasterPKServiceTrait;
use crate::state::master_pk_state::MasterPKState;
use axum::extract::{Path, State};
use axum_extra::extract::WithRejection;
use axum::Json;

// pub async fn handle_delete_keypair(
//    State(state): State<MasterPKState>,
//    WithRejection(Path(hash), _): WithRejection<Path<String>, ApiError>,
// ) -> Result<Json<ApiResponse<()>>, ApiError> {
//    let res = state.service.delete_keypair(hash).await;

//    match res {
//       Some(e) => Err(e)?,
//       _ => Ok(Json(ApiResponse::send(()))),
//    }
// }
