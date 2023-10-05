use std::sync::Arc;

use crate::config::database::Database;
// use crate::repository::master_pk_repository::{MasterPKRepository, MasterPKRepositoryTrait};
use crate::service::master_pk_service::{MasterPKService, MasterPKServiceTrait};

#[derive(Clone)]
pub struct MasterPKState {
   pub(crate) service: MasterPKService,
   // pub(crate) repository: MasterPKRepository,
}

impl MasterPKState {
   pub fn new(conn: &Arc<Database>) -> MasterPKState {
      Self {
         service: MasterPKService::new(conn),
         // repository: MasterPKRepository::new(conn),
      }
   }
}
