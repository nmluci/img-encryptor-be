use async_trait::async_trait;
use std::sync::Arc;

use crate::config::database::Database;
use crate::config::parameter;
use crate::error::db_error::DBError;

#[derive(Clone)]
pub struct MasterPKService {}

#[async_trait]
pub trait MasterPKServiceTrait {
   fn new(db: &Arc<Database>) -> Self;
}

#[async_trait]
impl MasterPKServiceTrait for MasterPKService {
   fn new(conn: &Arc<Database>) -> Self {
      Self {}
   }
}
