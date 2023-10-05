use crate::config::database::{Database, DatabaseTrait};
use crate::entity::security::MasterKeyPair;
use crate::error::db_error::DBError;

use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;


#[derive(Clone)]
pub struct MasterPKRepository {
   pub(crate) db: Arc<Database>,
}

#[async_trait]
pub trait MasterPKRepositoryTrait {
   fn new(conn: &Arc<Database>) -> Self;

   async fn find_keypairs(&self) -> Result<Vec<MasterKeyPair>, DBError>;
   async fn find_keypair_by_id(&self, id: u64) -> Result<MasterKeyPair, DBError>;
   async fn find_keypair_by_hash(&self, hash: String) -> Result<MasterKeyPair, DBError>;
   async fn insert_keypair(&self, keypair: MasterKeyPair) -> Result<u64, DBError>;
   async fn update_keypair(&self, keypair: MasterKeyPair) -> Option<DBError>;
   async fn delete_keypair(&self, id: u64) -> Option<DBError>;
}

#[async_trait]
impl MasterPKRepositoryTrait for MasterPKRepository {
   fn new(conn: &Arc<Database>) -> Self {
      Self {
         db: Arc::clone(conn),
      }
   }

   async fn find_keypairs(&self) -> Result<Vec<MasterKeyPair>, DBError> {
      let res = sqlx::query_as::<_, MasterKeyPair>(r#"
         select id, public_key, private_key, keypair_hash, created_at, updated_at from tb_master_keypair
      "#).fetch_all(self.db.get_pool()).await;

      match res {
         Ok(v) => Ok(v),
         Err(e) => Err(DBError::Yabaii(e.to_string()))
      }
   }

   async fn find_keypair_by_id(&self, id: u64) -> Result<MasterKeyPair, DBError> {
      let res = sqlx::query_as::<_, MasterKeyPair>(r#"
         select id, public_key, private_key, keypair_hash, created_at, updated_at from tb_master_keypair 
         where
            id = ?
      "#).bind(id)
      .fetch_optional(self.db.get_pool())
      .await;

      match res {
         Ok(v) => match v {
            Some(v) => Ok(v),
            None => Err(DBError::NotFound)
        },
        Err(e) => Err(DBError::Yabaii(e.to_string()))
     }
   }

   async fn find_keypair_by_hash(&self, hash: String) -> Result<MasterKeyPair, DBError> {
      let res = sqlx::query_as::<_, MasterKeyPair>(r#"
         select id, public_key, private_key, keypair_hash, created_at, updated_at from tb_master_keypair 
         where
            keypair_hash = ?
      "#).bind(hash)
      .fetch_optional(self.db.get_pool())
      .await;
   
      match res {
         Ok(v) => match v {
             Some(v) => Ok(v),
             None => Err(DBError::NotFound)
         },
         Err(e) => Err(DBError::Yabaii(e.to_string()))
      }
   }

   async fn insert_keypair(&self, keypair: MasterKeyPair) -> Result<u64, DBError> {
      let current_time = Utc::now();

      let res = sqlx::query(
         "insert into tb_master_keypair(public_key, private_key, keypair_hash, created_at, updated_at) values (?, ?, ?, ?, ?)")
      .bind(keypair.public_key)
         .bind(keypair.private_key) 
         .bind(keypair.keypair_hash) 
         .bind(current_time) 
         .bind(current_time)
      .execute(self.db.get_pool())
      .await;
   
      match res {
         Ok(v) => Ok(v.last_insert_id()),
         Err(e) => Err(DBError::Yabaii(e.to_string()))
      }
   }

   async fn update_keypair(&self, keypair: MasterKeyPair) -> Option<DBError> {
      let current_time = Utc::now();

      let res = sqlx::query(
         "update tb_master_keypair set 
            public_key = ?, 
            private_key = ?, 
            keypair_hash = ?,  
            updated_at = ?
         where 
            id = ?
         ")
      .bind(keypair.public_key)
         .bind(keypair.private_key) 
         .bind(keypair.keypair_hash) 
         .bind(current_time) 
         .bind(keypair.id)
      .execute(self.db.get_pool())
      .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None
      }

   }
   
   async fn delete_keypair(&self, id: u64) -> Option<DBError> {
      let res = sqlx::query("delete from tb_master_keypair where id = ?")
      .bind(id)
      .execute(self.db.get_pool())
      .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None
      }
   }
}
