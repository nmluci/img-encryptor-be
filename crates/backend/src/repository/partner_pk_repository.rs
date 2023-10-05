use crate::{
   config::database::{Database, DatabaseTrait},
   entity::security::PartnerKeyPair,
   error::db_error::DBError,
};
use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;

#[derive(Clone)]
pub struct PartnerPKRepository {
   pub(crate) db: Arc<Database>,
}

#[async_trait]
pub trait PartnerPKRepositoryTrait {
   fn new(conn: &Arc<Database>) -> Self;

   async fn find_partner_keypairs(&self, partner_id: u64) -> Result<PartnerKeyPair, DBError>;
   async fn find_partner_keypair_by_id(&self, id: u64) -> Result<PartnerKeyPair, DBError>;
   async fn find_partner_keypair_by_hash(&self, hash: String) -> Result<PartnerKeyPair, DBError>;
   async fn insert_partner_keypair(&self, keypair: PartnerKeyPair) -> Result<u64, DBError>;
   async fn update_partner_keypair(&self, keypair: PartnerKeyPair) -> Option<DBError>;
   async fn delete_partner_keypair(&self, id: String) -> Option<DBError>;
}

#[async_trait]
impl PartnerPKRepositoryTrait for PartnerPKRepository {
   fn new(conn: &Arc<Database>) -> Self {
      Self {
         db: Arc::clone(conn),
      }
   }

   async fn find_partner_keypairs(&self, partner_id: u64) -> Result<PartnerKeyPair, DBError> {
      let res = sqlx::query_as::<_, PartnerKeyPair>(
         r#"
         select id, partner_id, public_key, keypair_hash from tb_partner_keypair
         where partner_id = ?
      "#,
      )
      .bind(partner_id)
      .fetch_optional(self.db.get_pool())
      .await;

      match res {
         Ok(v) => match v {
            Some(v) => Ok(v),
            None => Err(DBError::NotFound),
         },
         Err(e) => Err(DBError::Yabaii(e.to_string())),
      }
   }

   async fn find_partner_keypair_by_id(&self, id: u64) -> Result<PartnerKeyPair, DBError> {
      let res = sqlx::query_as::<_, PartnerKeyPair>(
         r#"
      select id, partner_id, public_key, keypair_hash from tb_partner_keypair
      where id = ?
   "#,
      )
      .bind(id)
      .fetch_optional(self.db.get_pool())
      .await;

      match res {
         Ok(v) => match v {
            Some(v) => Ok(v),
            None => Err(DBError::NotFound),
         },
         Err(e) => Err(DBError::Yabaii(e.to_string())),
      }
   }

   async fn find_partner_keypair_by_hash(&self, hash: String) -> Result<PartnerKeyPair, DBError> {
      let res = sqlx::query_as::<_, PartnerKeyPair>(
         r#"
      select id, partner_id, public_key, keypair_hash from tb_partner_keypair
      where keypair_hash = ?
   "#,
      )
      .bind(hash)
      .fetch_optional(self.db.get_pool())
      .await;

      match res {
         Ok(v) => match v {
            Some(v) => Ok(v),
            None => Err(DBError::NotFound),
         },
         Err(e) => Err(DBError::Yabaii(e.to_string())),
      }
   }

   async fn insert_partner_keypair(&self, keypair: PartnerKeyPair) -> Result<u64, DBError> {
      let current_time = Utc::now();

      let res = sqlx::query("insert into tb_partner_keypair(partner_id, public_key, keypair_hash, created_at, updated_at) values (?, ?, ?, ?, ?)")
      .bind(keypair.partner_id)
      .bind(keypair.public_key)
      .bind(keypair.keypair_hash)
      .bind(current_time)
      .bind(current_time)
      .execute(self.db.get_pool())
      .await;

      match res {
         Ok(v) => Ok(v.last_insert_id()),
         Err(e) => Err(DBError::Yabaii(e.to_string())),
      }
   }

   async fn update_partner_keypair(&self, keypair: PartnerKeyPair) -> Option<DBError> {
      let current_time = Utc::now();

      let res = sqlx::query(
         r#"
         update tb_partner_keypair set
            public_key = ?,
            keypair_hash = ?,
            updated_at = ?
         where
            id = ? and partner_id = ?
      "#,
      )
      .bind(keypair.public_key)
      .bind(keypair.keypair_hash)
      .bind(current_time)
      .bind(keypair.id)
      .bind(keypair.partner_id)
      .execute(self.db.get_pool())
      .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None,
      }
   }

   async fn delete_partner_keypair(&self, hash: String) -> Option<DBError> {
      let res = sqlx::query(r#"delete from tb_partner_keypair where keypair_hash = ?"#)
         .bind(hash)
         .execute(self.db.get_pool())
         .await;

      match res {
         Err(e) => Some(DBError::Yabaii(e.to_string())),
         _ => None,
      }
   }
}
