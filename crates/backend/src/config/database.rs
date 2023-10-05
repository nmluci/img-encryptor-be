use crate::parameter;
use async_trait::async_trait;
use log::{info, debug};
use sqlx::{Error, MySql, MySqlPool, Pool};

pub struct Database {
   pool: Pool<MySql>,
}

#[async_trait]
pub trait DatabaseTrait {
   async fn init() -> Result<Self, Error>
   where
      Self: Sized;
   fn get_pool(&self) -> &Pool<MySql>;
}

#[async_trait]
impl DatabaseTrait for Database {
   async fn init() -> Result<Self, Error> {
      let db = parameter::get_param("DATABASE_URL");
      let pool = MySqlPool::connect(&db)
         .await
         .unwrap_or_else(|e| panic!("connect to database err: {}", e));

      if parameter::get_param("FF_SKIP_MIGRATIONS") == "1" {
         info!("FF_SKIP_MIGRATIONS detected, skipping automigrations");
         return Ok(Self {pool})
      }
      
      sqlx::migrate!("../../migrations")
         .run(&pool)
         .await
         .unwrap_or_else(|e| panic!("migration err: {}", e));
      Ok(Self { pool })
   }

   fn get_pool(&self) -> &Pool<MySql> {
      &self.pool
   }
}
