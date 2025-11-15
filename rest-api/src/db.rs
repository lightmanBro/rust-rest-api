//Database initialization and connection functions would go here

use ::sqlx::{Pool, Postgres, postgres::PgPoolOptions};

//Initialize the database connection pool given a database URL
/// We return `sqlx::Pool<Postgres>` which is `Send + Sync` and can be shared.
pub async fn init_db(database_url: &str) -> Result<Pool<Postgres>, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
