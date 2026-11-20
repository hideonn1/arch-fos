use std::path::Path;
use std::str::FromStr;

use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiDbError {
    #[error("database file does not exist yet at {0} (start arch-fos-collector first)")]
    MissingDatabase(String),
    #[error("sqlite error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

/// Opens the SQLite database strictly in read-only mode (`mode=ro`).
pub async fn open_readonly_pool(db_path: &Path) -> Result<SqlitePool, ApiDbError> {
    if !db_path.exists() {
        return Err(ApiDbError::MissingDatabase(db_path.display().to_string()));
    }

    let dsn = format!("sqlite://{}", db_path.display());
    let options = SqliteConnectOptions::from_str(&dsn)?
        .read_only(true)
        .create_if_missing(false);

    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await?;

    Ok(pool)
}
