use serde::{Deserialize, Serialize, Serializer, Deserializer};
use chrono::{DateTime, Utc};
use super::error::{CncError, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng}
};
use sqlx::{SqlitePool, Row};

/// Manages user authentication and storage
pub struct UserManager {
    pool: SqlitePool,
}

impl UserManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
        }
    }

    pub async fn get_all_users(&self) -> Result<Vec<User>> {
        self.get_users_paginated(1000, 0).await
    }

    pub async fn get_users_paginated(&self, limit: i64, offset: i64) -> Result<Vec<User>> {
        let users = sqlx::query("SELECT username, password_hash, role, expiry_date FROM users LIMIT ? OFFSET ?")
            .bind(limit)
            .bind(offset)
            .map(|row: sqlx::sqlite::SqliteRow| {
                let role_str: String = row.get("role");
                User {
                    username: row.get("username"),
                    password_hash: row.get("password_hash"),
                    expire: row.get("expiry_date"),
                    level: Level::from_str(&role_str),
                }
            })
            .fetch_all(&self.pool)
            .await?;
        
        Ok(users)
    }

    pub async fn get_user(&self, username: &str) -> Result<Option<User>> {
        let user = sqlx::query("SELECT username, password_hash, role, expiry_date FROM users WHERE username = ?")
            .bind(username)
            .map(|row: sqlx::sqlite::SqliteRow| {
                let role_str: String = row.get("role");
                User {
                    username: row.get("username"),
                    password_hash: row.get("password_hash"),
                    expire: row.get("expiry_date"),
                    level: Level::from_str(&role_str),
                }
            })
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<Option<User>> {
        if !validate_username(username) {
            return Err(CncError::AuthFailed("Invalid username format".to_string()));
        }
        
        if !validate_password_input(password) {
            return Err(CncError::AuthFailed("Invalid password format".to_string()));
        }

        let user_opt = self.get_user(username).await?;
        
        if let Some(user) = user_opt {
            if verify_password(password, &user.password_hash)? {
                if user.expire > Utc::now() {
                    return Ok(Some(user));
                } else {
                     // Account expired
                     return Ok(None);
                }
            }
        }
        
        Err(CncError::AuthFailed("Authentication failed".to_string()))
    }

    pub async fn add_user(&self, username: String, password: &str, expire: DateTime<Utc>, level: Level) -> Result<()> {
        if !validate_username(&username) {
            return Err(CncError::AuthFailed("Invalid username format".to_string()));
        }
        
        if !validate_password_input(password) {
            return Err(CncError::AuthFailed("Invalid password format".to_string()));
        }

        // Check if user exists
        if self.get_user(&username).await?.is_some() {
             return Err(CncError::AuthFailed(format!("User '{}' already exists", username)));
        }

        let password_hash = hash_password(password)?;
        let role_str = level.to_str();

        sqlx::query("INSERT INTO users (username, password_hash, role, expiry_date) VALUES (?, ?, ?, ?)")
            .bind(&username)
            .bind(password_hash)
            .bind(role_str)
            .bind(expire)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }

    pub async fn delete_user(&self, username: &str, requester_username: &str) -> Result<()> {
        if username == requester_username {
            return Err(CncError::AuthFailed("Cannot delete your own account".to_string()));
        }

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;

        // Prevent deleting the last user to avoid lockout
        if count <= 1 {
             // Check if the user we are trying to delete actually exists
             if self.get_user(username).await?.is_some() {
                 return Err(CncError::AuthFailed("Cannot delete last user".to_string()));
             }
        }

        let result = sqlx::query("DELETE FROM users WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(CncError::AuthFailed(format!("User '{}' not found", username)));
        }

        Ok(())
    }

    pub async fn change_password(&self, username: &str, new_password: &str) -> Result<()> {
        if !validate_password_input(new_password) {
            return Err(CncError::AuthFailed("Invalid password format".to_string()));
        }

        let password_hash = hash_password(new_password)?;

        let result = sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
            .bind(password_hash)
            .bind(username)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(CncError::AuthFailed(format!("User '{}' not found", username)));
        }
        
        Ok(())
    }

    pub async fn update_user(&self, username: &str, level: Option<Level>, expire: Option<DateTime<Utc>>) -> Result<()> {
        if level.is_none() && expire.is_none() {
            return Ok(());
        }

        let mut query = "UPDATE users SET ".to_string();
        let mut updates = Vec::new();
        
        if level.is_some() {
            updates.push("role = ?");
        }
        if expire.is_some() {
            updates.push("expiry_date = ?");
        }
        
        query.push_str(&updates.join(", "));
        query.push_str(" WHERE username = ?");
        
        let mut q = sqlx::query(&query);
        
        if let Some(l) = level {
            q = q.bind(l.to_str());
        }
        if let Some(e) = expire {
            q = q.bind(e);
        }
        
        q = q.bind(username);
        
        let result = q.execute(&self.pool).await?;
        
        if result.rows_affected() == 0 {
             return Err(CncError::AuthFailed(format!("User '{}' not found", username)));
        }

        Ok(())
    }
}

/// Track login attempts to prevent brute force attacks
pub struct LoginAttemptTracker {
    pool: SqlitePool,
}

impl LoginAttemptTracker {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
    
    /// Record a failed login attempt for a username and IP
    pub async fn record_failed_attempt(&self, username: &str, ip_address: &str) {
        let _ = sqlx::query("INSERT INTO login_attempts (username, ip_address, attempt_time) VALUES (?, ?, ?)")
            .bind(username)
            .bind(ip_address)
            .bind(Utc::now())
            .execute(&self.pool)
            .await;
    }
    
    /// Check if a username or IP is currently locked out
    /// Returns true if 5+ failed attempts in last 5 minutes
    pub async fn is_locked_out(&self, username: &str, ip_address: &str) -> bool {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM login_attempts WHERE (username = ? OR ip_address = ?) AND attempt_time > ?"
        )
        .bind(username)
        .bind(ip_address)
        .bind(Utc::now() - chrono::Duration::minutes(5))
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);
        
        count >= 5
    }
    
    /// Clear attempts for a username and IP (after successful login)
    pub async fn clear_attempts(&self, username: &str, ip_address: &str) {
        let _ = sqlx::query("DELETE FROM login_attempts WHERE username = ? OR ip_address = ?")
            .bind(username)
            .bind(ip_address)
            .execute(&self.pool)
            .await;
    }
    
    /// Get remaining lockout time in seconds
    pub async fn get_lockout_remaining(&self, username: &str, ip_address: &str) -> u64 {
        // Find the oldest attempt within the last 5 minutes that contributes to the lockout
        // Actually, we just need to know when the lockout expires.
        // If we have >= 5 attempts, the lockout expires 5 minutes after the *first* of those 5 attempts?
        // Or 5 minutes after the *last* attempt?
        // Usually it's a sliding window. If you have 5 attempts in the last 5 minutes, you are locked out.
        // You become unlocked when the 5th-to-last attempt is older than 5 minutes.
        
        // Let's get the timestamp of the 5th most recent attempt.
        // If we have fewer than 5, we are not locked out (return 0).
        
        let attempts: Vec<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT attempt_time FROM login_attempts WHERE (username = ? OR ip_address = ?) AND attempt_time > ? ORDER BY attempt_time DESC LIMIT 5"
        )
        .bind(username)
        .bind(ip_address)
        .bind(Utc::now() - chrono::Duration::minutes(5))
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default();

        if attempts.len() >= 5 {
            // The 5th most recent attempt (index 4) determines the start of the window that locks us out.
            // Wait, if I have 5 attempts at T, T+1, T+2, T+3, T+4.
            // I am locked out until T + 5min.
            // Because at T + 5min + epsilon, the attempt at T falls out of the window, and I have 4 attempts.
            
            let oldest_relevant_attempt = attempts[4]; // The 5th one
            let unlock_time = oldest_relevant_attempt + chrono::Duration::minutes(5);
            let now = Utc::now();
            
            if unlock_time > now {
                return (unlock_time - now).num_seconds() as u64;
            }
        }
        
        0
    }
    
    /// Cleanup old attempts (call periodically)
    pub async fn cleanup_old_attempts(&self) {
        let _ = sqlx::query("DELETE FROM login_attempts WHERE attempt_time < ?")
            .bind(Utc::now() - chrono::Duration::minutes(5))
            .execute(&self.pool)
            .await;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "Username")]
    pub username: String,
    
    #[serde(rename = "PasswordHash")]
    pub password_hash: String,
    
    #[serde(rename = "Expire")]
    pub expire: DateTime<Utc>,
    
    #[serde(rename = "Level")]
    pub level: Level,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Basic = 0,
    Pro = 1,
    Admin = 2,
    Owner = 3,
}

impl Serialize for Level {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_str())
    }
}

impl<'de> Deserialize<'de> for Level {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Level::from_str(&s))
    }
}

impl Level {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "owner" => Level::Owner,
            "admin" => Level::Admin,
            "pro" => Level::Pro,
            _ => Level::Basic,
        }
    }
    
    pub fn to_str(self) -> &'static str {
        match self {
            Level::Owner => "Owner",
            Level::Admin => "Admin",
            Level::Pro => "Pro",
            Level::Basic => "Basic",
        }
    }
}

impl User {
    pub fn get_level(&self) -> Level {
        self.level
    }
    
    #[allow(dead_code)]
    pub fn new(username: String, password: &str, expire: DateTime<Utc>, level: Level) -> Result<Self> {
        let password_hash = hash_password(password)?;
        Ok(Self {
            username,
            password_hash,
            expire,
            level,
        })
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| CncError::PasswordHashError(format!("{:?}", e)))?
        .to_string();
    
    Ok(hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| CncError::PasswordHashError(format!("{:?}", e)))?;
    
    let argon2 = Argon2::default();
    
    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn validate_username(username: &str) -> bool {
    if username.is_empty() || username.len() > 32 {
        return false;
    }
    
    username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
}

pub fn validate_password_input(password: &str) -> bool {
    if password.len() < 8 || password.len() > 128 {
        return false;
    }
    
    true
}

#[allow(dead_code)]
pub fn sanitize_username(username: &str) -> String {
    username
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(32)
        .collect()
}

pub fn random_string(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let mut rng = rand::rngs::OsRng;
    
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

pub fn set_title(title: &str) -> String {
    format!("\x1B]0;{}\x07", title)
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();
        
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_level_comparison() {
        assert!(Level::Owner >= Level::Admin);
        assert!(Level::Admin >= Level::Pro);
        assert!(Level::Pro >= Level::Basic);
        assert!(Level::Basic >= Level::Basic);
        
        assert!(Level::Basic < Level::Pro);
        assert!(Level::Pro < Level::Admin);
        assert!(Level::Admin < Level::Owner);
    }

    #[test]
    fn test_level_to_str() {
        assert_eq!(Level::Owner.to_str(), "Owner");
        assert_eq!(Level::Admin.to_str(), "Admin");
        assert_eq!(Level::Pro.to_str(), "Pro");
        assert_eq!(Level::Basic.to_str(), "Basic");
    }

    #[test]
    fn test_user_creation() {
        let user = User {
            username: "testuser".to_string(),
            password_hash: "hash".to_string(),
            expire: Utc::now(),
            level: Level::Basic,
        };
        
        assert_eq!(user.username, "testuser");
        assert_eq!(user.get_level(), Level::Basic);
    }

    #[test]
    fn test_validate_username() {
        assert!(validate_username("john"));
        assert!(validate_username("admin123"));
        assert!(validate_username("user_name"));
        assert!(validate_username("ab")); // 2 chars is valid
        
        assert!(!validate_username(&"a".repeat(33))); // too long (> 32)
        assert!(!validate_username("user@name")); // invalid char
        assert!(!validate_username("")); // empty
    }

    #[test]
    fn test_validate_password() {
        assert!(validate_password_input("password123"));
        assert!(validate_password_input("VerySecureP@ss!"));
        assert!(validate_password_input("12345678")); // exactly 8 chars
        
        assert!(!validate_password_input("short")); // too short (< 8)
        assert!(!validate_password_input(&"a".repeat(129))); // too long (> 128)
        assert!(!validate_password_input("")); // empty
    }

    #[test]
    fn test_random_string() {
        let str1 = random_string(16);
        let str2 = random_string(16);
        
        assert_eq!(str1.len(), 16);
        assert_eq!(str2.len(), 16);
        // Random strings might occasionally be the same, so don't assert inequality
        
        // Check all chars are from the valid charset
        const CHARSET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
        assert!(str1.chars().all(|c| CHARSET.contains(c)));
    }
}
