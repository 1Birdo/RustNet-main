use serde::{Deserialize, Serialize, Serializer, Deserializer};
use chrono::{DateTime, Utc};
use tokio::fs;
use super::error::{CncError, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng}
};
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Mutex;
use std::sync::Arc;

/// Manages user authentication and storage
pub struct UserManager {
    users_file: String,
    users_cache: Arc<Mutex<Vec<User>>>,

}

impl UserManager {
    pub fn new(users_file: String) -> Self {
        Self {
            users_file,
            users_cache: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub async fn load_users(&self) -> Result<()> {
        let contents = match fs::read_to_string(&self.users_file).await {
            Ok(c) => c,
            Err(_) => return Ok(()), // File might not exist yet
        };
        
        let users: Vec<User> = serde_json::from_str(&contents).unwrap_or_default();
        *self.users_cache.lock().await = users;
        Ok(())
    }

    pub async fn get_all_users(&self) -> Vec<User> {
        self.users_cache.lock().await.clone()
    }

    pub async fn get_user(&self, username: &str) -> Option<User> {
        let users = self.users_cache.lock().await;
        users.iter()
            .find(|u| u.username.eq_ignore_ascii_case(username))
            .cloned()
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<Option<User>> {
        if !validate_username(username) {
            return Err(CncError::AuthFailed("Invalid username format".to_string()));
        }
        
        if !validate_password_input(password) {
            return Err(CncError::AuthFailed("Invalid password format".to_string()));
        }

        let users = self.users_cache.lock().await;
        for user in users.iter() {
            if user.username.eq_ignore_ascii_case(username) && verify_password(password, &user.password_hash)? && user.expire > Utc::now() {
                return Ok(Some(user.clone()));
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

        let mut users = self.users_cache.lock().await;
        if users.iter().any(|u| u.username.eq_ignore_ascii_case(&username)) {
            return Err(CncError::AuthFailed(format!("User '{}' already exists", username)));
        }

        let new_user = User::new(username, password, expire, level)?;
        users.push(new_user);
        
        // Save to file
        self.save_users_internal(&users).await?;
        Ok(())
    }

    pub async fn delete_user(&self, username: &str) -> Result<()> {
        let mut users = self.users_cache.lock().await;
        let initial_len = users.len();
        users.retain(|u| !u.username.eq_ignore_ascii_case(username));
        
        if users.len() == initial_len {
            return Err(CncError::AuthFailed(format!("User '{}' not found", username)));
        }
        
        if users.is_empty() {
            return Err(CncError::AuthFailed("Cannot delete last user".to_string()));
        }

        self.save_users_internal(&users).await?;
        Ok(())
    }

    pub async fn change_password(&self, username: &str, new_password: &str) -> Result<()> {
        if !validate_password_input(new_password) {
            return Err(CncError::AuthFailed("Invalid password format".to_string()));
        }

        let mut users = self.users_cache.lock().await;
        let user = users.iter_mut()
            .find(|u| u.username.eq_ignore_ascii_case(username))
            .ok_or_else(|| CncError::AuthFailed(format!("User '{}' not found", username)))?;

        user.password_hash = hash_password(new_password)?;
        
        self.save_users_internal(&users).await?;
        Ok(())
    }

    pub async fn update_user(&self, username: &str, level: Option<Level>, expire: Option<DateTime<Utc>>) -> Result<()> {
        let mut users = self.users_cache.lock().await;
        let user = users.iter_mut()
            .find(|u| u.username.eq_ignore_ascii_case(username))
            .ok_or_else(|| CncError::AuthFailed(format!("User '{}' not found", username)))?;

        if let Some(l) = level {
            user.level = l;
        }
        if let Some(e) = expire {
            user.expire = e;
        }

        self.save_users_internal(&users).await?;
        Ok(())
    }

    pub async fn check_database_integrity(&self) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        let mut users = self.users_cache.lock().await.clone();
        
        // Check for duplicate usernames (case-insensitive)
        let mut seen = std::collections::HashSet::new();
        let mut duplicates = Vec::new();
        
        for user in &users {
            let username_lower = user.username.to_lowercase();
            if !seen.insert(username_lower.clone()) {
                duplicates.push(username_lower);
            }
        }
        
        if !duplicates.is_empty() {
            warnings.push(format!("Found {} duplicate username(s): {}", 
                duplicates.len(), 
                duplicates.join(", ")
            ));
            
            // Remove duplicates, keeping only the most recently expired entry
            let mut unique_users = Vec::new();
            let mut seen_usernames = std::collections::HashSet::new();
            
            // Sort by expiry date descending
            users.sort_by(|a, b| b.expire.cmp(&a.expire));
            
            for user in users.clone() {
                let username_lower = user.username.to_lowercase();
                if seen_usernames.insert(username_lower) {
                    unique_users.push(user);
                }
            }
            
            // Update cache and file
            *self.users_cache.lock().await = unique_users.clone();
            self.save_users_internal(&unique_users).await?;
            
            warnings.push(format!("Removed {} duplicate entries, kept {} unique users", 
                users.len() - unique_users.len(),
                unique_users.len()
            ));
        }
        
        // Check for expired accounts
        let now = Utc::now();
        let expired_count = users.iter().filter(|u| u.expire < now).count();
        if expired_count > 0 {
            warnings.push(format!("Found {} expired account(s)", expired_count));
        }
        
        Ok(warnings)
    }

    async fn save_users_internal(&self, users: &[User]) -> Result<()> {
        // Create backup
        if tokio::fs::metadata(&self.users_file).await.is_ok() {
            let timestamp = chrono::Utc::now().timestamp();
            let backup_file = format!("{}.backup.{}", self.users_file, timestamp);
            let _ = tokio::fs::copy(&self.users_file, &backup_file).await;
            cleanup_old_backups(&self.users_file).await;
        }

        let json = serde_json::to_string_pretty(users)?;
        fs::write(&self.users_file, json).await?;
        Ok(())
    }
}

/// Track login attempts to prevent brute force attacks
pub struct LoginAttemptTracker {
    attempts: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl LoginAttemptTracker {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    
    /// Record a failed login attempt for a username
    pub async fn record_failed_attempt(&self, username: &str) {
        let mut attempts = self.attempts.lock().await;
        attempts.entry(username.to_lowercase())
            .or_insert_with(Vec::new)
            .push(Instant::now());
    }
    
    /// Check if a username is currently locked out
    /// Returns true if 5+ failed attempts in last 5 minutes
    pub async fn is_locked_out(&self, username: &str) -> bool {
        let attempts = self.attempts.lock().await;
        if let Some(times) = attempts.get(&username.to_lowercase()) {
            let recent = times.iter()
                .filter(|t| t.elapsed().as_secs() < 300)  // 5 minutes
                .count();
            recent >= 5
        } else {
            false
        }
    }
    
    /// Clear attempts for a username (after successful login)
    pub async fn clear_attempts(&self, username: &str) {
        self.attempts.lock().await.remove(&username.to_lowercase());
    }
    
    /// Get remaining lockout time in seconds
    pub async fn get_lockout_remaining(&self, username: &str) -> u64 {
        let attempts = self.attempts.lock().await;
        if let Some(times) = attempts.get(&username.to_lowercase()) {
            if let Some(oldest_recent) = times.iter()
                .filter(|t| t.elapsed().as_secs() < 300)
                .min_by_key(|t| t.elapsed())
            {
                return 300u64.saturating_sub(oldest_recent.elapsed().as_secs());
            }
        }
        0
    }
    
    /// Cleanup old attempts (call periodically)
    pub async fn cleanup_old_attempts(&self) {
        let mut attempts = self.attempts.lock().await;
        for (_, times) in attempts.iter_mut() {
            times.retain(|t| t.elapsed().as_secs() < 300);
        }
        attempts.retain(|_, times| !times.is_empty());
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

/// Cleanup old backup files, keeping only the last 10
async fn cleanup_old_backups(users_file: &str) {
    let dir_path = std::path::Path::new(users_file).parent().unwrap_or(std::path::Path::new("."));
    let file_name = std::path::Path::new(users_file).file_name().unwrap().to_str().unwrap();
    
    let mut backups = Vec::new();
    
    if let Ok(mut entries) = tokio::fs::read_dir(dir_path).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            if let Ok(name) = entry.file_name().into_string() {
                if name.starts_with(file_name) && name.contains(".backup.") {
                    if let Ok(metadata) = entry.metadata().await {
                        if let Ok(modified) = metadata.modified() {
                            backups.push((entry.path(), modified));
                        }
                    }
                }
            }
        }
    }
    
    // Sort by modification time (newest first)
    backups.sort_by(|a, b| b.1.cmp(&a.1));
    
    // Remove old backups (keep only 10 most recent)
    for (path, _) in backups.iter().skip(10) {
        if let Err(e) = tokio::fs::remove_file(path).await {
            tracing::warn!("Failed to remove old backup {:?}: {}", path, e);
        } else {
            tracing::debug!("Removed old backup: {:?}", path);
        }
    }
}

pub async fn migrate_plaintext_passwords_at(users_file: &str) -> Result<()> {
    let contents = match fs::read_to_string(users_file).await {
        Ok(c) => c,
        Err(_) => return Ok(()), // No file to migrate
    };
    
    #[derive(Deserialize)]
    struct OldUser {
        #[serde(rename = "Username")]
        username: String,
        #[serde(rename = "Password", default)]
        password: Option<String>,
        #[serde(rename = "PasswordHash", default)]
        password_hash: Option<String>,
        #[serde(rename = "Expire")]
        expire: DateTime<Utc>,
        #[serde(rename = "Level")]
        level: String,
    }
    
    let old_users: Vec<OldUser> = serde_json::from_str(&contents)?;
    let mut new_users = Vec::new();
    let mut migrated = false;
    
    for old_user in old_users {
        let hash = if let Some(existing_hash) = old_user.password_hash {
            existing_hash
        } else if let Some(plaintext) = old_user.password {
            migrated = true;
            tracing::warn!("Migrating plaintext password for user: {}", old_user.username);
            hash_password(&plaintext)?
        } else {
            return Err(CncError::AuthFailed("User has no password or hash".to_string()));
        };
        
        new_users.push(User {
            username: old_user.username,
            password_hash: hash,
            expire: old_user.expire,
            level: Level::from_str(&old_user.level),
        });
    }
    
    if migrated {
        let json = serde_json::to_string_pretty(&new_users)?;
        fs::write(users_file, json).await?;
        tracing::info!("Successfully migrated plaintext passwords to hashed format");
    }
    
    Ok(())
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
