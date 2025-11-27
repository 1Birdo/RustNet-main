use regex::Regex;
use std::sync::Arc;
use crate::modules::state::AppState;
use super::theme::CURRENT_THEME;

pub async fn get_terminal_width(state: &Arc<AppState>) -> usize {
    state.config.read().await.terminal_width
}
pub async fn get_terminal_height(state: &Arc<AppState>) -> usize {
    state.config.read().await.terminal_height
}
pub fn apply_gradient(text: &str, start_color: u8, end_color: u8) -> String {
    let len = text.chars().count();
    if len == 0 {
        return String::new();
    }
    let mut result = String::new();
    for (i, ch) in text.chars().enumerate() {
        let ratio = i as f32 / len.max(1) as f32;
        let color = start_color as f32 + (end_color as f32 - start_color as f32) * ratio;
        result.push_str(&format!("\x1b[38;5;{}m{}", color as u8, ch));
    }
    result.push_str("\x1b[0m");
    result
}
pub fn apply_ice_gradient(text: &str) -> String {
    let colors = [
        CURRENT_THEME.text, // White/Lightest
        195, 
        159, 
        123, 
        CURRENT_THEME.accent, 
        CURRENT_THEME.secondary, 
        CURRENT_THEME.primary
    ];
    let len = text.chars().count();
    if len == 0 { return String::new(); }
    let mut result = String::new();
    for (i, ch) in text.chars().enumerate() {
        let position = i as f32 / len.max(1) as f32;
        let index = (position * (colors.len() - 1) as f32).round() as usize;
        let color = colors[index.min(colors.len() - 1)];
        result.push_str(&format!("\x1b[38;5;{}m{}", color, ch));
    }
    result.push_str("\x1b[0m");
    result
}
pub fn apply_fire_gradient(text: &str) -> String {
    let colors = [196, 202, 208, 214, 220];
    let len = text.chars().count();
    if len == 0 { return String::new(); }
    let mut result = String::new();
    for (i, ch) in text.chars().enumerate() {
        let position = i as f32 / len.max(1) as f32;
        let index = (position * (colors.len() - 1) as f32).round() as usize;
        let color = colors[index.min(colors.len() - 1)];
        result.push_str(&format!("\x1b[38;5;{}m{}", color, ch));
    }
    result.push_str("\x1b[0m");
    result
}
#[allow(dead_code)]
pub fn strip_ansi(text: &str) -> String {
    use std::sync::OnceLock;
    static ANSI_REGEX: OnceLock<Regex> = OnceLock::new();
    let ansi_regex = ANSI_REGEX.get_or_init(|| {
        Regex::new(r"\x1b\[[0-9;]*m").expect("Invalid ANSI regex")
    });
    ansi_regex.replace_all(text, "").to_string()
}
#[allow(dead_code)]
pub fn visible_len(text: &str) -> usize {
    strip_ansi(text).chars().count()
}
pub struct MenuItem {
    pub cmd: &'static str,
    pub desc: &'static str,
}
pub const OWNER_COMMANDS: &[MenuItem] = &[
    MenuItem { cmd: "broadcast", desc: "Broadcast message" },
    MenuItem { cmd: "adduser", desc: "Add new user" },
    MenuItem { cmd: "deluser", desc: "Delete user" },
    MenuItem { cmd: "suspend", desc: "Suspend user" },
    MenuItem { cmd: "unsuspend", desc: "Unsuspend user" },
    MenuItem { cmd: "userchange", desc: "Modify user" },
    MenuItem { cmd: "db", desc: "Database ops" },
    MenuItem { cmd: "config", desc: "Edit config" },
    MenuItem { cmd: "revoke", desc: "Revoke node token" },
    MenuItem { cmd: "killall", desc: "Stop all attacks" },
    MenuItem { cmd: "panic", desc: "Emergency stop" },
    MenuItem { cmd: "regnode", desc: "Register node" },
    MenuItem { cmd: "update", desc: "Update system" },
    MenuItem { cmd: "nodes", desc: "List all nodes" },
    MenuItem { cmd: "backups", desc: "Backup system" },
    MenuItem { cmd: "restore", desc: "Restore backup" },
    MenuItem { cmd: "tokens", desc: "List tokens" },
    MenuItem { cmd: "nodequeue", desc: "Queue node cmd" },
];

pub fn format_success(msg: &str) -> String {
    format!("\x1b[38;5;{}m[✓] {}\n\r", CURRENT_THEME.success, msg)
}

pub fn format_error(msg: &str) -> String {
    format!("\x1b[38;5;{}m[X] {}\n\r", CURRENT_THEME.error, msg)
}

pub fn format_warning(msg: &str) -> String {
    format!("\x1b[38;5;{}m[!] {}\n\r", CURRENT_THEME.warning, msg)
}

pub fn format_info(msg: &str) -> String {
    format!("\x1b[38;5;{}m[*] {}\n\r", CURRENT_THEME.info, msg)
}
