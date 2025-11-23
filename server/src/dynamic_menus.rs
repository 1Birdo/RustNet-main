// Dynamic menu rendering with gradients and centered content
use crate::Client;
use crate::Result;
use std::sync::Arc;

pub fn get_terminal_width() -> usize {
    95 // Fixed for network terminals
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
    let colors = [195, 159, 123, 87, 51, 45, 39];
    let len = text.chars().count();
    if len == 0 {
        return String::new();
    }
    
    let mut result = String::new();
    for (i, ch) in text.chars().enumerate() {
        let position = (i as f32 / len as f32) * (colors.len() - 1) as f32;
        let index = position.floor() as usize;
        let next_index = (index + 1).min(colors.len() - 1);
        let t = position - index as f32;
        
        let c1 = colors[index];
        let c2 = colors[next_index];
        let color = (c1 as f32 * (1.0 - t) + c2 as f32 * t) as u8;
        
        result.push_str(&format!("\x1b[38;5;{}m{}", color, ch));
    }
    result.push_str("\x1b[0m");
    result
}

pub fn strip_ansi(text: &str) -> String {
    use regex::Regex;
    use std::sync::OnceLock;
    
    static ANSI_REGEX: OnceLock<Regex> = OnceLock::new();
    let ansi_regex = ANSI_REGEX.get_or_init(|| {
        Regex::new(r"\x1b\[[0-9;]*m").unwrap()
    });
    
    ansi_regex.replace_all(text, "").to_string()
}

pub fn visible_len(text: &str) -> usize {
    strip_ansi(text).chars().count()
}

pub fn center_text(text: &str, width: usize) -> String {
    let text_len = visible_len(text);
    if text_len >= width {
        return text.to_string();
    }
    let padding = (width - text_len) / 2;
    format!("{}{}", " ".repeat(padding), text)
}

pub async fn render_centered_table<T>(
    client: &Arc<Client>,
    title: &str,
    title_color_start: u8,
    title_color_end: u8,
    rows: Vec<T>,
    row_renderer: impl Fn(&T, usize) -> String,
) -> Result<()> 
where
    T: Send + Sync,
{
    let width = get_terminal_width();
    
    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╮\r\n", "═".repeat(width - 2)).as_bytes()).await?;
    
    // Title with gradient
    let title_gradient = apply_ice_gradient(title);
    let title_text = format!("§ {} §", title_gradient);
    let padding_total = width - visible_len(&format!("§ {} §", title)) - 4;
    let left_pad = padding_total / 2;
    let right_pad = padding_total - left_pad;
    client.write(format!("\x1b[38;5;240m║{}{}{}║\r\n", 
        " ".repeat(left_pad),
        title_text,
        " ".repeat(right_pad)).as_bytes()).await?;
    
    // Separator
    client.write(format!("\x1b[38;5;240m╠{}╣\r\n", "═".repeat(width - 2)).as_bytes()).await?;
    
    // Rows
    for (idx, row) in rows.iter().enumerate() {
        let row_content = row_renderer(row, idx);
        client.write(row_content.as_bytes()).await?;
    }
    
    // Footer
    client.write(format!("\x1b[38;5;240m╰{}╯\r\n", "═".repeat(width - 2)).as_bytes()).await?;
    
    Ok(())
}

pub async fn render_dual_panel_menu(
    client: &Arc<Client>,
    title: &str,
    title_color: u8,
    left_header: &str,
    right_header: &str,
    left_items: Vec<String>,
    right_items: Vec<String>,
    side_panel: Vec<String>,
) -> Result<()> {
    let width = get_terminal_width();
    let side_width = 30;
    let main_width = width - side_width - 2;
    
    // Top border
    client.write(format!("\x1b[38;5;240m╭{}╦{}╮\r\n", 
        "═".repeat(main_width - 1),
        "═".repeat(side_width)).as_bytes()).await?;
    
    // Title
    let title_gradient = apply_ice_gradient(title);
    let title_line = format!("§ {} §", title_gradient);
    let title_padding = main_width - visible_len(&format!("§ {} §", title)) - 2;
    let left_pad = title_padding / 2;
    let right_pad = title_padding - left_pad;
    
    client.write(format!("\x1b[38;5;240m║{}{}{}║ {} ║\r\n",
        " ".repeat(left_pad),
        title_line,
        " ".repeat(right_pad),
        " ".repeat(side_width - 2)).as_bytes()).await?;
    
    // Column headers
    let left_color = apply_ice_gradient(left_header);
    let right_color = apply_ice_gradient(right_header);
    
    // Calculate column widths based on main_width
    let left_col_width = 37;
    let right_col_width = main_width - 1 - left_col_width;
    
    client.write(format!("\x1b[38;5;240m╠{}╦{}╢  │    │    │    │    │    │  ║\r\n",
        "═".repeat(left_col_width),
        "═".repeat(right_col_width)).as_bytes()).await?;
    
    let left_hdr_pad = if left_col_width > visible_len(left_header) + 2 { left_col_width - visible_len(left_header) - 2 } else { 0 };
    let right_hdr_pad = if right_col_width > visible_len(right_header) + 2 { right_col_width - visible_len(right_header) - 2 } else { 0 };
    
    client.write(format!("\x1b[38;5;240m║  {}{}║  {}{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\r\n",
        left_color,
        " ".repeat(left_hdr_pad),
        right_color,
        " ".repeat(right_hdr_pad)).as_bytes()).await?;
    
    client.write(format!("\x1b[38;5;240m╠{}╬{}╬{}╣\r\n",
        "═".repeat(left_col_width),
        "═".repeat(right_col_width),
        "═".repeat(side_width)).as_bytes()).await?;
    
    // Render rows
    let max_rows = left_items.len().max(right_items.len()).max(side_panel.len());
    for i in 0..max_rows {
        let left = left_items.get(i).map(|s| s.as_str()).unwrap_or("");
        let right = right_items.get(i).map(|s| s.as_str()).unwrap_or("");
        let side = side_panel.get(i).map(|s| s.as_str()).unwrap_or("");
        
        let left_pad = if visible_len(left) < left_col_width - 2 { left_col_width - 2 - visible_len(left) } else { 0 };
        let right_pad = if visible_len(right) < right_col_width - 2 { right_col_width - 2 - visible_len(right) } else { 0 };
        let side_pad = if visible_len(side) < side_width - 2 { side_width - 2 - visible_len(side) } else { 0 };
        
        client.write(format!("\x1b[38;5;240m║ {}{} ║ {}{} ║ {} ║\r\n",
            left, " ".repeat(left_pad),
            right, " ".repeat(right_pad),
            if side.is_empty() { " ".repeat(side_width - 2) } else { format!("{}{}", side, " ".repeat(side_pad)) }
        ).as_bytes()).await?;
    }
    
    // Footer
    client.write(format!("\x1b[38;5;240m╰{}╩{}╯\r\n",
        "═".repeat(main_width - 1),
        "═".repeat(side_width)).as_bytes()).await?;
    
    Ok(())
}
