use tokio::net::TcpStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt, BufReader, AsyncBufReadExt};
use tokio::sync::Mutex;
use std::sync::Arc;
use std::collections::HashMap;
use super::auth::{User, Level};
use super::error::{CncError, Result};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use tokio_rustls::server::TlsStream;

pub enum Connection {
    Plain(BufReader<TcpStream>),
    Tls(BufReader<TlsStream<TcpStream>>),
}

impl Connection {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Connection::Plain(stream) => stream.write_all(data).await,
            Connection::Tls(stream) => stream.write_all(data).await,
        }
    }
    
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Connection::Plain(stream) => stream.read(buf).await,
            Connection::Tls(stream) => stream.read(buf).await,
        }
    }

    async fn read_line_limited(&mut self, line: &mut String, limit: usize) -> std::io::Result<usize> {
        match self {
            Connection::Plain(stream) => read_line_safe(stream, line, limit).await,
            Connection::Tls(stream) => read_line_safe(stream, line, limit).await,
        }
    }
}

async fn read_line_safe<R: AsyncBufReadExt + Unpin>(reader: &mut R, line: &mut String, limit: usize) -> std::io::Result<usize> {
    let mut total_read = 0;
    loop {
        let available = reader.fill_buf().await?;
        let len = available.len();
        if len == 0 {
            return Ok(total_read);
        }
        
        let (found_newline, bytes_to_consume) = match available.iter().position(|&b| b == b'\n') {
            Some(pos) => (true, pos + 1),
            None => (false, len),
        };
        
        if line.len() + bytes_to_consume > limit {
             return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Line too long"));
        }
        
        line.push_str(&String::from_utf8_lossy(&available[..bytes_to_consume]));
        reader.consume(bytes_to_consume);
        total_read += bytes_to_consume;
        
        if found_newline {
            return Ok(total_read);
        }
    }
}

pub struct Client {
    pub id: Uuid,
    pub conn: Arc<Mutex<Connection>>,
    pub user: User,
    pub address: String,
    #[allow(dead_code)]
    pub connected_at: DateTime<Utc>,
    pub last_activity: Arc<Mutex<DateTime<Utc>>>,
    pub breadcrumb: Arc<Mutex<String>>,
}

impl Client {
    pub fn new(conn: BufReader<TcpStream>, user: User) -> Result<Self> {
        let address = conn.get_ref().peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        
        Ok(Self {
            id: Uuid::new_v4(),
            conn: Arc::new(Mutex::new(Connection::Plain(conn))),
            user,
            address,
            connected_at: Utc::now(),
            last_activity: Arc::new(Mutex::new(Utc::now())),
            breadcrumb: Arc::new(Mutex::new("Home".to_string())),
        })
    }
    
    pub fn new_from_tls(conn: BufReader<TlsStream<TcpStream>>, user: User) -> Result<Self> {
        let address = conn.get_ref().get_ref().0.peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        
        Ok(Self {
            id: Uuid::new_v4(),
            conn: Arc::new(Mutex::new(Connection::Tls(conn))),
            user,
            address,
            connected_at: Utc::now(),
            last_activity: Arc::new(Mutex::new(Utc::now())),
            breadcrumb: Arc::new(Mutex::new("Home".to_string())),
        })
    }
    
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        let mut conn = self.conn.lock().await;
        conn.write_all(data).await?;
        self.update_activity().await;
        Ok(())
    }
    
    /// Try to write data without blocking if the connection is busy (e.g. reading input)
    pub async fn try_write(&self, data: &[u8]) -> Result<bool> {
        let mut conn = match self.conn.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Ok(false),
        };
        conn.write_all(data).await?;
        // Don't update activity for background updates like titles
        Ok(true)
    }

    pub async fn read_line(&self) -> Result<String> {
        let mut conn = self.conn.lock().await;
        let mut line = String::new();
        
        // Limit max line length to prevent memory exhaustion (e.g. 4KB)
        const MAX_LINE_LENGTH: usize = 4096;
        
        match conn.read_line_limited(&mut line, MAX_LINE_LENGTH).await {
            Ok(0) => return Err(CncError::ConnectionClosed),
            Ok(_) => {
                self.update_activity().await;
                Ok(line)
            },
            Err(e) => Err(CncError::IoError(e)),
        }
    }
    
    async fn update_activity(&self) {
        let mut last_activity = self.last_activity.lock().await;
        *last_activity = Utc::now();
    }
    
    pub async fn set_breadcrumb(&self, breadcrumb: &str) {
        let mut bc = self.breadcrumb.lock().await;
        *bc = breadcrumb.to_string();
    }
    
    pub async fn get_breadcrumb(&self) -> String {
        let bc = self.breadcrumb.lock().await;
        bc.clone()
    }
    
    pub fn has_permission(&self, required: Level) -> bool {
        self.user.get_level() >= required
    }
}

pub struct ClientManager {
    clients: Arc<Mutex<HashMap<Uuid, Arc<Client>>>>,
    max_connections: usize,
}

impl ClientManager {
    pub fn new(max_connections: usize) -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            max_connections,
        }
    }
    
    pub async fn add_client(&self, client: Client) -> Result<Arc<Client>> {
        let mut clients = self.clients.lock().await;
        
        if clients.len() >= self.max_connections {
            return Err(CncError::ResourceLimitExceeded(
                "Maximum user connections reached".to_string()
            ));
        }
        
        let client = Arc::new(client);
        clients.insert(client.id, client.clone());
        
        Ok(client)
    }
    
    pub async fn remove_client(&self, id: &Uuid) {
        let mut clients = self.clients.lock().await;
        clients.remove(id);
    }
    
    pub async fn get_all_clients(&self) -> Vec<Arc<Client>> {
        let clients = self.clients.lock().await;
        clients.values().cloned().collect()
    }
    
    pub async fn get_client_count(&self) -> usize {
        let clients = self.clients.lock().await;
        clients.len()
    }
    
    pub async fn cleanup_inactive(&self, timeout_secs: u64) {
        let mut clients = self.clients.lock().await;
        let now = Utc::now();
        let mut to_remove = Vec::new();
        
        for (id, client) in clients.iter() {
            let last_activity = *client.last_activity.lock().await;
            if (now - last_activity).num_seconds() > timeout_secs as i64 {
                to_remove.push(*id);
            }
        }
        
        for id in to_remove {
            clients.remove(&id);
        }
    }
}
