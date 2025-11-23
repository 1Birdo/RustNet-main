# RustNet - C&C Framework

A lightweight, secure Command & Control (C&C) framework built in Rust for managing bot networks. Designed for private, small-scale deployments (5-20 users).

## 🚀 Quick Start

### Prerequisites
- **Rust 1.70+** with Cargo installed
- **TLS Certificates** (self-signed or from Let's Encrypt)
- **Port Access**: 1420 (users), 7002 (bots)

### Build & Run

```bash
# Build the server
cd server
cargo build --release

# Run with default config
./target/release/rustnet-server

# Or with custom config
./target/release/rustnet-server --config /path/to/config.toml
```

### First-Time Setup

1. **Generate TLS Certificates** (if needed):
   ```bash
   # Self-signed certificate (development/testing)
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
   ```

2. **Configure Server** - Edit `server/config/server.toml`:
   ```toml
   [server]
   user_port = 1420         # Port for user connections
   bot_port = 7002          # Port for bot connections
   enable_tls = true        # ALWAYS use TLS in production
   cert_path = "cert.pem"
   key_path = "key.pem"
   
   [limits]
   max_bots = 1000
   session_timeout_secs = 1800  # 30 minutes
   ```

3. **Default Credentials**:
   - Username: `admin`
   - Password: `changeme`
   - **⚠️ CHANGE IMMEDIATELY** using `changepass` command

4. **Connect to Server**:
   ```bash
   # Using netcat/telnet
   nc localhost 1420
   
   # Or with TLS
   openssl s_client -connect localhost:1420
   ```

5. **Setup Bot Client**:
   ```bash
   # On server, register a bot and get token
   !regbot x86_64
   
   # On bot machine:
   cd client
   
   # Configure C2 server address (pick one method):
   
   # Method A: Using config file (recommended)
   cp c2_address.txt.example c2_address.txt
   # Edit c2_address.txt and set your C2 server IP:PORT
   
   # Method B: Using environment variable
   export C2_ADDRESS="YOUR_SERVER_IP:7002"
   
   # Configure bot token (copy from server output):
   
   # Method A: Using file (recommended)
   echo "YOUR_TOKEN_HERE" > bot_token.txt
   
   # Method B: Using environment variable
   export BOT_AUTH_TOKEN="YOUR_TOKEN_HERE"
   
   # Build and run
   cargo build --release
   ./target/release/rustnet-client
   ```

## 📋 User Commands

### Attack Management
- `attack <ip> <port> <duration> <method>` - Launch DDoS attack
  
  **Fully Implemented Methods:**
  - `!udpflood` - Basic UDP packet flood
  - `!udpsmart` - Smart UDP flood with randomized payloads
  - `!tcpflood` - TCP connection flood
  - `!dns` - DNS query flood
  - `!http` - HTTP POST flood
  
  **Advanced Methods (High Impact):**
  - `!slowloris` - Slow HTTP headers attack (connection exhaustion)
  - `!sslflood` - TLS/SSL handshake flood (CPU intensive for target)
  - `!websocket` - WebSocket connection and message flood
  - `!amplification` - DNS amplification attack (traffic multiplier)
  - `!connection` - Connection exhaustion attack (hold connections open)
  
  **Limited Support (Requires Raw Sockets):**
  - `!synflood` - SYN flood (fallback to TCP)
  - `!ackflood` - ACK flood (fallback to TCP)
  - `!greflood` - GRE flood (fallback to TCP)
  - `!icmpflood` - ICMP/Ping flood (fallback to UDP)
  
  **Example**: `!slowloris 203.0.113.50 80 60`
  
  **⚠️ Note**: Private IPs (192.168.*, 10.*, 127.*, etc.) are blocked

- `stop <attack_id>` - Stop an active attack
- `attacks` - List all running attacks
- `status` - Show attack statistics

### Bot Management
- `bots` - List connected bots (count and details)
- `ping` - Check server responsiveness

### User Management (Owner/Admin Only)
- `adduser <username> <password> <role>` - Create new user
  - **Roles**: `basic`, `pro`, `admin`, `owner`
  - **Example**: `adduser alice secure123 pro`
  - **Owner only**: Can create any role

- `deluser <username>` - Delete user (Owner only)
  - **⚠️ Cannot delete last user**

- `changepass <old_password> <new_password>` - Change your password

- `listusers` - Show all users with roles and metadata

### System
- `dashboard` / `dash` - Real-time server dashboard with live stats
- `health` - Server uptime and status
- `help` - Display command list
- `clear` - Clear screen
- `exit` / `quit` - Disconnect from server

## 🔐 Security Best Practices

### For Server Administrators

1. **Always Use TLS**
   - TLS is enabled by default
   - Use valid certificates (Let's Encrypt recommended)
   - Never disable TLS in production

2. **Strong Passwords**
   - Minimum 8 characters
   - Use unique passwords for each user
   - Change default credentials immediately

3. **User Roles** (Least Privilege)
   - `basic` - View-only access (bots, attacks, status)
   - `pro` - Can launch attacks (most family/friends)
   - `admin` - Can manage users (trusted members)
   - `owner` - Full control (you only)

4. **Rate Limiting** (Automatic)
   - 10 connections per minute per IP
   - Prevents brute-force and DoS attacks
   - No configuration needed

5. **Network Security**
   - Run behind firewall
   - Use port forwarding carefully
   - Consider VPN for remote access

6. **Monitoring**
   - Check logs regularly: `RUST_LOG=info ./cnc`
   - Review `listusers` for suspicious accounts
   - Monitor `attacks` for unauthorized usage

### For Users

1. **Responsible Usage**
   - Only target systems you own or have permission to test
   - Attacks on private IPs are blocked by design
   - Follow local laws and regulations

2. **Attack Method Selection**
   - **Basic Volume Attacks:**
     - `!udpflood` / `!udpsmart` - UDP volume attacks (best for bandwidth saturation)
     - `!tcpflood` - TCP connection exhaustion
   
   - **Application Layer Attacks (Most Effective):**
     - `!http` - HTTP POST application layer stress
     - `!slowloris` - **NEW** - Keeps connections open with slow headers (highly effective against web servers)
     - `!websocket` - **NEW** - WebSocket connection flood (targets real-time applications)
   
   - **Protocol-Specific Attacks:**
     - `!dns` - DNS query flooding
     - `!sslflood` - **NEW** - TLS handshake flood (CPU intensive, effective against HTTPS servers)
     - `!amplification` - **NEW** - DNS amplification (10-100x traffic multiplier)
   
   - **Connection Exhaustion:**
     - `!connection` - **NEW** - Opens and holds maximum connections (exhausts server connection pools)
   
   - **Raw Socket Methods** (require elevated privileges):
     - `!synflood` / `!ackflood` / `!greflood` / `!icmpflood` - Fallback to safe alternatives

3. **Duration Guidelines**
   - Start with short tests (10-30 seconds)
   - Maximum 3600 seconds (1 hour)
   - Use `!stop <id>` to cancel early

4. **Attack Limits by User Level**
   - **Basic**: 1 concurrent attack, 2 minute cooldown
   - **Pro**: 3 concurrent attacks, 1 minute cooldown
   - **Admin**: 5 concurrent attacks, 30 second cooldown
   - **Owner**: 10 concurrent attacks, no cooldown

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         RustNet C&C Server              │
│  ┌─────────────────────────────────┐   │
│  │   User Port (420 - TLS)         │   │
│  │   - Authentication (Argon2)     │   │
│  │   - RBAC (4 roles)              │   │
│  │   - Rate Limiting (10/min)      │   │
│  └─────────────────────────────────┘   │
│  ┌─────────────────────────────────┐   │
│  │   Bot Port (7002)               │   │
│  │   - Bot Registration            │   │
│  │   - Heartbeat (PING/PONG)       │   │
│  │   - Command Relay               │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │   Core Modules                  │   │
│  │   - Attack Manager              │   │
│  │   - Client Manager              │   │
│  │   - Bot Manager                 │   │
│  │   - Session Cleanup (30s)       │   │
│  └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
              │         │
              │         │
        ┌─────┴─┐   ┌──┴──────┐
        │ Users │   │  Bots   │
        └───────┘   └─────────┘
```

## 🛠️ Configuration Reference

### config/server.toml
```toml
[server]
user_port = 1420             # User connection port
bot_port = 7002              # Bot connection port
enable_tls = true            # Enable TLS encryption
cert_path = "cert.pem"       # TLS certificate path
key_path = "key.pem"         # TLS private key path
deployment_mode = "local"    # "local" or "public"

[limits]
max_bots = 1000              # Maximum bot connections
session_timeout_secs = 1800  # User session timeout (30 min)

# NOTE: Attack limits are hardcoded per user level:
# - Basic: 1 attack, 120s cooldown
# - Pro: 3 attacks, 60s cooldown
# - Admin: 5 attacks, 30s cooldown
# - Owner: 10 attacks, no cooldown
# Max attack duration: 3600s (1 hour)
```

### client/c2_address.txt (Bot Configuration)
```
# C2 server IP:PORT
YOUR_SERVER_IP:7002
```

Alternatively, use environment variable:
```bash
export C2_ADDRESS="YOUR_SERVER_IP:7002"
```

### users.json (Auto-generated)
```json
{
  "users": {
    "admin": {
      "password_hash": "$argon2id$v=19$...",
      "role": "owner",
      "max_concurrent_attacks": 10,
      "max_attack_duration": 3600,
      "created_at": "2024-01-15T10:30:00Z",
      "last_login": "2024-01-16T14:22:00Z"
    }
  }
}
```

## 📊 Deployment Checklist

### Pre-Deployment
- [ ] Build release binary: `cargo build --release`
- [ ] Generate TLS certificates (self-signed or Let's Encrypt)
- [ ] Configure `config/server.toml` (ports, TLS paths)
- [ ] Change default admin password
- [ ] Register bot tokens: `!regbot <arch>`
- [ ] Test connection: `nc localhost 1420`
- [ ] Verify TLS: `openssl s_client -connect localhost:1420`

### Post-Deployment
- [ ] Create user accounts for family/friends
- [ ] Distribute bot tokens to bot machines (via bot_token.txt or env var)
- [ ] Share connection instructions (IP, port, credentials)
- [ ] Test attack commands with short durations
- [ ] Monitor logs for errors: `RUST_LOG=info ./rustnet-server`
- [ ] Schedule regular backups of `config/users.json`

### Firewall Rules (Example)
```bash
# Allow user connections (port 1420)
sudo ufw allow 1420/tcp

# Allow bot connections (port 7002)
sudo ufw allow 7002/tcp

# Enable firewall
sudo ufw enable
```

## 🐛 Troubleshooting

### Connection Issues
**Problem**: "Connection refused" error
- **Solution**: Check if server is running: `ps aux | grep rustnet-server`
- **Solution**: Verify port is open: `netstat -an | grep 1420`
- **Solution**: Check firewall rules: `sudo ufw status`

**Problem**: "TLS handshake failed"
- **Solution**: Verify certificate paths in config/server.toml
- **Solution**: Check certificate expiry: `openssl x509 -in cert.pem -noout -dates`
- **Solution**: Use correct connection method (openssl s_client vs plain nc)

**Problem**: "Bot authentication failed"
- **Solution**: Verify bot token matches registered token from `!regbot`
- **Solution**: Check bot_token.txt file or BOT_AUTH_TOKEN environment variable
- **Solution**: Ensure token has no extra whitespace or newlines

### Authentication Issues
**Problem**: "Rate limit exceeded"
- **Solution**: Wait 1 minute between connection attempts
- **Solution**: Check if IP is correct (not behind NAT/proxy)

**Problem**: "Authentication failed" repeatedly
- **Solution**: Verify username/password (case-sensitive)
- **Solution**: Check users.json for account existence
- **Solution**: Use `changepass` if forgotten password (requires old password)

### Attack Issues
**Problem**: "Invalid IP address" for local network
- **Solution**: Private IPs are blocked by design (security feature)
- **Solution**: Only target public IPs you own/control

**Problem**: "Invalid attack method"
- **Solution**: Use only whitelisted methods (see Attack Management)
- **Solution**: Check for typos: `tcp-flood` not `tcpflood`

### Performance Issues
**Problem**: High CPU usage
- **Solution**: Check active attack count: `attacks` command
- **Solution**: Reduce concurrent attacks per user (config: max_concurrent_attacks)
- **Solution**: Stop unnecessary attacks: `stop <id>`

**Problem**: Memory leak suspected
- **Solution**: Automatic cleanup runs every 30 seconds (sessions, bots, rate limits)
- **Solution**: Check logs for cleanup errors: `grep cleanup rustnet.log`
- **Solution**: Restart server if necessary (no data loss - users.json persisted)

## 📝 Development

### Build from Source
```bash
# Clone repository
git clone https://github.com/yourusername/RustNet.git
cd RustNet

# Build server
cd server
cargo build --release

# Run tests
cargo test

# Build bot client
cd ../client
cargo build --release

# Run with debug logging
RUST_LOG=debug cargo run
```

### Code Structure
```
RustNet-main/
├── server/              # Main C&C server (Rust)
│   ├── src/
│   │   ├── main.rs      # Entry point, command handlers
│   │   └── modules/
│   │       ├── auth.rs        # Authentication & user management
│   │       ├── validation.rs  # Input validation, IP filtering
│   │       ├── config.rs      # Configuration management
│   │       ├── rate_limiter.rs # IP-based rate limiting
│   │       ├── client_manager.rs # User client management
│   │       ├── bot_manager.rs    # Bot management & tokens
│   │       ├── attack_manager.rs # Attack coordination
│   │       ├── tls.rs            # TLS encryption
│   │       └── error.rs          # Error types & audit logging
│   ├── Cargo.toml
│   └── config/
│       ├── server.toml       # Main configuration
│       └── users.json        # User database (auto-created)
├── client/              # Bot client (Rust)
│   ├── src/
│   │   ├── main.rs              # Bot entry point & C2 protocol
│   │   └── attack_methods.rs   # Attack implementations
│   ├── Cargo.toml
│   ├── bot_token.txt.example    # Token configuration template
│   └── c2_address.txt.example   # C2 server address template
└── docs/
    └── README.md        # This file
```

### Testing
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_validate_ip_address

# Run with output
cargo test -- --nocapture

# Check code coverage (requires cargo-tarpaulin)
cargo tarpaulin --out Html
```

## 🔄 Maintenance

### Regular Tasks
1. **Weekly**: Review user activity (`listusers` command)
2. **Monthly**: Rotate TLS certificates (if using short-lived certs)
3. **Quarterly**: Update dependencies (`cargo update`, check for CVEs)
4. **As Needed**: Backup `users.json` before major changes

### Updating Users
```bash
# Backup users.json
cp cnc/users.json cnc/users.json.backup

# Edit users.json (manual)
vim cnc/users.json

# Restart server to apply
pkill cnc && ./cnc
```

### Log Management
```bash
# Run with logging to file
RUST_LOG=info ./cnc 2>&1 | tee rustnet.log

# Rotate logs (weekly)
mv rustnet.log rustnet.log.$(date +%Y%m%d)
gzip rustnet.log.*

# Clean old logs (keep 30 days)
find . -name "rustnet.log.*" -mtime +30 -delete
```

## 📜 License

[Specify your license here - MIT, GPL, etc.]

## ⚠️ Legal Disclaimer

This software is provided for **educational and authorized testing purposes only**. Users are responsible for ensuring compliance with all applicable laws and regulations. Unauthorized use of this software against systems you do not own or have explicit permission to test is illegal and may result in criminal prosecution.

**The authors are not responsible for any misuse or damage caused by this software.**

## 🤝 Contributing

This is a private project for family/friends deployment. If you'd like to contribute:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Support

For issues or questions:
- Check the **Troubleshooting** section above
- Review logs: `RUST_LOG=debug ./cnc`
- Contact the administrator (that's you!)

---

**Version**: 1.0.0  
**Last Updated**: 2024-01-16  
**Rust Version**: 1.70+  
**Status**: Production-Ready for Small-Scale Deployment
