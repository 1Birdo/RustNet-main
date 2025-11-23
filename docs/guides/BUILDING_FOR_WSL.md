# Building RustNet for WSL and Linux

## Quick Answer: Yes!

You can build RustNet for WSL/Linux from Windows in several ways:

### Option 1: Build Inside WSL (Recommended)
```bash
# In WSL terminal
cd /mnt/t/RustNet-main

# Build server
cd server
cargo build --release

# Build client
cd ../client
cargo build --release

# Binaries will be at:
# - server/target/release/rustnet-server
# - client/target/release/rustnet-client
```

### Option 2: Cross-Compile from Windows
```powershell
# Install cross-compilation target
rustup target add x86_64-unknown-linux-gnu

# Build for Linux from Windows
cd t:\RustNet-main

# Server
cd server
cargo build --release --target x86_64-unknown-linux-gnu

# Client
cd ..\client
cargo build --release --target x86_64-unknown-linux-gnu

# Binaries at: target/x86_64-unknown-linux-gnu/release/
```

### Option 3: Use Cross Tool (Best for Multiple Targets)
```powershell
# Install cross (one-time setup)
cargo install cross

# Build for Linux
cd t:\RustNet-main

# Server
cd server
cross build --release --target x86_64-unknown-linux-gnu

# Client
cd ..\client
cross build --release --target x86_64-unknown-linux-gnu
```

## Detailed Setup Guide

### Prerequisites

#### For WSL
1. **Install WSL** (if not already):
   ```powershell
   # In PowerShell (Admin)
   wsl --install
   ```

2. **Install Rust in WSL**:
   ```bash
   # In WSL terminal
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

3. **Install Build Dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install build-essential pkg-config libssl-dev

   # Arch Linux
   sudo pacman -S base-devel openssl
   ```

#### For Cross-Compilation (Windows)
1. **Add Linux Target**:
   ```powershell
   rustup target add x86_64-unknown-linux-gnu
   rustup target add x86_64-unknown-linux-musl  # For static binaries
   ```

2. **Install Linker** (for native cross-compilation):
   - Download and install [MinGW-w64](https://www.mingw-w64.org/)
   - OR use `cross` tool (easier)

### Building Strategies

#### Strategy 1: Native WSL Build (Simplest)
```bash
# Access Windows files from WSL
cd /mnt/t/RustNet-main

# Build everything
cargo build --release --workspace

# Test
cd server
cargo test

# Run
./target/release/rustnet-server
```

**Advantages:**
- ✅ Native Linux build, no cross-compilation issues
- ✅ All dependencies work out of the box
- ✅ Can run and test immediately
- ✅ Full development environment

**Disadvantages:**
- ❌ Requires WSL installed
- ❌ Need to install Rust and dependencies in WSL

#### Strategy 2: Windows Cross-Compile
```powershell
# One-time: Add target
rustup target add x86_64-unknown-linux-gnu

# Build
cd t:\RustNet-main
cargo build --release --workspace --target x86_64-unknown-linux-gnu

# Binaries at:
# target/x86_64-unknown-linux-gnu/release/rustnet-server
# target/x86_64-unknown-linux-gnu/release/rustnet-client
```

**Advantages:**
- ✅ Build from Windows environment
- ✅ No WSL required
- ✅ Faster if you already have Windows setup

**Disadvantages:**
- ❌ May have linker issues with some dependencies
- ❌ Cannot run/test Linux binaries on Windows
- ❌ Some dependencies might not cross-compile easily

#### Strategy 3: Cross Tool (Best of Both)
```powershell
# One-time setup
cargo install cross

# Build for multiple targets easily
cd t:\RustNet-main\server
cross build --release --target x86_64-unknown-linux-gnu
cross build --release --target x86_64-unknown-linux-musl  # Static binary

cd ..\client
cross build --release --target x86_64-unknown-linux-gnu
```

**Advantages:**
- ✅ Handles all cross-compilation complexity
- ✅ Uses Docker containers for consistent builds
- ✅ Works for many targets (ARM, MUSL, etc.)
- ✅ No linker configuration needed

**Disadvantages:**
- ❌ Requires Docker Desktop
- ❌ Slower first build (downloads containers)
- ❌ Larger disk space usage

## Supported Targets

### Linux Targets
```powershell
# x86_64 (most common)
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-musl  # Static linking

# ARM64 (Raspberry Pi, AWS Graviton, etc.)
rustup target add aarch64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-musl

# ARM v7 (Older Raspberry Pi)
rustup target add armv7-unknown-linux-gnueabihf

# i686 (32-bit)
rustup target add i686-unknown-linux-gnu
```

### Build Commands for Each Target
```powershell
# Standard Linux (glibc)
cargo build --release --target x86_64-unknown-linux-gnu

# Static Linux (MUSL - no external dependencies)
cargo build --release --target x86_64-unknown-linux-musl

# ARM64 Linux
cargo build --release --target aarch64-unknown-linux-gnu

# Raspberry Pi (ARM v7)
cargo build --release --target armv7-unknown-linux-gnueabihf
```

## Complete WSL Workflow

### Initial Setup (One Time)
```bash
# 1. Start WSL
wsl

# 2. Navigate to project
cd /mnt/t/RustNet-main

# 3. Install Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 4. Install dependencies
sudo apt update
sudo apt install build-essential pkg-config libssl-dev

# 5. Verify installation
rustc --version
cargo --version
```

### Daily Development
```bash
# Start WSL
wsl

# Navigate to project
cd /mnt/t/RustNet-main

# Build server
cd server
cargo build --release

# Build client
cd ../client
cargo build --release

# Run server
cd ../server
./target/release/rustnet-server

# In another WSL terminal, test connection
nc localhost 420
```

### Testing in WSL
```bash
cd /mnt/t/RustNet-main/server

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run

# Check for issues
cargo check
cargo clippy
```

## Static Binaries (Portable Linux)

For maximum portability, build with MUSL (no external library dependencies):

```powershell
# Add MUSL target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cd t:\RustNet-main\server
cargo build --release --target x86_64-unknown-linux-musl

# Binary will be fully static - works on any Linux
```

**Benefits of MUSL:**
- ✅ Single binary with no dependencies
- ✅ Works on any Linux distro
- ✅ No need to install OpenSSL or other libs
- ✅ Perfect for containers/Docker

## Troubleshooting

### Issue: "linker 'cc' not found" (Windows cross-compile)
**Solution:** Use `cross` tool instead:
```powershell
cargo install cross
cross build --release --target x86_64-unknown-linux-gnu
```

### Issue: OpenSSL errors during cross-compilation
**Solution:** Switch to MUSL target with vendored OpenSSL:
```powershell
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### Issue: Cannot access Windows files from WSL
**Solution:** Use `/mnt/` prefix:
```bash
# Windows: T:\RustNet-main
# WSL:     /mnt/t/RustNet-main
cd /mnt/t/RustNet-main
```

### Issue: Permission denied when running binary
**Solution:** Add execute permission:
```bash
chmod +x target/release/rustnet-server
chmod +x target/release/rustnet-client
```

### Issue: "cross" requires Docker
**Solution:** Install Docker Desktop for Windows:
1. Download from [docker.com](https://www.docker.com/products/docker-desktop)
2. Enable WSL 2 integration in Docker settings
3. Restart and try `cross` again

## Performance Comparison

| Build Method | Build Time | Binary Size | Portability | Complexity |
|--------------|------------|-------------|-------------|------------|
| WSL Native | Fast | ~8MB | WSL only | Low |
| Windows Cross (GNU) | Medium | ~8MB | Most Linux | Medium |
| Windows Cross (MUSL) | Slow | ~10MB | All Linux | Medium |
| Cross Tool | Slow (first) | ~8MB | Target-specific | Low |

## Recommended Approach

### For Development
**Use WSL Native Build:**
```bash
# In WSL
cd /mnt/t/RustNet-main
cargo build --release --workspace
```
- Fastest development cycle
- Can test immediately
- Full debugging support

### For Distribution
**Use Cross Tool with MUSL:**
```powershell
# In Windows
cargo install cross
cd t:\RustNet-main

# Build static binaries
cross build --release --target x86_64-unknown-linux-musl -p rustnet-server
cross build --release --target x86_64-unknown-linux-musl -p rustnet-client
```
- Single binary, no dependencies
- Works on any Linux distro
- Professional distribution

## Deployment to Linux Server

### From Windows to Linux Server
```powershell
# Build for Linux
cd t:\RustNet-main
cargo build --release --target x86_64-unknown-linux-gnu

# Copy to server (SCP)
scp target/x86_64-unknown-linux-gnu/release/rustnet-server user@server:/opt/rustnet/
scp -r server/config user@server:/opt/rustnet/

# SSH to server and run
ssh user@server
cd /opt/rustnet
chmod +x rustnet-server
./rustnet-server
```

### From WSL to Linux Server
```bash
# Build in WSL
cd /mnt/t/RustNet-main/server
cargo build --release

# Copy to server
scp target/release/rustnet-server user@server:/opt/rustnet/
scp -r config user@server:/opt/rustnet/
```

## Summary

✅ **Yes, you can build for WSL!** Three main options:

1. **WSL Native** (Recommended for development)
   - Easiest, fastest, full features
   - Build and test in same environment

2. **Windows Cross-Compile** (Good for distribution)
   - Build from Windows, run on Linux
   - Requires target installation

3. **Cross Tool** (Best for multiple targets)
   - Professional solution
   - Handles all complexity
   - Requires Docker

Choose based on your needs:
- **Daily development**: WSL native
- **Single Linux target**: Windows cross-compile
- **Multiple targets/production**: Cross tool

---

**Quick Start for WSL:**
```bash
wsl
cd /mnt/t/RustNet-main
cargo build --release --workspace
./server/target/release/rustnet-server
```

That's it! 🚀
