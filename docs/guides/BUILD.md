# Build Scripts

This directory contains build scripts for compiling RustNet components.

## Server Build

### Development Build
```bash
cd server
cargo build
```

### Release Build (Optimized)
```bash
cd server
cargo build --release
```

Binary output: `server/target/release/rustnet-server` (or `.exe` on Windows)

## Client Build

### Development Build
```bash
cd client
cargo build
```

### Release Build (Optimized)
```bash
cd client
cargo build --release
```

Binary output: `client/target/release/rustnet-client` (or `.exe` on Windows)

## Cross-Compilation

For building the bot client for different architectures:

```bash
# Install cross-compilation tools
cargo install cross

# Build for Linux ARM64
cd client
cross build --release --target aarch64-unknown-linux-gnu

# Build for Linux x86_64
cross build --release --target x86_64-unknown-linux-gnu

# Build for Windows
cross build --release --target x86_64-pc-windows-gnu
```

## Build Optimization

The release builds include:
- Link-time optimization (LTO)
- Code size optimization
- Debug symbols stripped
- Maximum optimization level

This results in smaller, faster binaries suitable for production deployment.

## Build from Workspace Root

```bash
# Build all workspace members
cargo build --release --workspace

# Build specific member
cargo build --release -p rustnet-server
cargo build --release -p rustnet-client
```
