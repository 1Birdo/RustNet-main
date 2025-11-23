#!/bin/bash

# Rust cross-compilation build script for device bot

echo "Building device bot for multiple architectures..."

# Install cross if not already installed
if ! command -v cross &> /dev/null; then
    echo "Installing cross for cross-compilation..."
    cargo install cross
fi

# Array of target architectures
targets=(
    "x86_64-unknown-linux-gnu"
    "i686-unknown-linux-gnu"
    "aarch64-unknown-linux-gnu"
    "armv7-unknown-linux-gnueabihf"
    "arm-unknown-linux-gnueabihf"
    "mips-unknown-linux-gnu"
    "mipsel-unknown-linux-gnu"
)

# Build directory
BUILD_DIR="builds"
mkdir -p "$BUILD_DIR"

cd device || exit

# Build for each target
for target in "${targets[@]}"; do
    echo "Building for $target..."
    cross build --release --target "$target" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        # Copy binary to builds directory with architecture suffix
        cp "target/$target/release/device" "../$BUILD_DIR/device_$target"
        echo "✓ Successfully built for $target"
    else
        echo "✗ Failed to build for $target"
    fi
done

cd ..

echo ""
echo "Build complete! Binaries are in the $BUILD_DIR directory."
ls -lh "$BUILD_DIR"
