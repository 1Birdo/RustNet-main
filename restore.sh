#!/bin/bash
# RustNet Restore Script
# Restore from a backup archive

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <backup_file.tar.gz>"
    echo ""
    echo "Available backups:"
    ls -lh "${BACKUP_DIR:-$HOME/rustnet-backups}"/rustnet_backup_*.tar.gz 2>/dev/null || echo "  No backups found"
    exit 1
fi

BACKUP_FILE="$1"
RUSTNET_DIR="${RUSTNET_DIR:-/opt/rustnet/server}"
TEMP_DIR="/tmp/rustnet_restore_$$"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "⚠️  WARNING: This will overwrite existing configuration!"
echo "Backup file: $BACKUP_FILE"
echo "Target directory: $RUSTNET_DIR"
echo ""
read -p "Continue? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Restore cancelled"
    exit 0
fi

echo "🔄 Starting restore..."

# Extract backup
mkdir -p "$TEMP_DIR"
tar -xzf "$BACKUP_FILE" -C "$TEMP_DIR"

# Find the extracted directory
BACKUP_CONTENT=$(ls -1 "$TEMP_DIR" | head -1)

# Restore files
if [ -f "$TEMP_DIR/$BACKUP_CONTENT/users.json" ]; then
    mkdir -p "$RUSTNET_DIR/config"
    cp "$TEMP_DIR/$BACKUP_CONTENT/users.json" "$RUSTNET_DIR/config/"
    echo "✓ Restored users.json"
fi

if [ -f "$TEMP_DIR/$BACKUP_CONTENT/server.toml" ]; then
    cp "$TEMP_DIR/$BACKUP_CONTENT/server.toml" "$RUSTNET_DIR/config/"
    echo "✓ Restored server.toml"
fi

if [ -f "$TEMP_DIR/$BACKUP_CONTENT/config.json" ]; then
    cp "$TEMP_DIR/$BACKUP_CONTENT/config.json" "$RUSTNET_DIR/"
    echo "✓ Restored config.json"
fi

if [ -f "$TEMP_DIR/$BACKUP_CONTENT/cert.pem" ]; then
    cp "$TEMP_DIR/$BACKUP_CONTENT/cert.pem" "$RUSTNET_DIR/"
    echo "✓ Restored cert.pem"
fi

if [ -f "$TEMP_DIR/$BACKUP_CONTENT/key.pem" ]; then
    cp "$TEMP_DIR/$BACKUP_CONTENT/key.pem" "$RUSTNET_DIR/"
    echo "✓ Restored key.pem"
fi

if [ -f "$TEMP_DIR/$BACKUP_CONTENT/attack_history.json" ]; then
    cp "$TEMP_DIR/$BACKUP_CONTENT/attack_history.json" "$RUSTNET_DIR/config/"
    echo "✓ Restored attack_history.json"
fi

if [ -f "$TEMP_DIR/$BACKUP_CONTENT/audit.log" ]; then
    cp "$TEMP_DIR/$BACKUP_CONTENT/audit.log" "$RUSTNET_DIR/config/"
    echo "✓ Restored audit.log"
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo "✅ Restore complete!"
echo "⚠️  Remember to restart the server: systemctl restart rustnet"
