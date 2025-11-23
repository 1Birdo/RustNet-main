#!/bin/bash
# RustNet Backup Script
# Run this script regularly to backup critical configuration and data

set -e

BACKUP_DIR="${BACKUP_DIR:-$HOME/rustnet-backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="rustnet_backup_${TIMESTAMP}"
RUSTNET_DIR="${RUSTNET_DIR:-/opt/rustnet/server}"

echo "🔄 Starting RustNet backup..."
echo "Backup directory: $BACKUP_DIR"
echo "RustNet directory: $RUSTNET_DIR"

# Create backup directory
mkdir -p "$BACKUP_DIR/$BACKUP_NAME"

# Backup users database
if [ -f "$RUSTNET_DIR/config/users.json" ]; then
    cp "$RUSTNET_DIR/config/users.json" "$BACKUP_DIR/$BACKUP_NAME/"
    echo "✓ Backed up users.json"
else
    echo "⚠ users.json not found"
fi

# Backup server configuration
if [ -f "$RUSTNET_DIR/config/server.toml" ]; then
    cp "$RUSTNET_DIR/config/server.toml" "$BACKUP_DIR/$BACKUP_NAME/"
    echo "✓ Backed up server.toml"
elif [ -f "$RUSTNET_DIR/config.json" ]; then
    cp "$RUSTNET_DIR/config.json" "$BACKUP_DIR/$BACKUP_NAME/"
    echo "✓ Backed up config.json"
fi

# Backup TLS certificates
if [ -f "$RUSTNET_DIR/cert.pem" ]; then
    cp "$RUSTNET_DIR/cert.pem" "$BACKUP_DIR/$BACKUP_NAME/"
    echo "✓ Backed up cert.pem"
fi

if [ -f "$RUSTNET_DIR/key.pem" ]; then
    cp "$RUSTNET_DIR/key.pem" "$BACKUP_DIR/$BACKUP_NAME/"
    echo "✓ Backed up key.pem"
fi

# Backup attack history
if [ -f "$RUSTNET_DIR/config/attack_history.json" ]; then
    cp "$RUSTNET_DIR/config/attack_history.json" "$BACKUP_DIR/$BACKUP_NAME/"
    echo "✓ Backed up attack_history.json"
fi

# Backup audit log
if [ -f "$RUSTNET_DIR/config/audit.log" ]; then
    cp "$RUSTNET_DIR/config/audit.log" "$BACKUP_DIR/$BACKUP_NAME/"
    echo "✓ Backed up audit.log"
fi

# Compress the backup
cd "$BACKUP_DIR"
tar -czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
rm -rf "$BACKUP_NAME"

echo "✅ Backup complete: $BACKUP_DIR/${BACKUP_NAME}.tar.gz"

# Clean up old backups (keep last 30)
BACKUP_COUNT=$(ls -1t "$BACKUP_DIR"/rustnet_backup_*.tar.gz 2>/dev/null | wc -l)
if [ "$BACKUP_COUNT" -gt 30 ]; then
    echo "🧹 Cleaning up old backups..."
    ls -1t "$BACKUP_DIR"/rustnet_backup_*.tar.gz | tail -n +31 | xargs rm -f
    echo "✓ Kept last 30 backups"
fi

echo "📊 Backup statistics:"
ls -lh "$BACKUP_DIR/${BACKUP_NAME}.tar.gz"
echo "Total backups: $(ls -1 $BACKUP_DIR/rustnet_backup_*.tar.gz 2>/dev/null | wc -l)"
