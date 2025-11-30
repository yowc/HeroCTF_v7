#!/bin/bash
# CTF Challenge Startup Script
# Build shellcodes and rusty_pool_party injector
# Serves rusty_pool_party.exe and runs C2 server

set -e

export C2_IP="$DEPLOY_HOST"
export C2_PORT=$(echo "$DEPLOY_PORTS" | grep -oP '8080/tcp->\K[0-9]+')
export FILE_SERVER_PORT=8000

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHALLENGE_DIR="$SCRIPT_DIR/../../sleeping_pipe/challenge"

echo "[*] Building shellcodes..."
cd "$CHALLENGE_DIR"
make clean
make all
make extract

echo "[*] Copying shellcode binaries to rusty_pool_party..."
cp bin/*.bin "$SCRIPT_DIR/"

echo "[*] Building rusty_pool_party..."
cd "$SCRIPT_DIR"
cargo build --release --target x86_64-pc-windows-gnu

echo "[*] Copying executable to current directory..."
cp target/x86_64-pc-windows-gnu/release/rusty_pool_party.exe .

echo "[*] Cleaning up build artifacts..."
rm -f "$SCRIPT_DIR"/*.bin
cargo clean

echo "[+] Done! rusty_pool_party.exe is ready in $SCRIPT_DIR"

# Create a separate directory to serve only the exe
SERVE_DIR=$(mktemp -d)
cp "$SCRIPT_DIR/rusty_pool_party.exe" "$SERVE_DIR/"

cd "$SERVE_DIR"
echo "[*] Starting file server on port $FILE_SERVER_PORT (serving only rusty_pool_party.exe)..."
python -m http.server "$FILE_SERVER_PORT" --bind 0.0.0.0 &

cd "$CHALLENGE_DIR"
echo "[*] Starting C2 server..."
exec python c2_server.py
