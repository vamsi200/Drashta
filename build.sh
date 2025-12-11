#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend"
BINARY_PATH="$BACKEND_DIR/target/release/drashta"

echo "======================================"
echo " Build Process Starting"
echo "======================================"
echo ""

if [[ ! -d "$BACKEND_DIR" || ! -d "$FRONTEND_DIR" ]]; then
  echo "Error: This script must be run from the project root."
  echo "Expected directories:"
  echo "  $BACKEND_DIR"
  echo "  $FRONTEND_DIR"
  exit 1
fi

echo "[1/3] Building backend (release mode)"
cd "$BACKEND_DIR"
cargo build --release
echo "Backend build completed."
echo ""

echo "[2/3] Installing frontend dependencies (npm install)"
cd "$FRONTEND_DIR"
npm install
echo "npm install completed."
echo ""

echo "[3/3] Building frontend (npm run build)"
npm run build
echo "Frontend build completed."
echo ""

echo "======================================"
echo " Build Completed Successfully"
echo "======================================"
echo ""
echo "To run the backend binary:"
echo ""
echo "  $BINARY_PATH --port <PORT>"
echo ""
echo "Default port: 3200"
echo ""
echo "======================================"
