#!/bin/bash

BINARY="../target/release/drashta"
URL="http://localhost:3200/drain?event_name=networkmanager.events&limit=1000"
RUNS=5

if [ ! -f "$BINARY" ]; then
  echo "Error: Binary not found at $BINARY"
  exit 1
fi

$BINARY &
SERVER_PID=$!

sleep 2

cleanup() {
  echo ""
  echo "Stopping server..."
  kill $SERVER_PID 2>/dev/null
  wait $SERVER_PID 2>/dev/null
  echo "Server stopped"
}

trap cleanup EXIT INT TERM

echo "Benchmarking: $URL"
echo "------------------------------------------------------------"

for i in $(seq 1 $RUNS); do
  echo -n "Run $i: "
  curl -w "time: %{time_total}s | status: %{http_code} | size: %{size_download} bytes\n" \
    -o /dev/null \
    -s \
    "$URL"
done

echo "------------------------------------------------------------"
echo "Done"
