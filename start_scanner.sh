#!/bin/bash
echo ""
echo "======================================================"
echo "  NetScan Pro - Industrial Network Scanner"
echo "======================================================"
echo ""
echo "  Starting backend server on port 8765..."
echo "  Opening browser..."
echo ""
echo "  Press Ctrl+C to stop."
echo "======================================================"
echo ""

# Open browser after 1 second
sleep 1 && xdg-open http://localhost:8765 2>/dev/null \
  || open http://localhost:8765 2>/dev/null &

# Run server (needs sudo on Linux for raw socket ping)
python3 network_scanner_server.py
