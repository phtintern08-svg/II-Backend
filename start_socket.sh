#!/bin/bash

# Standalone Socket.IO Server Startup Script
# ===========================================
# Starts Socket.IO server on port 3000, separate from Passenger
# This bypasses Passenger's worker limitations

echo "=========================================="
echo "🚀 Starting Standalone Socket.IO Server"
echo "=========================================="

# Stop any existing socket server
echo "Stopping old socket server..."
pkill -f "run_socket_standalone.py"
pkill -f "run_socket.py"
sleep 2

# Get Python interpreter path
# ⭐ CRITICAL: Use the correct Python from virtualenv
PYTHON_PATH="/home/impromptuindian/virtualenv/backend/3.11/bin/python"

# Verify Python exists
if [ ! -f "$PYTHON_PATH" ]; then
    echo "❌ ERROR: Python not found at $PYTHON_PATH"
    echo "Please check your virtualenv path and update PYTHON_PATH in this script"
    echo ""
    echo "To find your Python path, run:"
    echo "  which python3"
    echo "  or"
    echo "  ls -la ~/virtualenv/backend/*/bin/python"
    exit 1
fi

# Get backend directory (where this script is located)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure logs directory exists
mkdir -p ~/logs

# Start Socket.IO server in background
echo "Starting Socket.IO server on port 3000..."
echo "Using Python: $PYTHON_PATH"
echo "Script: $SCRIPT_DIR/run_socket_standalone.py"
echo "Working Directory: $SCRIPT_DIR"

nohup "$PYTHON_PATH" "$SCRIPT_DIR/run_socket_standalone.py" \
    > ~/logs/socket.log 2>&1 &

# Wait a moment for server to start
sleep 3

# Verify it's running
if pgrep -f "run_socket_standalone.py" > /dev/null; then
    PID=$(pgrep -f "run_socket_standalone.py")
    echo "✅ Socket.IO server started successfully"
    echo "📍 Process ID: $PID"
    echo "📍 Port: 3000"
    echo "📍 Logs: ~/logs/socket.log"
    echo ""
    echo "To check status: ps aux | grep run_socket_standalone"
    echo "To view logs: tail -f ~/logs/socket.log"
    echo "To stop: pkill -f run_socket_standalone.py"
else
    echo "❌ ERROR: Socket.IO server failed to start"
    echo "Check logs: tail -f ~/logs/socket.log"
    exit 1
fi
