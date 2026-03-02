#!/bin/bash
# Startup script for Socket.IO server
# Usage: ./start_socket.sh

cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "../venv/bin/activate" ]; then
    source ../venv/bin/activate
fi

# Start Socket.IO server
echo "🚀 Starting Socket.IO server..."
nohup python run_socket.py > ../logs/socket.log 2>&1 &

echo "✅ Socket.IO server started in background"
echo "📋 Process ID: $!"
echo "📝 Logs: ~/logs/socket.log"
echo ""
echo "To stop: pkill -f run_socket.py"
echo "To view logs: tail -f ~/logs/socket.log"

