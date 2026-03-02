#!/bin/bash

echo "Stopping old socket server..."
pkill -f run_socket.py

echo "Starting Socket.IO server..."

nohup python ~/backend/run_socket.py \
> ~/logs/socket.log 2>&1 &

echo "✅ Socket.IO server started"
echo "📝 Logs: ~/logs/socket.log"
echo "🔍 Check: ps aux | grep run_socket"
