#!/bin/bash

echo "Stopping old socket..."
pkill -f run_socket.py

sleep 2

echo "Starting socket..."

PYTHON_PATH="/home/impromptuindian/virtualenv/backend/3.11/bin/python"

nohup $PYTHON_PATH \
/home/impromptuindian/backend/run_socket.py \
> /home/impromptuindian/logs/socket.log 2>&1 &

echo "Socket Started"