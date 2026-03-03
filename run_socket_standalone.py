#!/usr/bin/env python3
"""
Standalone Socket.IO Server - Separate from Passenger
=====================================================
Runs on port 3000, completely independent of Passenger Flask app
This bypasses Passenger's worker limitations for stable real-time connections

Architecture:
- Passenger: Handles HTTP API requests only
- This Server: Handles Socket.IO real-time connections only
- Single long-running process = stable sessions
"""

import os
import sys

# Add backend directory to path for imports
backend_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, backend_dir)

# Import Flask and Socket.IO
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS

# Create minimal Flask app for Socket.IO
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'socket-server-secret-key')

# Enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# Create Socket.IO instance
# ⭐ Use threading mode for stability (works on all shared hosting)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",  # Stable on shared hosting
    logger=True,
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25,
    allow_upgrades=True,  # Allow WebSocket (standalone server supports it)
    transports=["websocket", "polling"]  # WebSocket preferred, polling fallback
)

# Import and register handlers from main app
try:
    from app_pkg.socketio_handlers import register_handlers
    from app_pkg import create_app as create_main_app
    
    # Create main app context for database access
    main_app = create_main_app()
    
    # Register Socket.IO handlers (they need app context)
    with main_app.app_context():
        register_handlers(socketio)
    
    print("✅ Socket.IO handlers registered from main app")
except Exception as e:
    print(f"⚠️ Warning: Could not load handlers from main app: {e}")
    import traceback
    traceback.print_exc()
    print("⚠️ Using minimal handlers only")
    
    # Minimal fallback handlers
    @socketio.on('connect')
    def handle_connect():
        print(f"✅ Client connected: {request.sid}")
        emit('system_message', {'msg': 'Connected to Socket.IO server'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        print(f"❌ Client disconnected: {request.sid}")

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Starting Standalone Socket.IO Server")
    print("=" * 60)
    print(f"📍 Port: 3000")
    print(f"📍 Transport: WebSocket + Polling fallback")
    print(f"📍 Process ID: {os.getpid()}")
    print(f"📍 Async Mode: threading")
    print(f"📍 Working Directory: {backend_dir}")
    print("=" * 60)
    
    # Run Socket.IO server on port 3000
    # ⭐ This runs OUTSIDE Passenger - single process, stable sessions
    socketio.run(
        app,
        host="0.0.0.0",  # Listen on all interfaces
        port=3000,
        debug=False,
        use_reloader=False  # Disable auto-reload in production
    )
