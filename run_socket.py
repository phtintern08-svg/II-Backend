#!/usr/bin/env python3
"""
Socket.IO Server - Separate Process
====================================
Runs Socket.IO server on port 5001, separate from Passenger Flask app
This is the correct enterprise pattern for WebSocket support behind Apache/Passenger

Usage:
    nohup python ~/backend/run_socket.py > ~/logs/socket.log 2>&1 &
    
Or with systemd/service manager for production
"""

import os
import sys
import traceback

# Get the backend directory (where this file is located)
backend_dir = os.path.dirname(os.path.abspath(__file__))

# Add backend directory to Python path
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Change working directory to backend
try:
    os.chdir(backend_dir)
except OSError:
    pass

# ✅ CRITICAL: Eventlet monkey patch MUST be first
import eventlet
eventlet.monkey_patch()

# Load environment variables
from dotenv import load_dotenv
ENV_PATH = os.path.join(backend_dir, ".env")
load_dotenv(ENV_PATH)

try:
    # Import app factory and socketio
    from app_pkg import create_app, socketio
    
    # Create Flask app
    app = create_app()
    
    # Socket.IO is already initialized and bound to app via socketio.init_app(app)
    # Now we run it on a separate port
    
    print("=" * 60)
    print("🚀 Starting Socket.IO Server on port 5001")
    print("=" * 60)
    print(f"✅ Eventlet loaded")
    print(f"✅ Flask app created")
    print(f"✅ Socket.IO initialized")
    print(f"✅ Listening on: 0.0.0.0:5001")
    print("=" * 60)
    print("\n⚠️  IMPORTANT: Configure Apache to proxy /socket.io to this port")
    print("   Add to Apache config:")
    print("   ProxyPass /socket.io http://127.0.0.1:5001/socket.io")
    print("   ProxyPassReverse /socket.io http://127.0.0.1:5001/socket.io")
    print("\n" + "=" * 60 + "\n")
    
    # Run Socket.IO server
    # This will run indefinitely until stopped
    socketio.run(
        app,
        host="0.0.0.0",
        port=5001,
        debug=False,
        use_reloader=False,  # Don't reload in production
        log_output=True
    )
    
except ImportError as e:
    error_msg = f"Failed to import application: {e}\n\n{traceback.format_exc()}"
    print(error_msg, file=sys.stderr)
    sys.exit(1)
    
except Exception as e:
    error_msg = f"Failed to start Socket.IO server: {e}\n\n{traceback.format_exc()}"
    print(error_msg, file=sys.stderr)
    sys.exit(1)
