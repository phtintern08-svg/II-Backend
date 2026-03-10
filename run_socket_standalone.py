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

# ✅ Load environment variables (for database connection, etc.)
# This is CRITICAL for database credentials in cPanel environment
try:
    from dotenv import load_dotenv
    env_path = os.path.join(backend_dir, '.env')
    if os.path.exists(env_path):
        load_dotenv(env_path, override=True)  # override=True ensures .env takes precedence
        print(f"✅ Loaded environment variables from: {env_path}")
        # Verify critical DB vars are loaded
        db_host = os.getenv('DB_HOST') or os.getenv('MYSQL_HOST')
        if db_host:
            print(f"✅ Database host configured: {db_host}")
        else:
            print("⚠️ WARNING: Database host not found in environment variables")
    else:
        print(f"⚠️ No .env file found at: {env_path}")
        print("   Attempting to use system environment variables...")
        # Try to load from parent directory or common locations
        parent_env = os.path.join(os.path.dirname(backend_dir), '.env')
        if os.path.exists(parent_env):
            load_dotenv(parent_env, override=True)
            print(f"✅ Loaded environment variables from parent: {parent_env}")
        else:
            print("   Using system environment variables only")
except ImportError:
    print("⚠️ python-dotenv not installed")
    print("   Install with: pip install python-dotenv")
    print("   Using system environment variables only")
except Exception as e:
    print(f"⚠️ Error loading .env file: {e}")
    print("   Using system environment variables only")

# ✅ Import and create the main Flask app FIRST (has DB config)
# This ensures database connection is available
try:
    from app_pkg import create_app
    from app_pkg import socketio  # ✅ Use the socketio instance from main app
    from flask_cors import CORS
    
    # Create the full Flask app (with database, models, etc.)
    app = create_app()
    
    # Enable CORS
    CORS(app, resources={r"/*": {"origins": "*"}})
    
    # ✅ Socket.IO is already initialized in create_app() and bound to the app
    # We just need to register the handlers
    from app_pkg.socketio_handlers import register_handlers
    
    # Register Socket.IO handlers (they now have access to the full app with DB)
    register_handlers(socketio)
    
    print("✅ Socket.IO handlers registered from main app")
    print("✅ Using full Flask app - database access available")
    
except Exception as e:
    print(f"❌ ERROR: Could not load main app: {e}")
    import traceback
    traceback.print_exc()
    print("❌ Server cannot start without main app")
    sys.exit(1)

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
    
    # ⭐ SSL Configuration (Solution 2: SSL on port 3000)
    # ⭐ Direct WSS connection bypasses Nginx/Passenger WebSocket restrictions
    import ssl
    cert_file = os.path.expanduser("~/ssl/certs/support.impromptuindian.com.crt")
    key_file = os.path.expanduser("~/ssl/private/support.impromptuindian.com.key")
    ssl_context = None
    if os.path.exists(cert_file) and os.path.exists(key_file):
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(cert_file, key_file)
        print(f"✅ SSL enabled: {cert_file}")
    else:
        print(f"⚠️ SSL certificates not found:")
        print(f"   Certificate: {cert_file}")
        print(f"   Private Key: {key_file}")
        print(f"   Running without SSL (HTTP only)")
        print(f"   ⚠️ Frontend must use ws:// (not wss://) if SSL not available")
    
    # Run Socket.IO server on port 3000
    # ⭐ This runs OUTSIDE Passenger - single process, stable sessions
    # ⭐ allow_unsafe_werkzeug=True is required for shared hosting (no gunicorn/nginx)
    # ⭐ ssl_context=None means HTTP (Solution 1: proxy handles SSL)
    # ⭐ Set ssl_context to enable WSS directly (Solution 2: SSL on port 3000)
    socketio.run(
        app,
        host="0.0.0.0",  # Listen on all interfaces
        port=3000,
        debug=False,
        use_reloader=False,  # Disable auto-reload in production
        allow_unsafe_werkzeug=True,  # ✅ Required for shared hosting (Werkzeug is safe here)
        ssl_context=ssl_context  # ✅ None = HTTP (proxy handles SSL), or SSL context for WSS
    )
