import os
import traceback
import importlib.util

# ✅ Load .env file explicitly (Passenger doesn't load it automatically)
from dotenv import load_dotenv

# backend/ directory (this is the project root)
PROJECT_ROOT = os.path.dirname(__file__)

# ✅ Load .env file explicitly (Passenger-safe)
ENV_PATH = os.path.join(PROJECT_ROOT, ".env")
load_dotenv(ENV_PATH)

# Add backend to path
import sys
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

captured_error = None

try:
    # ✅ CRITICAL: For Socket.IO WebSocket support in Passenger
    # Import directly from app_pkg to get socketio instance
    from app_pkg import create_app
    from app_pkg import socketio
    
    # Create Flask app
    flask_app = create_app()
    
    # Use Socket.IO WSGI app for WebSocket support
    # This is REQUIRED for WebSocket upgrades to work in Passenger
    if socketio:
        application = socketio.wsgi_app(flask_app)
        print("✅ Socket.IO WSGI app loaded for WebSocket support")
    else:
        application = flask_app
        print("⚠️ Socket.IO not available - using regular Flask app")
        
except Exception as e:
    captured_error = str(e) + "\n\n" + traceback.format_exc()
    print(f"❌ Error loading app: {captured_error}", file=sys.stderr)

# Fallback WSGI app to show error in browser
if captured_error:
    def application(environ, start_response):
        start_response(
            "500 Internal Server Error",
            [("Content-Type", "text/plain")]
        )
        body = "DEPLOYMENT FAILED\n\n" + captured_error
        return [body.encode("utf-8")]
