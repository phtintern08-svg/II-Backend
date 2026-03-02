# ✅ CRITICAL: Eventlet monkey patch MUST be first
import eventlet
eventlet.monkey_patch()

# Import app factory
from app_pkg import create_app

# Create Flask app (this also initializes socketio)
app = create_app()

# Import socketio AFTER app is created (it's initialized in create_app)
from app_pkg import socketio

# ✅ CRITICAL: Passenger entrypoint - Use Socket.IO WSGI app
# This is REQUIRED for WebSocket upgrades to work in Passenger
if socketio:
    application = socketio.WSGIApp(socketio.server, app)
    print("✅ Socket.IO WSGI app loaded for WebSocket support")
else:
    application = app
    print("⚠️ Socket.IO not available - using regular Flask app")
