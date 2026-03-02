# ✅ CRITICAL: Eventlet monkey patch MUST be first
import eventlet
eventlet.monkey_patch()

# Import app factory
from app_pkg import create_app

# Create Flask app
app = create_app()

# ✅ IMPORTANT: Flask-SocketIO automatically injects middleware when socketio.init_app(app) is called
# So we just expose the Flask app - Socket.IO middleware is already attached
application = app
