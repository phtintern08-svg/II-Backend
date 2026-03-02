# ✅ CRITICAL: For Passenger + Socket.IO integration
# No monkey patch needed - gevent handles it internally
# Socket.IO runs inside Passenger process

from app_pkg import create_app

# Create Flask app (Socket.IO is already initialized and will be bound via socketio.init_app)
app = create_app()

# Passenger entrypoint - Socket.IO middleware is automatically attached
application = app
