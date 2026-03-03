# ✅ CRITICAL: For Passenger + Socket.IO integration
# Socket.IO runs inside Passenger process using threading mode
# No separate socket server needed - everything runs through Passenger

from app_pkg import create_app

# Create Flask app (Socket.IO is already initialized and will be bound via socketio.init_app)
app = create_app()

# Passenger entrypoint - Socket.IO middleware is automatically attached
application = app
