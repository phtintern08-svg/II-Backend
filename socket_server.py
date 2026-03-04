"""
Simple Socket.IO Server - Separate from Passenger
==================================================
Runs on port 5001, completely independent of Passenger Flask app
This bypasses Passenger's worker limitations for stable real-time connections

Architecture:
- Passenger: Handles HTTP API requests only
- This Server: Handles Socket.IO real-time connections only
- Single long-running process = stable sessions
"""

from flask import Flask
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

@socketio.on("connect")
def handle_connect():
    print("✅ Client connected")

@socketio.on("disconnect")
def handle_disconnect():
    print("❌ Client disconnected")

@socketio.on("join_ticket")
def handle_join(data):
    """Join a ticket room"""
    ticket_id = data.get("ticket_id")
    if ticket_id:
        room = f"ticket_{ticket_id}"
        join_room(room)
        print(f"✅ Client joined room: {room}")
        emit('system_message', {'msg': f'Joined ticket {ticket_id}'}, room=room)
    else:
        emit('error', {'msg': 'Ticket ID required'})

@socketio.on("send_message")
def handle_message(data):
    """Handle message sending"""
    ticket_id = data.get("ticket_id")
    message = data.get("message", "")
    
    if not ticket_id or not message:
        emit('error', {'msg': 'Ticket ID and message required'})
        return
    
    room = f"ticket_{ticket_id}"
    emit("receive_message", data, room=room)
    print(f"✅ Message sent in room: {room}")

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Starting Socket.IO Server")
    print("=" * 60)
    print("📍 Port: 5001")
    print("📍 Transport: WebSocket + Polling fallback")
    print("📍 Async Mode: threading")
    print("=" * 60)
    
    socketio.run(
        app,
        host="0.0.0.0",
        port=5001,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True
    )
