"""
Socket.IO Event Handlers - Basic Events
========================================
Basic Socket.IO event handlers for real-time support chat
"""

from app_pkg import socketio
from flask_socketio import emit, join_room
from app_pkg.logger_config import app_logger


@socketio.on("connect")
def handle_connect():
    """Handle client connection"""
    app_logger.info("✅ Client connected to Socket.IO")
    emit('system_message', {'msg': 'Connected to support chat'})


@socketio.on("join_ticket")
def handle_join(data):
    """Join a ticket room"""
    ticket_id = data.get("ticket_id")
    if ticket_id:
        room = f"ticket_{ticket_id}"
        join_room(room)
        app_logger.info(f"✅ Client joined room: {room}")
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
    app_logger.info(f"✅ Message sent in room: {room}")
