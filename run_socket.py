#!/usr/bin/env python3
"""
Socket.IO Server - Separate Process
====================================
Runs Socket.IO server on port 5001, separate from Passenger Flask app
This is the correct enterprise pattern for WebSocket support behind Apache/Passenger
"""

import eventlet
eventlet.monkey_patch()

from app_pkg import create_app, socketio

app = create_app()

if __name__ == "__main__":
    print("✅ Starting Socket.IO server on port 5001")
    
    socketio.run(
        app,
        host="127.0.0.1",
        port=5001,
        debug=False
    )
