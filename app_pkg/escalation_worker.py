"""
Escalation Worker - Background Task (Threading Mode)
=====================================================
Runs periodically to check and escalate tickets
Uses threading mode for Passenger compatibility
⭐ SINGLE INSTANCE: Uses lock file to prevent multiple workers from running
"""

import os
import time
from datetime import datetime
from app_pkg.models import db
from app_pkg.intelligent_support import EscalationEngine
from app_pkg.logger_config import app_logger

# ✅ Using threading mode - regular time.sleep() is fine
sleep = time.sleep

# ⭐ Lock file to prevent multiple escalation workers (Passenger runs multiple processes)
LOCK_FILE = "/tmp/escalation_worker.lock"


def run_escalation_worker(app):
    """
    Background worker that checks tickets and escalates if needed
    MUST be started with socketio.start_background_task() for threading compatibility
    
    Args:
        app: Flask application instance (needed for app context)
    """
    while True:
        try:
            # Run within Flask application context
            with app.app_context():
                app_logger.info("Running escalation worker...")
                
                # Check and escalate tickets
                escalated_count = EscalationEngine.check_and_escalate_tickets()
                
                if escalated_count > 0:
                    app_logger.info(f"Escalated {escalated_count} tickets")
            
            # Sleep for 60 seconds before next check (threading mode - regular sleep is fine)
            sleep(60)
            
        except Exception as e:
            app_logger.exception(f"Error in escalation worker: {e}")
            # Sleep even on error to prevent tight loop
            sleep(60)


def start_escalation_worker_background_task(socketio_instance, app):
    """
    Start escalation worker as Socket.IO background task (Threading-compatible)
    
    ✅ MUST use socketio.start_background_task() for proper integration with Socket.IO
    ⭐ SINGLE INSTANCE: Only one worker runs across all Passenger processes (lock file)
    
    Args:
        socketio_instance: Socket.IO instance
        app: Flask application instance
    """
    # ⭐ Prevent multiple workers from starting (Passenger runs multiple processes)
    if os.path.exists(LOCK_FILE):
        app_logger.info("⚠️ Escalation worker already running (lock file exists). Skipping start.")
        return
    
    try:
        # Create lock file
        with open(LOCK_FILE, 'w') as f:
            f.write(str(os.getpid()))
        
        # ✅ Use Socket.IO background task (threading-compatible)
        socketio_instance.start_background_task(run_escalation_worker, app)
        app_logger.info("✅ Escalation worker started as Socket.IO background task (single instance, threading-compatible)")
    except Exception as e:
        app_logger.error(f"❌ Failed to start escalation worker: {e}")
        # Remove lock file on error
        if os.path.exists(LOCK_FILE):
            try:
                os.remove(LOCK_FILE)
            except:
                pass
        raise
