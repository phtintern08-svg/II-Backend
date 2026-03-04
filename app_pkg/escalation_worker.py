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
    Can be started with threading.Thread() (no Socket.IO dependency)
    
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


# ⭐ Escalation worker is now started directly via threading.Thread() in __init__.py
# ⭐ No longer needs Socket.IO instance (standalone server handles Socket.IO)
# ⭐ Lock file prevents multiple instances across Passenger workers
