"""
Escalation Worker - Background Task
===================================
Runs periodically to check and escalate tickets
"""

import time
from datetime import datetime
from app_pkg.models import db
from app_pkg.intelligent_support import EscalationEngine
from app_pkg.logger_config import app_logger


def run_escalation_worker():
    """
    Background worker that checks tickets and escalates if needed
    Run this in a separate thread or process
    """
    while True:
        try:
            app_logger.info("Running escalation worker...")
            
            # Check and escalate tickets
            escalated_count = EscalationEngine.check_and_escalate_tickets()
            
            if escalated_count > 0:
                app_logger.info(f"Escalated {escalated_count} tickets")
            
            # Sleep for 60 seconds before next check
            time.sleep(60)
            
        except Exception as e:
            app_logger.exception(f"Error in escalation worker: {e}")
            # Sleep even on error to prevent tight loop
            time.sleep(60)


def start_escalation_worker_thread():
    """Start escalation worker in a background thread"""
    import threading
    
    worker_thread = threading.Thread(
        target=run_escalation_worker,
        daemon=True,
        name="EscalationWorker"
    )
    worker_thread.start()
    app_logger.info("✅ Escalation worker thread started")
    return worker_thread
