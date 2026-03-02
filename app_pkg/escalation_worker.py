"""
Escalation Worker - Background Task (Gevent-Compatible)
=======================================================
Runs periodically to check and escalate tickets
MUST use gevent-compatible sleep when using gevent async mode
"""

from datetime import datetime
from app_pkg.models import db
from app_pkg.intelligent_support import EscalationEngine
from app_pkg.logger_config import app_logger

# ✅ CRITICAL: Use gevent-compatible sleep
# DO NOT use time.sleep() - it blocks gevent green threads
try:
    from gevent import sleep
except ImportError:
    try:
        from eventlet import sleep
    except ImportError:
        # Fallback if neither available (shouldn't happen)
        import time
        sleep = time.sleep


def run_escalation_worker(app):
    """
    Background worker that checks tickets and escalates if needed
    MUST be started with socketio.start_background_task() for gevent compatibility
    
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
            
            # ✅ CRITICAL: Use gevent.sleep() NOT time.sleep()
            # This allows gevent to yield to other green threads
            sleep(60)  # Sleep for 60 seconds before next check
            
        except Exception as e:
            app_logger.exception(f"Error in escalation worker: {e}")
            # Sleep even on error to prevent tight loop
            sleep(60)


def start_escalation_worker_background_task(socketio_instance, app):
    """
    Start escalation worker as Socket.IO background task (Gevent-compatible)
    
    ✅ MUST use socketio.start_background_task() instead of threading.Thread()
    This is REQUIRED when using gevent to avoid lock conflicts
    
    Args:
        socketio_instance: Socket.IO instance
        app: Flask application instance
    """
    try:
        # ✅ Use Socket.IO background task (gevent-compatible)
        socketio_instance.start_background_task(run_escalation_worker, app)
        app_logger.info("✅ Escalation worker started as Socket.IO background task (gevent-compatible)")
    except Exception as e:
        app_logger.error(f"❌ Failed to start escalation worker: {e}")
        raise
