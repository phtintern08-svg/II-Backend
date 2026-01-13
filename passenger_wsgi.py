import os
import sys
import traceback

# Add backend_api root to PYTHONPATH
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

try:
    from app import create_app
    application = create_app()
except Exception as e:
    # Log the error to stderr (Passenger will capture this)
    import sys
    sys.stderr.write(f"ERROR: Failed to create Flask application: {str(e)}\n")
    sys.stderr.write(traceback.format_exc())
    raise
