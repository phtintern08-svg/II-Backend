"""
Flask Application Entry Point for Passenger WSGI
Uses the application factory pattern from app_pkg

This file is loaded by passenger_wsgi.py which expects either:
- 'app' variable (Flask application instance)
- 'application' variable (WSGI application)

Both are provided for maximum compatibility.
"""
import os
import sys
import traceback

# Get the backend directory (where this file is located)
backend_dir = os.path.dirname(os.path.abspath(__file__))

# Add backend directory to Python path to ensure imports work
# This is critical for Passenger where the working directory may differ
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Change working directory to backend for relative paths (logs, etc.)
# This ensures file operations work correctly in Passenger
try:
    os.chdir(backend_dir)
except OSError:
    # If chdir fails, continue anyway (may not have permissions)
    pass

# Initialize application
app = None
application = None

try:
    # Import the application factory from app_pkg
    from app_pkg import create_app
    
    # Create the Flask application instance using the factory
    app = create_app()
    
    # Passenger WSGI expects 'application' variable
    # Also provide 'app' for compatibility
    application = app
    
except ImportError as e:
    # Log import errors for debugging
    error_msg = f"Failed to import application factory: {e}\n\n{traceback.format_exc()}"
    print(error_msg, file=sys.stderr)
    
    # Create a minimal error WSGI app
    def error_application(environ, start_response):
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
        return [error_msg.encode('utf-8')]
    
    application = error_application
    app = error_application
    
except Exception as e:
    # Log any other initialization errors
    error_msg = f"Failed to create Flask application: {e}\n\n{traceback.format_exc()}"
    print(error_msg, file=sys.stderr)
    
    # Create a minimal error WSGI app
    def error_application(environ, start_response):
        start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
        return [error_msg.encode('utf-8')]
    
    application = error_application
    app = error_application

# Only for local development/testing (ignored by Passenger)
if __name__ == "__main__":
    if app and hasattr(app, 'run'):
        app.run(host="0.0.0.0", port=5000, debug=os.environ.get("DEBUG", "False") == "True")
    else:
        print("Error: Flask application could not be initialized", file=sys.stderr)
        sys.exit(1)

