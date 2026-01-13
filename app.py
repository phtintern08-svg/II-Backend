"""
Flask Application Entry Point
Creates the Flask application using the application factory pattern
"""
from app import create_app
from config import Config

# Create the Flask application
app = create_app(Config)

if __name__ == "__main__":
    # Run the application (for development only)
    # In production, use passenger_wsgi.py
    app.run(debug=Config.DEBUG, host="0.0.0.0", port=5000)
