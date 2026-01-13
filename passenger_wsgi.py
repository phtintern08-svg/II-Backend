"""
Passenger WSGI Entry Point
This file is the entry point for Passenger (cPanel) deployment
"""
import sys
import os
import logging

# Add the backend_api directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configure logging for Passenger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../logs/passenger.log'),
        logging.StreamHandler(sys.stderr)
    ]
)

logger = logging.getLogger(__name__)

try:
    # Import the Flask application
    from app import create_app
    from config import Config
    
    # Create the application
    application = create_app(Config)
    
    logger.info("Passenger WSGI application initialized successfully")
    logger.info(f"Environment: {Config.ENV}")
    logger.info(f"Debug mode: {Config.DEBUG}")
    
except Exception as e:
    logger.exception(f"Failed to initialize Passenger WSGI application: {e}")
    raise

# Passenger looks for the 'application' object
# Note: Do NOT rename this variable - Passenger requires it to be named 'application'
