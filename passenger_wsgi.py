"""
Passenger WSGI Entry Point
This file is the entry point for Passenger (cPanel) deployment
"""
import sys
import os
import logging

# Absolute path of backend_api
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Ensure backend_api is in Python path
sys.path.insert(0, BASE_DIR)

# Create logs folder if missing
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "passenger.log")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stderr),
    ],
)

logger = logging.getLogger("passenger")

try:
    from app import create_app
    from config import Config

    application = create_app(Config)

    logger.info("Passenger WSGI started successfully")
    logger.info(f"ENV = {Config.ENV}")
    logger.info(f"DEBUG = {Config.DEBUG}")

except Exception as e:
    logger.exception("Passenger failed to start")
    raise
