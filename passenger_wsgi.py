"""
Passenger WSGI Entry Point
This file is the entry point for Passenger (cPanel) deployment
"""
import sys
import os

# Ensure backend_api is in Python path
sys.path.insert(0, os.path.dirname(__file__))

from app import create_app

application = create_app()
