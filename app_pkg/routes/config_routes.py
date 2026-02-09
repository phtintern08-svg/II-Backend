"""
Config routes - Public configuration endpoint for frontend
Exposes safe, non-secret configuration values to the frontend
"""
from flask import Blueprint, jsonify, current_app
from app_pkg.logger_config import app_logger

bp = Blueprint('config', __name__, url_prefix='/api')


@bp.route('/config', methods=['GET'])
def get_frontend_config():
    """
    Public config endpoint for frontend JS
    ONLY expose safe, non-secret values
    
    Returns Mappls API key for frontend map initialization
    """
    try:
        # Get API key from app config (loaded from environment)
        api_key = current_app.config.get("MAPPLS_API_KEY", "")
        
        # Log for debugging (without exposing full key)
        if api_key:
            app_logger.info("Mappls API key found in config (length: %d)", len(api_key))
        else:
            app_logger.warning("Mappls API key is empty or not set in environment")
        
        return jsonify({
            "mappls": {
                "apiKey": api_key
            }
        })
    except Exception as e:
        app_logger.error("Error in /api/config endpoint: %s", str(e))
        # Return empty key rather than failing completely
        return jsonify({
            "mappls": {
                "apiKey": ""
            }
        }), 200
