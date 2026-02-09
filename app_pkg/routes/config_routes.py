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
        
        # CRITICAL DEBUG LOGGING - Log what we're sending to frontend
        if api_key:
            app_logger.info("✅ /api/config: Mappls API key found (length: %d, first 4 chars: %s)", 
                          len(api_key), api_key[:4] if len(api_key) >= 4 else "N/A")
        else:
            app_logger.error("❌ /api/config: MAPPLS_API_KEY is EMPTY or NOT SET in environment!")
            app_logger.error("   Check: 1) .env file exists, 2) Environment variable in cPanel, 3) Passenger restart")
        
        # Build response
        response_data = {
            "mappls": {
                "apiKey": api_key
            }
        }
        
        # Log the response structure being sent
        app_logger.info("📤 /api/config response: %s", 
                       {"mappls": {"apiKey": api_key[:10] + "..." if len(api_key) > 10 else api_key}})
        
        return jsonify(response_data)
    except Exception as e:
        app_logger.error("❌ /api/config ERROR: %s", str(e), exc_info=True)
        # Return empty key rather than failing completely
        return jsonify({
            "mappls": {
                "apiKey": ""
            }
        }), 200
