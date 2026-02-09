"""
Config routes - Public configuration endpoint for frontend
Exposes safe, non-secret configuration values to the frontend
"""
from flask import Blueprint, jsonify, current_app

bp = Blueprint('config', __name__, url_prefix='/api')


@bp.route('/config', methods=['GET'])
def get_frontend_config():
    """
    Public config endpoint for frontend JS
    ONLY expose safe, non-secret values
    """
    return jsonify({
        "mappls": {
            "apiKey": current_app.config.get("MAPPLS_API_KEY", "")
        }
    })
