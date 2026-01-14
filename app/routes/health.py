"""
Health Check Route
Simple endpoint to verify the API is running
"""
from flask import Blueprint, jsonify

bp = Blueprint("health", __name__)

@bp.route("/health", methods=["GET"])
def health():
    """
    GET /api/health
    Health check endpoint - no authentication required
    /api prefix is added globally during blueprint registration
    """
    return jsonify({
        "status": "ok",
        "service": "impromptuindian backend",
        "passenger": True
    }), 200
