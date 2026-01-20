from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

from config import Config
from app_pkg.models import db
from app_pkg.schemas import ma
from app_pkg.logger_config import (
    app_logger,
    access_logger,
    error_logger
)

# Initialize extensions (without app binding)
mail = Mail()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
csrf = CSRFProtect()


def create_app(config_class=Config):
    """
    Flask application factory
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    ma.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    
    # CSRF is disabled for APIs (WTF_CSRF_ENABLED = False in config)
    # APIs use JWT tokens in Authorization headers, so CSRF protection is not needed
    # Only initialize CSRF if explicitly enabled (for future HTML form support if needed)
    if app.config.get('WTF_CSRF_ENABLED', False):
        csrf.init_app(app)

    # Enable CORS with explicit origins for cross-subdomain cookie support
    # When using credentials, must specify exact origins (cannot use *)
    CORS(
        app,
        supports_credentials=True,
        origins=[
            "https://apparels.impromptuindian.com",
            "https://rider.impromptuindian.com",
            "https://vendor.impromptuindian.com",
            "https://support.impromptuindian.com",
            "https://admin.impromptuindian.com",
            "http://localhost:5000",  # For local development
            "http://localhost:3000",  # For local frontend development
        ]
    )

    # Register blueprints
    from app_pkg.routes import (
        auth_routes,
        orders_routes,
        vendor_routes,
        rider_routes,
        admin_routes,
        customer_routes,
        support_routes,
        health
    )

    app.register_blueprint(auth_routes.bp, url_prefix="/api")
    app.register_blueprint(orders_routes.bp, url_prefix="/api")
    app.register_blueprint(vendor_routes.bp, url_prefix="/api")
    app.register_blueprint(rider_routes.bp, url_prefix="/api")
    app.register_blueprint(admin_routes.bp, url_prefix="/api")
    app.register_blueprint(customer_routes.bp, url_prefix="/api")
    app.register_blueprint(support_routes.bp, url_prefix="/api")
    app.register_blueprint(health.bp, url_prefix="/api")

    # CSRF is disabled globally for APIs (WTF_CSRF_ENABLED = False in config)
    # No need to exempt blueprints since CSRF is not active

    # Register handlers
    register_error_handlers(app)
    register_request_handlers(app)

    # Startup logs
    app_logger.info("Flask application initialized successfully")
    app_logger.info(f"Environment: {app.config.get('ENV')}")
    app_logger.info(f"Debug mode: {app.config.get('DEBUG')}")

    return app


def register_error_handlers(app):
    """
    Register global error handlers
    """

    def expects_json():
        if request.path.startswith("/api/"):
            return True
        if request.headers.get("Accept", "").startswith("application/json"):
            return True
        return False

    @app.errorhandler(404)
    def not_found(error):
        if expects_json():
            return jsonify({
                "error": "Endpoint not found",
                "path": request.path,
                "method": request.method
            }), 404
        return error

    @app.errorhandler(403)
    def forbidden(error):
        if expects_json():
            return jsonify({
                "error": "Forbidden",
                "message": "You do not have permission to access this resource"
            }), 403
        return error

    @app.errorhandler(500)
    def internal_error(error):
        error_logger.exception("Internal server error")
        if expects_json():
            return jsonify({
                "error": "Internal server error",
                "message": "An unexpected error occurred"
            }), 500
        return error


def register_request_handlers(app):
    """
    Register before/after request handlers
    """

    @app.before_request
    def log_request():
        if request.path.startswith("/api/"):
            access_logger.info(
                f"{request.remote_addr} - {request.method} {request.path}"
            )

    @app.after_request
    def log_response(response):
        if request.path.startswith("/api/"):
            access_logger.info(
                f"{request.method} {request.path} - {response.status_code}"
            )

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response
