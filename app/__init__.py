"""
Flask Application Factory
Creates and configures the Flask application with all extensions and blueprints
"""
from flask import Flask, request
from flask_cors import CORS
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
import os
import sys



from config import Config
from app.models import db
from app.schemas import ma
from app.logger_config import app_logger, access_logger, error_logger

# Initialize extensions (but don't bind to app yet)
mail = Mail()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
csrf = CSRFProtect()


def create_app(config_class=Config):
    """
    Flask Application Factory
    
    Args:
        config_class: Configuration class to use (defaults to Config)
    
    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions with app
    db.init_app(app)
    ma.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    csrf.init_app(app)
    
    # Exempt API routes from CSRF protection
    @csrf.exempt
    def api_csrf_exempt():
        pass
    
    # Configure CORS for production APIs (JWT in headers, not cookies)
    CORS(app, supports_credentials=True)
    
    # Register blueprints
    from app.routes import auth_routes, orders_routes, vendor_routes, rider_routes, admin_routes, customer_routes, support_routes, health
    
    # Register blueprints with /api prefix to keep HTML and Flask separated
    app.register_blueprint(auth_routes.bp, url_prefix="/api")
    app.register_blueprint(orders_routes.bp, url_prefix="/api")
    app.register_blueprint(vendor_routes.bp, url_prefix="/api")
    app.register_blueprint(rider_routes.bp, url_prefix="/api")
    app.register_blueprint(admin_routes.bp, url_prefix="/api")
    app.register_blueprint(customer_routes.bp, url_prefix="/api")
    app.register_blueprint(support_routes.bp, url_prefix="/api")
    app.register_blueprint(health.bp, url_prefix="/api")
    
    # Exempt all API blueprints from CSRF protection
    for bp in app.blueprints.values():
        if bp.url_prefix and bp.url_prefix.startswith("/api"):
            csrf.exempt(bp)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register request/response handlers
    register_request_handlers(app)
    
    # Log successful initialization
    app_logger.info(f"Flask application initialized successfully")
    app_logger.info(f"Environment: {app.config.get('ENV')}")
    app_logger.info(f"Debug mode: {app.config.get('DEBUG')}")
    
    return app


def register_error_handlers(app):
    """Register error handlers for the application"""
    from flask import jsonify, request
    
    def expects_json():
        """Check if the request expects a JSON response"""
        # Flask only handles /api/* routes - everything else is Apache
        if request.path.startswith('/api/'):
            return True
        
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH'] and request.content_type and 'application/json' in request.content_type:
            return True
        
        if request.headers.get('Accept', '').startswith('application/json'):
            return True
        
        return False
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors"""
        if expects_json():
            response = jsonify({
                "error": "Endpoint not found",
                "path": request.path,
                "method": request.method
            })
            response.headers['Content-Type'] = 'application/json'
            return response, 404
        return error
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors"""
        error_logger.error(f"Internal server error: {error}")
        if expects_json():
            response = jsonify({
                "error": "Internal server error",
                "message": "An unexpected error occurred"
            })
            response.headers['Content-Type'] = 'application/json'
            return response, 500
        return error
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle 403 errors"""
        if expects_json():
            response = jsonify({
                "error": "Forbidden",
                "message": "You don't have permission to access this resource"
            })
            response.headers['Content-Type'] = 'application/json'
            return response, 403
        return error


def register_request_handlers(app):
    """Register before/after request handlers"""
    
    @app.before_request
    def log_request_info():
        """Log request information"""
        if request.path.startswith('/api/'):
            access_logger.info(f"{request.method} {request.path} from {request.remote_addr}")
    
    @app.after_request
    def after_request(response):
        """Log response information and set headers"""
        # Log API responses
        if request.path.startswith('/api/'):
            access_logger.info(f"{request.method} {request.path} - {response.status_code}")
        
        # Set security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        return response
