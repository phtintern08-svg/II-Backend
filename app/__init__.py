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
    @app.before_request
    def csrf_exempt_api():
        if request.path.startswith("/api/"):
            setattr(request, "csrf_processing_disabled", True)
    
    # Configure CORS for production APIs (JWT in headers, not cookies)
    CORS(app, supports_credentials=True)
    
    # Register blueprints
    from app.routes import auth_routes, orders_routes, vendor_routes, rider_routes, admin_routes, customer_routes, utility_routes
    
    app.register_blueprint(auth_routes.bp)
    app.register_blueprint(orders_routes.bp)
    app.register_blueprint(vendor_routes.bp)
    app.register_blueprint(rider_routes.bp)
    app.register_blueprint(admin_routes.bp)
    app.register_blueprint(customer_routes.bp)
    app.register_blueprint(utility_routes.bp)
    
    # Register static file serving routes (for cPanel/Passenger)
    register_static_routes(app)
    
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
        api_endpoints = [
            '/api/authenticate', '/api/register', '/api/send-otp', '/api/verify-otp',
            '/api/', '/admin/', '/vendor/', '/rider/', '/customer/'
        ]
        
        for endpoint in api_endpoints:
            if request.path.startswith(endpoint):
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


def register_static_routes(app):
    """Register routes to serve static HTML files (for cPanel/Passenger)"""
    from flask import send_from_directory, abort
    
    # Determine frontend directory path (relative to backend_api)
    # backend_api is in: /home/impromptuindian/backend_api
    # Frontend is in: /home/impromptuindian/Frontend (sibling directory)
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    frontend_base = os.path.join(os.path.dirname(backend_dir), 'Frontend')
    
    # Get subdomain from host header
    def get_frontend_path():
        host = request.host.lower()
        if 'vendor.' in host:
            return os.path.join(frontend_base, 'vendor.impromptuindian.com')
        elif 'rider.' in host:
            return os.path.join(frontend_base, 'rider.impromptuindian.com')
        else:
            return os.path.join(frontend_base, 'apparels.impromptuindian.com')
    
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve_static(path):
        """Serve static files - catch-all for non-API routes (registered last)"""
        # Never serve API routes as static files
        if request.path.startswith('/api/'):
            abort(404)
        
        frontend_dir = get_frontend_path()
        
        # If path is empty or '/', serve index.html
        if not path or path == '':
            path = 'index.html'
        
        file_path = os.path.join(frontend_dir, path)
        
        # Security: prevent directory traversal
        frontend_dir_abs = os.path.abspath(frontend_dir)
        file_path_abs = os.path.abspath(file_path)
        if not file_path_abs.startswith(frontend_dir_abs):
            abort(403)
        
        # If it's a directory, try index.html
        if os.path.isdir(file_path):
            file_path = os.path.join(file_path, 'index.html')
        
        # If file doesn't exist, try with .html extension
        if not os.path.exists(file_path) and not path.endswith('.html'):
            file_path = file_path + '.html'
        
        # Serve the file if it exists
        if os.path.exists(file_path) and os.path.isfile(file_path):
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            return send_from_directory(directory, filename)
        
        # For SPA routing, serve index.html for any non-API route that doesn't match a file
        index_path = os.path.join(frontend_dir, 'index.html')
        if os.path.exists(index_path):
            return send_from_directory(frontend_dir, 'index.html')
        
        abort(404)


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
