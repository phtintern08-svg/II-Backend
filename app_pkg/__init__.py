from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

from config import Config
from app_pkg.models import db
from app_pkg.schemas import ma
from app_pkg.logger_config import (
    app_logger,
    access_logger,
    error_logger
)
from app_pkg.auth import get_token_from_request, verify_token

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

    # Content Security Policy (CSP) - CRITICAL for Mappls SDK to load sub-scripts
    # Without this, browser silently blocks Mappls internal scripts
    # Flask-Talisman expects snake_case keys, not kebab-case
    csp = {
        "default-src": "'self'",
        "script-src": [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "https://apis.mappls.com",
            "https://cdn.mappls.com",
            "https://*.mappls.com"
        ],
        "style-src": [
            "'self'",
            "'unsafe-inline'",
            "https://apis.mappls.com",
            "https://cdn.mappls.com",
            "https://*.mappls.com"
        ],
        "connect-src": [
            "'self'",
            "https://apis.mappls.com",
            "https://cdn.mappls.com",
            "https://*.mappls.com"
        ],
        "img-src": [
            "'self'",
            "data:",
            "blob:",
            "https:"
        ],
        "font-src": [
            "'self'",
            "data:",
            "https:"
        ],
        "frame_ancestors": "'none'"  # Flask-Talisman uses snake_case, not kebab-case
    }
    
    # Apply CSP using Talisman
    Talisman(app, content_security_policy=csp, force_https=False)

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
    try:
        from app_pkg.routes import (
            auth_routes,
            orders_routes,
            vendor_routes,
            rider_routes,
            admin_routes,
            customer_routes,
            support_routes,
            config_routes,
            health
        )

        app.register_blueprint(auth_routes.bp, url_prefix="/api")
        app.register_blueprint(orders_routes.bp, url_prefix="/api")
        app.register_blueprint(vendor_routes.bp, url_prefix="/api")
        app.register_blueprint(rider_routes.bp, url_prefix="/api")
        app.register_blueprint(admin_routes.bp, url_prefix="/api")
        app.register_blueprint(customer_routes.bp)  # prefix already in blueprint definition
        app.register_blueprint(support_routes.bp, url_prefix="/api")
        app.register_blueprint(config_routes.bp)  # prefix already in blueprint definition
        app.register_blueprint(health.bp, url_prefix="/api")
        
        app_logger.info("All blueprints registered successfully")
        
        # Log ALL registered routes for debugging (HARD PROOF)
        app_logger.info("=== ALL REGISTERED ROUTES ===")
        for rule in app.url_map.iter_rules():
            if rule.endpoint.startswith('customer.'):
                app_logger.info(f"ROUTE: {rule.rule} -> {rule.endpoint} [{', '.join(rule.methods)}]")
        
        # Count customer routes
        customer_routes_list = [rule.rule for rule in app.url_map.iter_rules() if rule.endpoint.startswith('customer.')]
        app_logger.info(f"Customer routes registered: {len(customer_routes_list)} routes")
        if len(customer_routes_list) == 0:
            app_logger.error("⚠️ WARNING: No customer routes found! Blueprint registration may have failed.")
    except Exception as e:
        app_logger.exception(f"Error registering blueprints: {e}")
        raise

    # CSRF is disabled globally for APIs (WTF_CSRF_ENABLED = False in config)
    # No need to exempt blueprints since CSRF is not active

    # Explicit root route handler - redirects to login page
    @app.route('/')
    def root_redirect():
        """Redirect root path to login page"""
        if app.config.get('ENV') == 'production':
            return redirect(
                f"https://apparels.{Config.BASE_DOMAIN}/login.html",
                code=302
            )
        else:
            # Development: use request host
            scheme = 'https' if request.is_secure else 'http'
            return redirect(
                f"{scheme}://{request.host}/login.html",
                code=302
            )

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
    def auth_guard():
        """
        Authentication guard for HTML pages
        - API endpoints handle their own authentication (return 401 JSON)
        - Public paths (login, static files) are always allowed
        - Protected HTML pages redirect to /login.html if not authenticated
        """
        path = request.path
        
        # Log API requests
        if path.startswith("/api/"):
            access_logger.info(
                f"{request.remote_addr} - {request.method} {request.path}"
            )
        
        # Public paths that don't require authentication
        PUBLIC_PATHS = (
            '/',
            '/login.html',
            '/register.html',
            '/verify-email.html',
            '/css/',
            '/js/',
            '/images/',
            '/favicon.ico',
            '/api/',  # API endpoints handle their own auth
        )
        
        # Check if path is public
        is_public = any(path.startswith(public_path) for public_path in PUBLIC_PATHS)
        
        if is_public:
            return None  # Continue to route handler
        
        # For non-public HTML pages, check authentication
        # Only check HTML pages (not API, not static files with extensions)
        # Note: '/' is now in PUBLIC_PATHS, so it's handled separately
        is_html_page = (
            path.endswith('.html') or 
            (not path.startswith('/api/') and not '.' in path.split('/')[-1])
        )
        
        if is_html_page:
            token = get_token_from_request()
            
            # Build absolute login URL (prevents relative path issues when on /admin/home.html, etc.)
            if app.config.get('ENV') == 'production':
                login_url = f"https://apparels.{Config.BASE_DOMAIN}/login.html"
            else:
                # Development: use request host
                scheme = 'https' if request.is_secure else 'http'
                login_url = f"{scheme}://{request.host}/login.html"
            
            if not token:
                # No token found - redirect to login (ABSOLUTE URL to prevent relative path issues)
                return redirect(login_url, code=302)
            
            # Verify token
            payload = verify_token(token)
            if not payload:
                # Invalid or expired token - redirect to login (ABSOLUTE URL to prevent relative path issues)
                return redirect(login_url, code=302)
            
            # Token is valid - continue to route handler
            return None
        
        # For all other paths (static files, etc.), allow
        return None

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
