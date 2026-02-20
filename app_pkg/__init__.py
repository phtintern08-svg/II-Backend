from flask import Flask, request, jsonify, redirect, session, render_template_string, render_template
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
    import os
    import hashlib
    
    # Get the directory where this file (__init__.py) is located
    app_pkg_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(app_pkg_dir, 'templates')
    
    # Initialize Flask app with explicit template folder
    app = Flask(__name__, template_folder=template_dir)
    app.config.from_object(config_class)
    
    # 🔥 DIAGNOSTIC: Log SECRET_KEY status at app startup (critical for Passenger worker consistency)
    # This helps identify if different workers have different SECRET_KEY values
    # ⚠️ CRITICAL: All Passenger workers MUST have the same SECRET_KEY value
    # If you see different hashes in logs for different PIDs, that's the problem!
    secret_key = app.config.get('SECRET_KEY')
    if secret_key:
        secret_hash = hashlib.sha256(secret_key.encode()).hexdigest()[:16]
        app_logger.info(
            f"✅ App initialized - Process ID: {os.getpid()}, "
            f"SECRET_KEY hash (first 16 chars): {secret_hash}, "
            f"SECRET_KEY length: {len(secret_key)}, "
            f"Env SECRET_KEY exists: {bool(os.environ.get('SECRET_KEY'))}"
        )
        # 🔥 WARNING: If different workers show different hashes, SECRET_KEY mismatch detected!
        app_logger.warning(
            f"🔍 SECRET_KEY DIAGNOSTIC - PID {os.getpid()}: "
            f"Hash={secret_hash}, "
            f"Length={len(secret_key)}, "
            f"FromEnv={bool(os.environ.get('SECRET_KEY'))}"
        )
    else:
        app_logger.error(
            f"❌ CRITICAL: SECRET_KEY is missing! Process ID: {os.getpid()}, "
            f"Env SECRET_KEY exists: {bool(os.environ.get('SECRET_KEY'))}"
        )

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
            admin_routes,
            customer_routes,
            support_routes,
            config_routes,
            health
        )
        
        # Import rider_routes separately with explicit error handling
        try:
            from app_pkg.routes import rider_routes
            app_logger.info("✅ Successfully imported rider_routes module")
        except ImportError as e:
            app_logger.error(f"❌ CRITICAL: Failed to import rider_routes: {e}")
            raise
        except Exception as e:
            app_logger.error(f"❌ CRITICAL: Error importing rider_routes: {e}")
            raise

        app.register_blueprint(auth_routes.bp, url_prefix="/api")
        app.register_blueprint(orders_routes.bp, url_prefix="/api/orders")
        app.register_blueprint(vendor_routes.bp)  # prefix already in blueprint definition
        
        # Register rider blueprint with explicit logging and error handling
        try:
            app_logger.info("Registering rider blueprint...")
            if not hasattr(rider_routes, 'bp'):
                app_logger.error("❌ CRITICAL: rider_routes.bp does not exist!")
                raise AttributeError("rider_routes.bp not found")
            
            app_logger.info(f"Rider blueprint found: name={rider_routes.bp.name}, prefix={rider_routes.bp.url_prefix}")
            app.register_blueprint(rider_routes.bp)  # prefix already in blueprint definition
            app_logger.info(f"✅ Rider blueprint registered successfully: {rider_routes.bp.name} with prefix: {rider_routes.bp.url_prefix}")
        except Exception as e:
            app_logger.error(f"❌ CRITICAL: Failed to register rider blueprint: {e}")
            import traceback
            app_logger.error(traceback.format_exc())
            raise
        
        app.register_blueprint(admin_routes.bp)  # prefix already in blueprint definition
        app.register_blueprint(customer_routes.bp)  # prefix already in blueprint definition
        app.register_blueprint(support_routes.bp, url_prefix="/api")
        app.register_blueprint(config_routes.bp)  # prefix already in blueprint definition
        app.register_blueprint(health.bp, url_prefix="/api")
        
        app_logger.info("All blueprints registered successfully")
        
        # Log ALL registered routes for debugging (HARD PROOF)
        app_logger.info("=== ALL REGISTERED ROUTES ===")
        
        # Log customer routes
        customer_routes_list = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint.startswith('customer.'):
                app_logger.info(f"ROUTE: {rule.rule} -> {rule.endpoint} [{', '.join(rule.methods)}]")
                customer_routes_list.append(rule.rule)
        app_logger.info(f"Customer routes registered: {len(customer_routes_list)} routes")
        
        # Log rider routes
        rider_routes_list = []
        for rule in app.url_map.iter_rules():
            if rule.endpoint.startswith('rider.'):
                app_logger.info(f"ROUTE: {rule.rule} -> {rule.endpoint} [{', '.join(rule.methods)}]")
                rider_routes_list.append(rule.rule)
        app_logger.info(f"Rider routes registered: {len(rider_routes_list)} routes")
        if len(rider_routes_list) == 0:
            app_logger.error("⚠️ WARNING: No rider routes found! Blueprint registration may have failed.")
        
        if len(customer_routes_list) == 0:
            app_logger.error("⚠️ WARNING: No customer routes found! Blueprint registration may have failed.")
    except Exception as e:
        app_logger.exception(f"Error registering blueprints: {e}")
        raise

    # CSRF is disabled globally for APIs (WTF_CSRF_ENABLED = False in config)
    # No need to exempt blueprints since CSRF is not active

    # 🔐 Global Website Access Token Lock Routes
    # Unlock route - allows users to enter access token
    # Rate limited to prevent brute force attacks (5 attempts per minute)
    @limiter.limit("5 per minute")
    @app.route('/unlock', methods=['GET', 'POST'])
    def unlock():
        """Unlock website with access token"""
        access_token = app.config.get('WEBSITE_ACCESS_TOKEN', '')
        
        # If no token is configured, lock is disabled - redirect to root
        if not access_token:
            return redirect('/')
        
        if request.method == 'POST':
            entered_token = request.form.get('access_token', '').strip()
            
            if entered_token == access_token:
                session['site_unlocked'] = True
                session.permanent = True  # Make session persistent
                app_logger.info(f"Website unlocked by {request.remote_addr}")
                
                # Redirect to root or referrer
                next_url = request.args.get('next', '/')
                return redirect(next_url)
            
            # Invalid token
            app_logger.warning(f"Failed unlock attempt from {request.remote_addr}")
            return render_template('unlock.html', error="Invalid access code")
        
        # GET request - show unlock page
        return render_template('unlock.html')
    
    # Lock route - clears session and redirects to unlock
    @app.route('/lock')
    def lock():
        """Lock website by clearing session"""
        session.clear()
        app_logger.info(f"Website locked by {request.remote_addr}")
        return redirect('/unlock')

    # Root route handler - serves portal selector page
    # This route is protected by require_access_token() middleware
    # Users must unlock the site before seeing the portal selector
    @app.route('/')
    def root_portal_selector():
        """Serve portal selector page (protected by global lock)"""
        return render_template('portal_selector.html')

    # Register handlers
    register_error_handlers(app)
    register_request_handlers(app)

    # Startup logs
    app_logger.info("Flask application initialized successfully")
    app_logger.info(f"Environment: {app.config.get('ENV')}")
    app_logger.info(f"Debug mode: {app.config.get('DEBUG')}")
    
    # 🔐 Website Access Token Lock Status
    access_token = app.config.get('WEBSITE_ACCESS_TOKEN', '')
    if access_token:
        app_logger.info("🔐 Website Access Token Lock: ENABLED")
        app_logger.info(f"   Token length: {len(access_token)} characters")
        app_logger.info("   PRODUCTION: Set WEBSITE_ACCESS_TOKEN in cPanel → Setup Python App → Environment Variables")
    else:
        app_logger.info("🔓 Website Access Token Lock: DISABLED (no WEBSITE_ACCESS_TOKEN set)")
    
    # CRITICAL: Verify Mappls keys are loaded at startup
    mappls_js_key = app.config.get('MAPPLS_JS_KEY', '')
    mappls_rest_key = app.config.get('MAPPLS_REST_KEY', '')
    
    if mappls_js_key:
        app_logger.info("✅ MAPPLS_JS_KEY loaded at startup (length: %d)", len(mappls_js_key))
    else:
        app_logger.error("❌ MAPPLS_JS_KEY is EMPTY at startup!")
        app_logger.error("   PRODUCTION FIX: Set MAPPLS_JS_KEY in cPanel → Setup Python App → Environment Variables")
    
    if mappls_rest_key:
        app_logger.info("✅ MAPPLS_REST_KEY loaded at startup (length: %d)", len(mappls_rest_key))
    else:
        app_logger.error("❌ MAPPLS_REST_KEY is EMPTY at startup!")
        app_logger.error("   PRODUCTION FIX: Set MAPPLS_REST_KEY in cPanel → Setup Python App → Environment Variables")
    
    if not mappls_js_key and not mappls_rest_key:
        app_logger.error("   Then restart the application")
    
    # CRITICAL: Verify UPLOAD_FOLDER is configured
    upload_folder = app.config.get('UPLOAD_FOLDER')
    if upload_folder:
        app_logger.info(f"✅ UPLOAD_FOLDER configured: {upload_folder}")
        # Verify folder exists or can be created
        import os
        try:
            os.makedirs(upload_folder, exist_ok=True)
            # Create subdirectories
            os.makedirs(os.path.join(upload_folder, 'vendor'), exist_ok=True)
            os.makedirs(os.path.join(upload_folder, 'rider'), exist_ok=True)
            app_logger.info("✅ Upload directories created/verified")
        except Exception as e:
            app_logger.error(f"❌ Failed to create upload directory: {e}")
            app_logger.error("   PRODUCTION FIX: Ensure UPLOAD_FOLDER path is writable")
    else:
        app_logger.error("❌ UPLOAD_FOLDER is NOT configured!")
        app_logger.error("   PRODUCTION FIX: Set UPLOAD_FOLDER in cPanel → Setup Python App → Environment Variables")
        app_logger.error("   Example: /home/impromptuindian/uploads")

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

    # 🔐 GLOBAL WEBSITE ACCESS TOKEN LOCK
    # This runs BEFORE auth_guard to lock the entire website
    # Blocks ALL domains, subdomains, APIs, and routes
    @app.before_request
    def require_access_token():
        """
        STRICT GLOBAL LOCK
        Overrides EVERYTHING including login pages.
        Blocks: impromptuindian.com, www.impromptuindian.com, apparels.impromptuindian.com,
                vendor.impromptuindian.com, rider.impromptuindian.com, admin.impromptuindian.com,
                ALL APIs, ALL routes, EVERYTHING
        """
        access_token = app.config.get('WEBSITE_ACCESS_TOKEN', '')
        
        # If no token → lock disabled
        if not access_token:
            return None
        
        # Allow only unlock + lock routes
        if request.endpoint in ['unlock', 'lock', 'static']:
            return None
        
        # Allow static files
        if request.path.startswith(('/static/', '/css/', '/js/', '/images/')):
            return None
        
        # Check unlock status
        is_unlocked = session.get('site_unlocked', False)
        
        # Debug logging for lock status (helps diagnose session issues)
        # Log at warning level so it's visible in production logs
        app_logger.warning(
            f"🔐 LOCK CHECK: {request.host} {request.path} | "
            f"unlocked={is_unlocked} | "
            f"endpoint={request.endpoint} | "
            f"remote_addr={request.remote_addr}"
        )
        
        # If not unlocked → force redirect
        if not is_unlocked:
            app_logger.warning(f"🔒 REDIRECTING TO /unlock: {request.host}{request.path}")
            return redirect('/unlock')
        
        # Site unlocked → allow request
        app_logger.debug(f"✅ UNLOCKED - Allowing access: {request.host}{request.path}")
        return None

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
        # NOTE: '/' is NOT public - it's locked by require_access_token()
        PUBLIC_PATHS = (
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
        # Note: '/' is locked by require_access_token() and not in PUBLIC_PATHS
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
