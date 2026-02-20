"""
Authentication and Authorization Utilities
Provides JWT token generation, verification, and decorators for route protection
"""
import jwt
import smtplib
import ssl
import secrets
import hashlib
import os
from functools import wraps
from flask import request, jsonify, current_app
from datetime import datetime, timedelta
from email.message import EmailMessage
from app_pkg.models import Admin, Customer, Vendor, Rider, Support
from app_pkg.logger_config import app_logger
from config import Config


def generate_token(user_id, role, username=None, email=None, phone=None):
    """
    Generate a JWT token for authenticated user
    
    Args:
        user_id: User ID
        role: User role (admin, customer, vendor, rider)
        username: Optional username
        email: Optional email
        phone: Optional phone
    
    Returns:
        str: JWT token
    """
    payload = {
        'user_id': user_id,
        'role': role,
        'username': username,
        'email': email,
        'phone': phone,
        'exp': datetime.utcnow() + timedelta(days=7),  # Token expires in 7 days
        'iat': datetime.utcnow()
    }
    
    secret_key = current_app.config.get('SECRET_KEY')
    if not secret_key:
        raise ValueError("SECRET_KEY not configured")
    
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    # PyJWT 2.x returns a string, but ensure it's a string for compatibility
    if isinstance(token, bytes):
        return token.decode('utf-8')
    return token


def verify_token(token):
    """
    Verify and decode a JWT token
    
    Args:
        token: JWT token string
    
    Returns:
        dict: Decoded token payload or None if invalid
    """
    try:
        secret_key = current_app.config.get('SECRET_KEY')
        if not secret_key:
            # 🔥 DIAGNOSTIC: Log SECRET_KEY missing (critical for Passenger worker consistency)
            app_logger.error(
                "SECRET_KEY is missing from app config! "
                f"Process ID: {os.getpid()}, "
                f"Environment SECRET_KEY exists: {bool(os.environ.get('SECRET_KEY'))}"
            )
            return None
        
        # 🔥 DIAGNOSTIC: Log SECRET_KEY hash to verify consistency across workers
        # (Hash only, never log actual key)
        secret_hash = hashlib.sha256(secret_key.encode()).hexdigest()[:16]
        app_logger.debug(
            f"JWT verification - Process ID: {os.getpid()}, "
            f"SECRET_KEY hash (first 16 chars): {secret_hash}"
        )
        
        payload = jwt.decode(token, secret_key, algorithms=['HS256'], leeway=10)
        return payload
    except jwt.ExpiredSignatureError as e:
        app_logger.warning(f"JWT token expired: {e}")
        return None
    except jwt.InvalidTokenError as e:
        # 🔥 DIAGNOSTIC: Log invalid token errors to identify SECRET_KEY mismatch
        secret_hash = hashlib.sha256(secret_key.encode()).hexdigest()[:16] if secret_key else "MISSING"
        token_length = len(token) if token else 0
        app_logger.warning(
            f"❌ JWT token invalid - Process ID: {os.getpid()}, "
            f"SECRET_KEY hash: {secret_hash}, "
            f"Token length: {token_length}, "
            f"Error: {type(e).__name__}, "
            f"Error details: {str(e)}"
        )
        return None


def get_current_user():
    """
    Get current authenticated user from request token
    
    Returns:
        dict: User information from token or None
    """
    token = get_token_from_request()
    if not token:
        return None
    
    payload = verify_token(token)
    return payload


def get_token_from_request():
    """
    Extract JWT token from request (Authorization header or cookie)
    
    Priority:
    1. Authorization header (Bearer token) - PRIMARY for SPA/fetch requests
    2. HttpOnly cookie (access_token) - Fallback for SSO / browser navigation
    3. Query parameter (token) - Legacy/JSONP support
    
    Returns:
        str: Token or None
    """
    # 1️⃣ Authorization header FIRST (SPA-safe)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        try:
            token = auth_header.split(' ', 1)[1]  # Extract token from "Bearer <token>"
            return token
        except IndexError:
            pass
    
    # 2️⃣ HttpOnly cookie fallback (SSO / browser nav)
    token = request.cookies.get('access_token')
    if token:
        return token
    
    # 3. Fallback: Check for token in request args (for JSONP compatibility)
    token = request.args.get('token')
    if token:
        return token
    
    return None


def require_auth(f):
    """
    Decorator to require authentication for a route
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        process_id = os.getpid()
        route_path = request.path
        
        token = get_token_from_request()
        
        if not token:
            app_logger.debug(f"Auth failed - No token found (Process: {process_id}, Route: {route_path})")
            return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401
        
        payload = verify_token(token)
        if not payload:
            # 🔥 DIAGNOSTIC: Log which route failed token verification
            app_logger.warning(
                f"Auth failed - Token verification failed "
                f"(Process: {process_id}, Route: {route_path}, "
                f"Token length: {len(token) if token else 0})"
            )
            return jsonify({"error": "Invalid or expired token", "code": "INVALID_TOKEN"}), 401
        
        # Verify user still exists in database
        user_id = payload.get('user_id')
        role = payload.get('role')
        
        # 🔥 DIAGNOSTIC: Log before verification attempt
        app_logger.debug(
            f"require_auth: About to verify user exists - "
            f"Route: {route_path}, User ID: {user_id}, Role: {role}, "
            f"Process ID: {process_id}"
        )
        
        user_exists = verify_user_exists(user_id, role)
        
        if not user_exists:
            app_logger.warning(
                f"❌ Auth failed - User not found in DB "
                f"(Process: {process_id}, Route: {route_path}, "
                f"User ID: {user_id}, Role: {role}, "
                f"Token payload: {payload})"
            )
            return jsonify({
                "error": "User no longer exists",
                "code": "USER_NOT_FOUND"
            }), 401
        
        # 🔥 DIAGNOSTIC: Log successful verification
        app_logger.debug(
            f"✅ require_auth: User verified successfully - "
            f"Route: {route_path}, User ID: {user_id}, Role: {role}, "
            f"Process ID: {process_id}"
        )
        
        # Add user info to request context
        request.current_user = payload
        
        # 🔥 FIX: Also set request.user_id and request.role for convenience
        # This prevents AttributeError when routes access request.user_id or request.role directly
        request.user_id = user_id
        request.role = role
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_role(*allowed_roles):
    """
    Decorator to require specific role(s) for a route
    
    Args:
        *allowed_roles: One or more allowed roles (admin, customer, vendor, rider)
    """
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            # 🔥 DEFENSIVE: Verify current_user exists and is a dict
            if not hasattr(request, 'current_user') or not request.current_user:
                app_logger.error(
                    f"❌ require_role: current_user missing! "
                    f"Process: {os.getpid()}, Route: {request.path}, "
                    f"Has user_id: {hasattr(request, 'user_id')}, "
                    f"Has role: {hasattr(request, 'role')}"
                )
                return jsonify({
                    "error": "Authentication error - user context missing",
                    "code": "AUTH_CONTEXT_MISSING"
                }), 401
            
            # 🔥 DEFENSIVE: Verify current_user is a dict-like object
            if not isinstance(request.current_user, dict):
                app_logger.error(
                    f"❌ require_role: current_user is not a dict! "
                    f"Process: {os.getpid()}, Route: {request.path}, "
                    f"Type: {type(request.current_user)}"
                )
                return jsonify({
                    "error": "Authentication error - invalid user context",
                    "code": "AUTH_CONTEXT_INVALID"
                }), 401
            
            user_role = request.current_user.get('role')
            user_id = request.current_user.get('user_id')
            
            # 🔥 DEFENSIVE: Verify role exists in token
            if not user_role:
                app_logger.error(
                    f"❌ require_role: role missing from token! "
                    f"Process: {os.getpid()}, Route: {request.path}, "
                    f"User ID: {user_id}, "
                    f"Current user keys: {list(request.current_user.keys()) if isinstance(request.current_user, dict) else 'N/A'}"
                )
                return jsonify({
                    "error": "Authentication error - role missing from token",
                    "code": "ROLE_MISSING"
                }), 401
            
            # 🔥 DIAGNOSTIC: Enhanced role checking with detailed logging
            app_logger.debug(
                f"require_role check - Route: {request.path}, "
                f"User role: {user_role}, Required roles: {allowed_roles}, "
                f"User ID: {user_id}, Process ID: {os.getpid()}"
            )
            
            if user_role not in allowed_roles:
                app_logger.warning(
                    f"⚠️ require_role: Insufficient permissions - "
                    f"Process: {os.getpid()}, Route: {request.path}, "
                    f"User role: '{user_role}' (type: {type(user_role).__name__}), "
                    f"Required: {allowed_roles} (types: {[type(r).__name__ for r in allowed_roles]}), "
                    f"User ID: {user_id}, "
                    f"Exact match check: {user_role in allowed_roles}, "
                    f"Case-sensitive comparison"
                )
                return jsonify({
                    "error": "Insufficient permissions",
                    "code": "INSUFFICIENT_PERMISSIONS",
                    "required_roles": list(allowed_roles),
                    "user_role": user_role
                }), 403
            
            # 🔥 FIX: Explicitly set request.user_id and request.role for consistency
            # This ensures all routes using require_role have these attributes set
            # (require_auth sets them, but being explicit here prevents any edge cases)
            request.user_id = user_id
            request.role = user_role
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


# Convenience aliases for decorators
login_required = require_auth  # Alias for backward compatibility


def admin_required(f):
    """Decorator to require admin role"""
    return require_role('admin')(f)


def role_required(allowed_roles):
    """
    Decorator factory to require specific roles
    
    Args:
        allowed_roles: List of allowed roles
    
    Usage:
        @role_required(['admin', 'vendor'])
        def some_function():
            pass
    """
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            user_role = request.current_user.get('role')
            
            if user_role not in allowed_roles:
                return jsonify({
                    "error": "Insufficient permissions",
                    "code": "INSUFFICIENT_PERMISSIONS",
                    "required_roles": allowed_roles,
                    "user_role": user_role
                }), 403
            
            # Add user_id and role to request for easy access
            request.user_id = request.current_user.get('user_id')
            request.role = user_role
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def require_self_or_role(user_id_param='user_id', *allowed_roles):
    """
    Decorator to allow access if user is accessing their own resource OR has required role
    
    Args:
        user_id_param: Parameter name in route/kwargs that contains the user ID
        *allowed_roles: Allowed roles for cross-user access
    """
    def decorator(f):
        @wraps(f)
        @require_auth
        def decorated_function(*args, **kwargs):
            current_user_id = request.current_user.get('user_id')
            current_user_role = request.current_user.get('role')
            
            # Get the user_id from route parameters or request data
            target_user_id = kwargs.get(user_id_param)
            if target_user_id is None:
                # Try to get from request JSON
                if request.is_json:
                    target_user_id = request.json.get(user_id_param)
                # Try to get from form data
                if target_user_id is None:
                    target_user_id = request.form.get(user_id_param)
                # Try to get from query params
                if target_user_id is None:
                    target_user_id = request.args.get(user_id_param)
            
            # Convert to int for comparison
            try:
                current_user_id = int(current_user_id)
                if target_user_id:
                    target_user_id = int(target_user_id)
            except (ValueError, TypeError):
                pass
            
            # Allow if accessing own resource or has required role
            if target_user_id and current_user_id == target_user_id:
                return f(*args, **kwargs)
            
            if current_user_role in allowed_roles:
                return f(*args, **kwargs)
            
            return jsonify({
                "error": "Insufficient permissions",
                "code": "INSUFFICIENT_PERMISSIONS"
            }), 403
        
        return decorated_function
    return decorator


def verify_user_exists(user_id, role):
    """
    Verify that the user exists in the database
    
    Args:
        user_id: User ID
        role: User role
    
    Returns:
        bool: True if user exists, False otherwise
    """
    try:
        # 🔥 DIAGNOSTIC: Log the verification attempt
        app_logger.debug(
            f"verify_user_exists called - User ID: {user_id}, Role: {role}, "
            f"Process ID: {os.getpid()}"
        )
        
        user = None
        if role == 'admin':
            user = Admin.query.get(user_id)
        elif role == 'customer':
            user = Customer.query.get(user_id)
        elif role == 'vendor':
            user = Vendor.query.get(user_id)
        elif role == 'rider':
            # 🔥 DIAGNOSTIC: Enhanced logging for rider verification
            bind_key = getattr(Rider, '__bind_key__', 'NOT SET')
            table_name = getattr(Rider, '__tablename__', 'NOT SET')
            
            # Check database bind configuration
            from flask import current_app
            binds = current_app.config.get('SQLALCHEMY_BINDS', {})
            rider_bind_uri = binds.get('rider', 'NOT CONFIGURED')
            # Mask password in URI for logging
            if rider_bind_uri != 'NOT CONFIGURED' and '@' in rider_bind_uri:
                # Mask password: mysql+pymysql://user:pass@host/db -> mysql+pymysql://user:***@host/db
                parts = rider_bind_uri.split('@')
                if len(parts) == 2:
                    user_pass = parts[0].split('://')[1] if '://' in parts[0] else parts[0]
                    if ':' in user_pass:
                        user = user_pass.split(':')[0]
                        masked_uri = rider_bind_uri.replace(f'{user}:', f'{user}:***')
                    else:
                        masked_uri = rider_bind_uri
                else:
                    masked_uri = rider_bind_uri
            else:
                masked_uri = rider_bind_uri
            
            app_logger.debug(
                f"Checking rider existence - User ID: {user_id}, "
                f"Rider model bind_key: {bind_key}, "
                f"Table name: {table_name}, "
                f"Rider DB bind URI: {masked_uri}, "
                f"Process ID: {os.getpid()}"
            )
            
            # Try explicit query with bind verification
            try:
                # Check if we can access the bind
                if 'rider' not in binds:
                    app_logger.error(
                        f"❌ CRITICAL: 'rider' bind not found in SQLALCHEMY_BINDS! "
                        f"Available binds: {list(binds.keys())}, "
                        f"Process ID: {os.getpid()}"
                    )
                
                user = Rider.query.get(user_id)
                
                # 🔥 DIAGNOSTIC: Try alternative query method to verify bind
                if user is None:
                    # Try using filter to see if it's a query issue
                    app_logger.debug(
                        f"Rider.query.get() returned None, trying filter() - User ID: {user_id}, "
                        f"Process ID: {os.getpid()}"
                    )
                    user_by_filter = Rider.query.filter(Rider.id == user_id).first()
                    if user_by_filter:
                        app_logger.warning(
                            f"⚠️ Rider found with filter() but not with get() - User ID: {user_id}, "
                            f"Process ID: {os.getpid()}"
                        )
                        user = user_by_filter
                
            except Exception as query_error:
                app_logger.error(
                    f"❌ Exception during Rider query - User ID: {user_id}, "
                    f"Exception: {type(query_error).__name__}: {str(query_error)}, "
                    f"Process ID: {os.getpid()}"
                )
                import traceback
                app_logger.error(f"Query traceback: {traceback.format_exc()}")
                user = None
            
            app_logger.debug(
                f"Rider query result - User ID: {user_id}, "
                f"Found: {user is not None}, "
                f"User object: {user}, "
                f"Process ID: {os.getpid()}"
            )
        elif role == 'support':
            user = Support.query.get(user_id)
        else:
            app_logger.warning(
                f"verify_user_exists - Unknown role: {role}, User ID: {user_id}, "
                f"Process ID: {os.getpid()}"
            )
            return False
        
        user_exists = user is not None
        
        if not user_exists:
            app_logger.warning(
                f"❌ User not found in database - User ID: {user_id}, Role: {role}, "
                f"Process ID: {os.getpid()}"
            )
        else:
            app_logger.debug(
                f"✅ User verified - User ID: {user_id}, Role: {role}, "
                f"Process ID: {os.getpid()}"
            )
        
        return user_exists
    except Exception as e:
        # 🔥 DIAGNOSTIC: Log the actual exception instead of swallowing it
        app_logger.error(
            f"❌ Exception in verify_user_exists - User ID: {user_id}, Role: {role}, "
            f"Exception type: {type(e).__name__}, "
            f"Exception message: {str(e)}, "
            f"Process ID: {os.getpid()}"
        )
        import traceback
        app_logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def send_verification_email(to_email, token):
    """
    Send email verification link to user
    
    Args:
        to_email: Recipient email address
        token: Verification token
    """
    # Log SMTP configuration for debugging (Passenger .env loading verification)
    from flask import current_app
    from config import Config
    try:
        current_app.logger.info(
            f"SMTP CHECK → HOST={Config.SMTP_HOST}, PORT={Config.SMTP_PORT}, USER={Config.SMTP_USER}"
        )
    except:
        pass  # Don't fail if logging fails
    
    try:
        msg = EmailMessage()
        msg["Subject"] = "Verify your Impromptu Indian account"
        msg["From"] = Config.SMTP_USER
        msg["To"] = to_email

        # ✅ CRITICAL FIX: Link must point to API endpoint, not HTML page
        # The API endpoint updates the database (used=True, used_at=now())
        # Option A (Recommended): Direct API link - cleaner, backend-driven
        link = f"{Config.APP_BASE_URL}/api/verify-email?token={token}"
        
        # Calculate expiration time from config (in minutes)
        expiration_minutes = Config.EMAIL_VERIFICATION_TTL // 60

        msg.set_content(
            f"""Welcome to Impromptu Indian 👋

Please verify your email by clicking the link below:

{link}

This link expires in {expiration_minutes} minutes.

If you didn't register, ignore this email.
"""
        )

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(Config.SMTP_HOST, Config.SMTP_PORT, context=context) as server:
            server.login(Config.SMTP_USER, Config.SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        # Log error but don't raise - registration should still succeed
        from app_pkg.logger_config import app_logger
        app_logger.exception(f"Failed to send verification email to {to_email}: {e}")
        return False

