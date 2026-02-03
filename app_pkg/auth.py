"""
Authentication and Authorization Utilities
Provides JWT token generation, verification, and decorators for route protection
"""
import jwt
import smtplib
import ssl
import secrets
from functools import wraps
from flask import request, jsonify, current_app
from datetime import datetime, timedelta
from email.message import EmailMessage
from app_pkg.models import Admin, Customer, Vendor, Rider
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
            return None
        
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
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
    Extract JWT token from request (cookie or Authorization header)
    
    Priority:
    1. HttpOnly cookie (access_token) - PRIMARY for subdomain SSO
    2. Authorization header (Bearer token) - Fallback for API clients
    3. Query parameter (token) - Legacy/JSONP support
    
    Returns:
        str: Token or None
    """
    # 1. Check HttpOnly cookie first (PRIMARY for subdomain SSO)
    token = request.cookies.get('access_token')
    if token:
        return token
    
    # 2. Check Authorization header (optional fallback for API clients)
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        try:
            token = auth_header.split(' ')[1]  # Extract token from "Bearer <token>"
            return token
        except IndexError:
            pass
    
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
        token = get_token_from_request()
        
        if not token:
            return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token", "code": "INVALID_TOKEN"}), 401
        
        # Add user info to request context
        request.current_user = payload
        
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
            user_role = request.current_user.get('role')
            
            if user_role not in allowed_roles:
                return jsonify({
                    "error": "Insufficient permissions",
                    "code": "INSUFFICIENT_PERMISSIONS",
                    "required_roles": list(allowed_roles),
                    "user_role": user_role
                }), 403
            
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
        if role == 'admin':
            user = Admin.query.get(user_id)
        elif role == 'customer':
            user = Customer.query.get(user_id)
        elif role == 'vendor':
            user = Vendor.query.get(user_id)
        elif role == 'rider':
            user = Rider.query.get(user_id)
        else:
            return False
        
        return user is not None
    except Exception:
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

        link = f"{Config.APP_BASE_URL}/verify-email.html?token={token}"

        msg.set_content(
            f"""Welcome to Impromptu Indian 👋

Please verify your email by clicking the link below:

{link}

This link expires in 30 minutes.

If you didn't register, ignore this email.
"""
        )

        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(Config.SMTP_HOST, Config.SMTP_PORT, context=context) as server:
            server.login(Config.SMTP_USER, Config.SMTP_PASS)
            server.send_message(msg)
    except Exception as e:
        # Log error but don't raise - registration should still succeed
        from app_pkg.logger_config import app_logger
        app_logger.exception(f"Failed to send verification email to {to_email}: {e}")
        raise  # Re-raise to handle in calling function

