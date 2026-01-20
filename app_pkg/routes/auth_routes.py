"""
Authentication Routes Blueprint
Handles login, registration, OTP, and authentication-related endpoints
"""
from flask import Blueprint, request, jsonify, send_from_directory, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import random
import time
import threading
import os
from datetime import datetime

from app_pkg.models import db, Admin, Customer, Vendor, Rider, Support, OTPLog
from app_pkg.auth import generate_token, verify_token, login_required, get_token_from_request
from app_pkg.validation import validate_request_data, LoginSchema, sanitize_text
from config import Config
from app_pkg.logger_config import app_logger, access_logger

# Create blueprint
bp = Blueprint('auth', __name__)

# In-memory storage for OTPs
otp_storage = {}
OTP_TTL_SECONDS = int(os.environ.get('OTP_TTL_SECONDS', '600'))  # default 10 minutes

# Custom key function for OTP rate limiting by recipient
def get_otp_recipient():
    """Get recipient from request for OTP rate limiting"""
    try:
        if request.is_json:
            recipient = request.get_json().get('recipient')
            if recipient:
                return f"otp:{recipient}"
    except Exception:
        pass
    return get_remote_address()

# Helper function for building subdomain URLs
def build_subdomain_url(subdomain, path=''):
    """Build URL for subdomain"""
    # BASE_DOMAIN is validated in config.py, so it's guaranteed to be a valid naked domain
    base_domain = Config.BASE_DOMAIN
    
    if Config.ENV == 'production':
        return f"https://{subdomain}.{base_domain}{path}"
    else:
        return f"http://{subdomain}.{base_domain}{path}"

# Helper function for logging auth events
def log_auth_event(event_type, success, identifier, user_id=None, role=None, ip_address=None, error=None):
    """Log authentication events"""
    try:
        # OTPLog model only supports: recipient, otp_code, type, status, created_at, expires_at
        # Log auth events to application logger instead of database
        app_logger.info(
            f"Auth Event: type={event_type}, success={success}, identifier={identifier}, "
            f"user_id={user_id}, role={role}, ip={ip_address}, error={error}"
        )
    except Exception as e:
        app_logger.error(f"Failed to log auth event: {e}")


@bp.route('/authenticate', methods=['POST'])
def authenticate():
    """
    POST /api/authenticate
    Authenticate user and return JWT token
    
    Request Body:
        {
            "identifier": "email or username",
            "password": "password"
        }
    
    Returns:
        {
            "message": "Login successful",
            "token": "jwt_token",
            "role": "user_role",
            "user_id": 123,
            "username": "username",
            "redirect_url": "url"
        }
    """
    # Create response helper to ensure JSON Content-Type
    def json_response(data, status_code=200):
        """Helper to ensure JSON response with proper headers"""
        response = jsonify(data)
        response.headers['Content-Type'] = 'application/json'
        return response, status_code
    
    # Log request details in DEBUG mode only
    if current_app.config.get('DEBUG', False):
        app_logger.debug(f"Authenticate request from {request.remote_addr}")
        app_logger.debug(f"Content-Type: {request.content_type}")
    
    try:
        # Safely parse JSON - use silent=True to avoid exceptions on malformed JSON
        # Do NOT use force=True as it can cause issues behind Passenger
        data = request.get_json(silent=True)
        
        # Handle cases where JSON parsing fails or body is empty
        if data is None:
            if request.content_length and request.content_length > 0:
                return json_response({
                    "error": "Invalid JSON format",
                    "message": "Request body must be valid JSON"
                }, 400)
            else:
                return json_response({
                    "error": "Missing request body",
                    "message": "Request body is required"
                }, 400)
        
        # Validate that data is a dictionary
        if not isinstance(data, dict):
            return json_response({
                "error": "Invalid request format",
                "message": "Request body must be a JSON object"
            }, 400)
        
        # Extract and validate required fields
        identifier = data.get('identifier')
        password = data.get('password')
        
        # Check for missing required fields
        if not identifier or not password:
            missing = []
            if not identifier:
                missing.append('identifier')
            if not password:
                missing.append('password')
            return json_response({
                "error": "Missing required fields",
                "message": f"The following fields are required: {', '.join(missing)}",
                "missing_fields": missing
            }, 400)
        
        # Ensure fields are strings and trim
        identifier = str(identifier).strip()
        password = str(password)
        
        if not identifier:
            return json_response({
                "error": "Invalid identifier",
                "message": "Identifier cannot be empty"
            }, 400)
        
        if not password:
            return json_response({
                "error": "Invalid password",
                "message": "Password cannot be empty"
            }, 400)
        
        # Validate field lengths
        if len(identifier) > 255:
            return json_response({
                "error": "Invalid identifier",
                "message": "Identifier must be 255 characters or less"
            }, 400)
        
        if len(password) > 255:
            return json_response({
                "error": "Invalid password",
                "message": "Password must be 255 characters or less"
            }, 400)
        
        # Check all user tables to find if email/username exists
        # Track which table has the user for better error messages
        user_found = False
        user_table = None
        user_obj = None
        
        # 1. Check Admin table (by username only) - impromptuindian_admin.admins
        admin = Admin.query.filter_by(username=identifier).first()
        if admin:
            user_found = True
            user_table = 'admin'
            user_obj = admin
            if check_password_hash(admin.password_hash, password):
                token = generate_token(
                    user_id=admin.id,
                    role="admin",
                    username=admin.username
                )
                log_auth_event('login', True, identifier, admin.id, 'admin', request.remote_addr)
                response = jsonify({
                    "message": "Login successful",
                    "role": "admin",
                    "user_id": admin.id,
                    "username": admin.username,
                    "redirect_url": "/admin/home.html"
                })
                response.set_cookie(
                    "access_token",
                    token,
                    domain=f".{Config.BASE_DOMAIN}",  # .impromptuindian.com
                    httponly=True,
                    secure=True,  # REQUIRED when SameSite=None
                    samesite="None",  # Allows cross-subdomain POST requests
                    max_age=7 * 24 * 60 * 60  # 7 days
                )
                response.headers['Content-Type'] = 'application/json'
                return response, 200
        
        # 2. Check Customer table (by email) - impromptuindian_customer.customers
        if not user_found:
            customer = Customer.query.filter_by(email=identifier).first()
            if customer:
                user_found = True
                user_table = 'customer'
                user_obj = customer
                if check_password_hash(customer.password_hash, password):
                    token = generate_token(
                        user_id=customer.id,
                        role="customer",
                        username=customer.username,
                        email=customer.email,
                        phone=customer.phone
                    )
                    log_auth_event('login', True, identifier, customer.id, 'customer', request.remote_addr)
                    response = jsonify({
                        "message": "Login successful",
                        "role": "customer",
                        "user_id": customer.id,
                        "username": customer.username,
                        "email": customer.email,
                        "phone": customer.phone,
                        "redirect_url": "/customer/home.html"
                    })
                    response.set_cookie(
                        "access_token",
                        token,
                        domain=f".{Config.BASE_DOMAIN}",  # .impromptuindian.com
                        httponly=True,
                        secure=True,  # REQUIRED when SameSite=None
                        samesite="None",  # Allows cross-subdomain POST requests
                        max_age=7 * 24 * 60 * 60  # 7 days
                    )
                    response.headers['Content-Type'] = 'application/json'
                    return response, 200
        
        # 3. Check Vendor table (by email) - impromptuindian_vendor.vendors
        if not user_found:
            vendor = Vendor.query.filter_by(email=identifier).first()
            if vendor:
                user_found = True
                user_table = 'vendor'
                user_obj = vendor
                if check_password_hash(vendor.password_hash, password):
                    token = generate_token(
                        user_id=vendor.id,
                        role="vendor",
                        username=vendor.username,
                        email=vendor.email,
                        phone=vendor.phone
                    )
                    log_auth_event('login', True, identifier, vendor.id, 'vendor', request.remote_addr)
                    redirect_url = build_subdomain_url('vendor', '/home.html')
                    response = jsonify({
                        "message": "Login successful",
                        "role": "vendor",
                        "user_id": vendor.id,
                        "business_name": vendor.business_name,
                        "username": vendor.username,
                        "email": vendor.email,
                        "phone": vendor.phone,
                        "redirect_url": redirect_url
                    })
                    response.set_cookie(
                        "access_token",
                        token,
                        domain=f".{Config.BASE_DOMAIN}",  # .impromptuindian.com
                        httponly=True,
                        secure=True,  # REQUIRED when SameSite=None
                        samesite="None",  # Allows cross-subdomain POST requests
                        max_age=7 * 24 * 60 * 60  # 7 days
                    )
                    response.headers['Content-Type'] = 'application/json'
                    return response, 200
        
        # 4. Check Rider table (by email) - impromptuindian_rider.riders
        if not user_found:
            rider = Rider.query.filter_by(email=identifier).first()
            if rider:
                user_found = True
                user_table = 'rider'
                user_obj = rider
                if check_password_hash(rider.password_hash, password):
                    token = generate_token(
                        user_id=rider.id,
                        role="rider",
                        username=rider.name,
                        email=rider.email,
                        phone=rider.phone
                    )
                    log_auth_event('login', True, identifier, rider.id, 'rider', request.remote_addr)
                    redirect_url = build_subdomain_url('rider', '/home.html')
                    response = jsonify({
                        "message": "Login successful",
                        "role": "rider",
                        "user_id": rider.id,
                        "username": rider.name,
                        "email": rider.email,
                        "phone": rider.phone,
                        "verification_status": rider.verification_status,
                        "redirect_url": redirect_url
                    })
                    response.set_cookie(
                        "access_token",
                        token,
                        domain=f".{Config.BASE_DOMAIN}",  # .impromptuindian.com
                        httponly=True,
                        secure=True,  # REQUIRED when SameSite=None
                        samesite="None",  # Allows cross-subdomain POST requests
                        max_age=7 * 24 * 60 * 60  # 7 days
                    )
                    response.headers['Content-Type'] = 'application/json'
                    return response, 200
        
        # 5. Check Support table (by email) - impromptuindian_support.support
        if not user_found:
            support = Support.query.filter_by(email=identifier).first()
            if support:
                user_found = True
                user_table = 'support'
                user_obj = support
                if check_password_hash(support.password_hash, password):
                    token = generate_token(
                        user_id=support.id,
                        role="support",
                        username=support.username,
                        email=support.email,
                        phone=support.phone
                    )
                    log_auth_event('login', True, identifier, support.id, 'support', request.remote_addr)
                    response = jsonify({
                        "message": "Login successful",
                        "role": "support",
                        "user_id": support.id,
                        "username": support.username,
                        "email": support.email,
                        "phone": support.phone,
                        "redirect_url": "/support/home.html"
                    })
                    response.set_cookie(
                        "access_token",
                        token,
                        domain=f".{Config.BASE_DOMAIN}",  # .impromptuindian.com
                        httponly=True,
                        secure=True,  # REQUIRED when SameSite=None
                        samesite="None",  # Allows cross-subdomain POST requests
                        max_age=7 * 24 * 60 * 60  # 7 days
                    )
                    response.headers['Content-Type'] = 'application/json'
                    return response, 200
        
        # Determine error message based on whether user was found
        if user_found:
            # Email/username exists but password is wrong
            log_auth_event('login', False, identifier, user_obj.id if user_obj else None, user_table, request.remote_addr, error="Wrong password")
            return json_response({
                "error": "Invalid password",
                "message": "The entered password is wrong"
            }, 401)
        else:
            # Email/username doesn't exist
            log_auth_event('login', False, identifier, None, None, request.remote_addr, error="Email/username not found")
            return json_response({
                "error": "Invalid email",
                "message": "The entered email is wrong"
            }, 401)
        
    except Exception as e:
        # Log full exception details server-side only
        app_logger.exception(f"Authentication error: {e}")
        
        # Always return JSON, never HTML
        is_debug = current_app.config.get('DEBUG', False)
        if is_debug:
            return json_response({
                "error": "Internal server error",
                "message": "An unexpected error occurred during authentication",
                "debug_info": str(e)
            }, 500)
        else:
            return json_response({
                "error": "Internal server error",
                "message": "Login failed. Please try again later."
            }, 500)


@bp.route('/register', methods=['POST'])
def register():
    """
    POST /api/register
    Register a new customer account
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['username', 'email', 'phone', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Check if email already exists
        existing_customer = Customer.query.filter_by(email=data['email']).first()
        if existing_customer:
            return jsonify({"error": "Email already registered"}), 400
        
        # Check if phone already exists
        existing_phone = Customer.query.filter_by(phone=data['phone']).first()
        if existing_phone:
            return jsonify({"error": "Phone number already registered"}), 400
        
        # Create new customer
        new_customer = Customer(
            username=sanitize_text(data['username']),
            email=data['email'].lower().strip(),
            phone=data['phone'].strip(),
            password_hash=generate_password_hash(data['password']),
            created_at=datetime.utcnow()
        )
        
        db.session.add(new_customer)
        db.session.commit()
        
        # Generate token
        token = generate_token(
            user_id=new_customer.id,
            role="customer",
            username=new_customer.username,
            email=new_customer.email,
            phone=new_customer.phone
        )
        
        log_auth_event('register', True, data['email'], new_customer.id, 'customer', request.remote_addr)
        
        # Set cookie for automatic login (consistent with login endpoint)
        response = jsonify({
            "message": "Registration successful",
            "role": "customer",
            "user_id": new_customer.id,
            "username": new_customer.username,
            "email": new_customer.email,
            "phone": new_customer.phone,
            "redirect_url": "/customer/home.html"
        })
        response.set_cookie(
            "access_token",
            token,
            domain=f".{Config.BASE_DOMAIN}",  # .impromptuindian.com
            httponly=True,
            secure=True,  # REQUIRED when SameSite=None
            samesite="None",  # Allows cross-subdomain POST requests
            max_age=7 * 24 * 60 * 60  # 7 days
        )
        response.headers['Content-Type'] = 'application/json'
        return response, 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Registration error: {e}")
        return jsonify({"error": "Registration failed. Please try again."}), 500


@bp.route('/send-otp', methods=['POST'])
def send_otp():
    """
    POST /api/send-otp
    Send OTP to email or phone
    """
    try:
        data = request.get_json()
        recipient = data.get('recipient') if data else None
        type_ = data.get('type') if data else None
        
        if not recipient or not type_:
            return jsonify({"error": "Recipient and type required"}), 400
        
        # Generate 6-digit OTP
        otp = str(random.randint(100000, 999999))

        # Store OTP with expiry
        expires_at = time.time() + OTP_TTL_SECONDS
        otp_storage[recipient] = (otp, expires_at)
        
        # Save OTP to Database
        try:
            new_otp_log = OTPLog(
                recipient=recipient,
                otp_code=otp,
                type=type_,
                status='sent',
                created_at=datetime.utcnow(),
                expires_at=datetime.fromtimestamp(expires_at)
            )
            db.session.add(new_otp_log)
            db.session.commit()
        except Exception as db_err:
            db.session.rollback()

        try:
            if type_ == 'email':
                # Validate email format
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                if not re.match(email_pattern, recipient):
                    return jsonify({"error": "Invalid email address format"}), 400
                
                # Check if SMTP is configured
                if not current_app.config.get('MAIL_USERNAME') or not current_app.config.get('MAIL_PASSWORD'):
                    app_logger.error("SMTP not configured", extra={"recipient": recipient})
                    return jsonify({"error": "Email service is not configured. Please contact support."}), 500
                
                # Send email in background thread
                def send_email_async():
                    try:
                        with current_app.app_context():
                            from flask_mail import Mail
                            mail = Mail(current_app)
                            msg = Message(
                                subject='Your ImpromptuIndian OTP Code',
                                recipients=[recipient],
                                body=f'Your OTP code is: {otp}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this code, please ignore this email.\n\nBest regards,\nImpromptuIndian Team'
                            )
                            mail.send(msg)
                            app_logger.info(f"OTP email sent successfully to {recipient}")
                    except Exception as email_err:
                        app_logger.exception("OTP email sending failed", extra={"recipient": recipient})
                
                # Start email thread (non-blocking)
                email_thread = threading.Thread(target=send_email_async)
                email_thread.daemon = True
                email_thread.start()
                
                return jsonify({"message": f"OTP sent successfully to {recipient}"}), 200

            elif type_ == 'phone':
                # Phone OTP is disabled
                return jsonify({"error": "Phone OTP authentication is currently disabled. Please use email for OTP verification."}), 400
            else:
                return jsonify({"error": "Invalid OTP type. Use 'email' or 'phone'."}), 400
                
        except Exception as send_err:
            app_logger.exception("OTP sending error", extra={"recipient": recipient, "type": type_})
            return jsonify({"message": f"OTP sent successfully to {recipient}"}), 200
            
    except Exception as e:
        app_logger.exception(f"Send OTP error: {e}")
        return jsonify({"error": "Failed to send OTP. Please check server configuration."}), 500


@bp.route('/verify-otp', methods=['POST'])
def verify_otp():
    """
    POST /api/verify-otp
    Verify OTP code
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
            
        recipient = data.get('recipient')
        otp = data.get('otp')
        
        if not recipient or not otp:
            return jsonify({"error": "Recipient and OTP required"}), 400
        
        stored = otp_storage.get(recipient)

        if not stored:
            return jsonify({"error": "No OTP found for this recipient. Please request a new one."}), 400

        stored_otp, expires_at = stored

        # Check expiration
        if time.time() > expires_at:
            del otp_storage[recipient]
            return jsonify({"error": "OTP has expired. Please request a new one."}), 400
        
        if stored_otp == otp:
            # OTP is correct, remove it from storage
            del otp_storage[recipient]
            return jsonify({"message": "OTP verified successfully", "verified": True}), 200
        else:
            return jsonify({"error": "Invalid OTP. Please try again.", "verified": False}), 400
            
    except Exception as e:
        app_logger.exception(f"Verify OTP error: {e}")
        return jsonify({"error": "Failed to verify OTP"}), 500


@bp.route('/verify-token', methods=['GET'])
def verify_token_endpoint():
    """
    GET /api/verify-token
    Verify JWT token validity (reads from cookie or Authorization header)
    Using GET avoids OPTIONS preflight for simpler CORS handling
    """
    try:
        # Get token from cookie (primary) or Authorization header (fallback)
        from app_pkg.auth import get_token_from_request
        token = get_token_from_request()
        
        if not token:
            return jsonify({"error": "Not authenticated"}), 401
        
        payload = verify_token(token)
        
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        return jsonify({
            "valid": True,
            "user_id": payload.get('user_id'),
            "role": payload.get('role')
        }), 200
        
    except Exception as e:
        app_logger.error(f"Token verification error: {e}")
        return jsonify({"error": "Token verification failed"}), 401


@bp.route('/logout', methods=['POST'])
def logout():
    """
    POST /api/logout
    Logout user by deleting the access_token cookie
    
    NOTE: This endpoint does NOT require authentication.
    Users should be able to logout even with expired tokens.
    """
    try:
        # Try to get user info for logging (optional - don't fail if token is expired)
        try:
            token = get_token_from_request()
            if token:
                payload = verify_token(token)
                if payload:
                    user_id = payload.get('user_id')
                    role = payload.get('role')
                    log_auth_event('logout', True, f"user_{user_id}", user_id, role, request.remote_addr)
        except Exception:
            # Token might be expired/invalid - that's okay, just log without user info
            log_auth_event('logout', True, 'unknown', None, None, request.remote_addr)
        
        # Delete the access_token cookie from all subdomains
        # IMPORTANT: Return JSON only - NEVER redirect from API endpoints
        response = jsonify({
            "success": True,
            "message": "Logged out successfully"
        })
        
        response.delete_cookie(
            "access_token",
            domain=f".{Config.BASE_DOMAIN}",  # .impromptuindian.com
            path="/"
        )
        
        return response, 200
    except Exception as e:
        app_logger.error(f"Logout error: {e}")
        # Even on error, return JSON (never redirect)
        return jsonify({
            "success": False,
            "error": "Logout failed"
        }), 500
