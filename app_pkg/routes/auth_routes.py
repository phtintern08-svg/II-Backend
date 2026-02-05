"""
Authentication Routes Blueprint
Handles login, registration, OTP, and authentication-related endpoints
"""
from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Message
import re
import random
import time
import threading
import os
import hashlib
from datetime import datetime, timedelta

from app_pkg.models import db, Admin, Customer, Vendor, Rider, Support, OTPLog, EmailVerificationToken
from app_pkg.auth import generate_token, verify_token, get_token_from_request, send_verification_email
import secrets
from app_pkg.validation import sanitize_text
from config import Config
from app_pkg.logger_config import app_logger
from sqlalchemy import or_, and_

# Create blueprint
bp = Blueprint('auth', __name__)

# ⚠️ SECURITY NOTE: In-memory OTP storage (will break with multiple workers/restarts)
# TODO: Migrate to DB-based OTP verification using OTPLog table
# Currently acceptable because:
# 1. Phone OTP is disabled on backend
# 2. Email OTP uses DB (OTPLog) for logging
# 3. Single-worker deployment works for now
otp_storage = {}
OTP_TTL_SECONDS = int(os.environ.get('OTP_TTL_SECONDS', '600'))  # default 10 minutes

# ✅ REMOVED: get_otp_recipient() function
# This function was never used and had an incomplete import (get_remote_address)
# If OTP rate limiting is needed in the future, implement it properly with correct imports

# Helper function for building subdomain URLs
def build_subdomain_url(subdomain, path=''):
    """Build URL for subdomain"""
    # BASE_DOMAIN is validated in config.py, so it's guaranteed to be a valid naked domain
    base_domain = Config.BASE_DOMAIN
    
    # ✅ FIX: Use config constants instead of hardcoded subdomain strings
    # Map subdomain names to config constants
    subdomain_map = {
        'vendor': Config.VENDOR_SUBDOMAIN,
        'rider': Config.RIDER_SUBDOMAIN,
        'support': Config.SUPPORT_SUBDOMAIN,
        'apparels': Config.APP_SUBDOMAIN
    }
    # Use mapped subdomain if available, otherwise use provided subdomain
    actual_subdomain = subdomain_map.get(subdomain, subdomain)
    
    if Config.ENV == 'production':
        return f"https://{actual_subdomain}.{base_domain}{path}"
    else:
        return f"http://{actual_subdomain}.{base_domain}{path}"

# Helper function for logging auth events
def log_auth_event(event_type, success, identifier, user_id=None, role=None, ip_address=None, error=None):
    """Log authentication events.

    IMPORTANT: This helper must NEVER raise, especially from within auth flows.
    """
    try:
        app_logger.info(
            f"Auth Event: type={event_type}, success={success}, identifier={identifier}, "
            f"user_id={user_id}, role={role}, ip={ip_address}, error={error}"
        )
    except Exception:
        # Logging failures must be completely ignored to avoid breaking authentication
        # (e.g., file permission issues, formatter bugs, etc.)
        pass


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
        
        # 1. Check Admin table (by username only) - impromptuindian_admin.admins
        admin = Admin.query.filter_by(username=identifier).first()
        if admin:
            if not check_password_hash(admin.password_hash, password):
                # Wrong password for existing admin
                log_auth_event('login', False, identifier, admin.id, 'admin', request.remote_addr, error="Wrong password")
                return json_response({
                    "error": "Invalid credentials",
                    "message": "Email or password incorrect"
                }, 401)

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
        
        # 2. Check Customer table (by email or phone) - impromptuindian_customer.customers
        customer = Customer.query.filter(
            (Customer.email == identifier) | (Customer.phone == identifier)
        ).first()
        if customer:
            if not check_password_hash(customer.password_hash, password):
                # Wrong password for existing customer
                log_auth_event('login', False, identifier, customer.id, 'customer', request.remote_addr, error="Wrong password")
                return json_response({
                    "error": "Invalid credentials",
                    "message": "Email or password incorrect"
                }, 401)
            
            # Check email verification
            if not customer.is_email_verified:
                return json_response({
                    "error": "Email not verified",
                    "message": "Please verify your email before logging in"
                }, 403)

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
        
        # 3. Check Vendor table (by email or phone) - impromptuindian_vendor.vendors
        vendor = Vendor.query.filter(
            (Vendor.email == identifier) | (Vendor.phone == identifier)
        ).first()
        if vendor:
            if not check_password_hash(vendor.password_hash, password):
                # Wrong password for existing vendor
                log_auth_event('login', False, identifier, vendor.id, 'vendor', request.remote_addr, error="Wrong password")
                return json_response({
                    "error": "Invalid credentials",
                    "message": "Email or password incorrect"
                }, 401)
            
            # Check email verification
            if not vendor.is_email_verified:
                return json_response({
                    "error": "Email not verified",
                    "message": "Please verify your email before logging in"
                }, 403)

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
        
        # 4. Check Rider table (by email or phone) - impromptuindian_rider.riders
        rider = Rider.query.filter(
            (Rider.email == identifier) | (Rider.phone == identifier)
        ).first()
        if rider:
            if not check_password_hash(rider.password_hash, password):
                # Wrong password for existing rider
                log_auth_event('login', False, identifier, rider.id, 'rider', request.remote_addr, error="Wrong password")
                return json_response({
                    "error": "Invalid credentials",
                    "message": "Email or password incorrect"
                }, 401)
            
            # Check email verification
            if not rider.is_email_verified:
                return json_response({
                    "error": "Email not verified",
                    "message": "Please verify your email before logging in"
                }, 403)

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
        
        # 5. Check Support table (by email or phone) - impromptuindian_support.support
        support = Support.query.filter(
            (Support.email == identifier) | (Support.phone == identifier)
        ).first()
        if support:
            if not check_password_hash(support.password_hash, password):
                # Wrong password for existing support user
                log_auth_event('login', False, identifier, support.id, 'support', request.remote_addr, error="Wrong password")
                return json_response({
                    "error": "Invalid credentials",
                    "message": "Email or password incorrect"
                }, 401)

            token = generate_token(
                user_id=support.id,
                role="support",
                username=support.username,
                email=support.email,
                phone=support.phone
            )
            log_auth_event('login', True, identifier, support.id, 'support', request.remote_addr)
            redirect_url = build_subdomain_url('support', '/home.html')
            response = jsonify({
                "message": "Login successful",
                "role": "support",
                "user_id": support.id,
                "username": support.username,
                "email": support.email,
                "phone": support.phone,
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
        
        # If we reached here, identifier was not found in any table
        log_auth_event('login', False, identifier, None, None, request.remote_addr, error="Email/phone/username not found")
        return json_response({
            "error": "Invalid credentials",
            "message": "Email or password incorrect"
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
    Register a new customer, rider, or vendor account
    Creates user and sends email verification link
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        role = data.get('role', 'customer')  # Default to customer
        
        # Validate required fields based on role
        if role == 'customer':
            required_fields = ['username', 'email', 'password']
        elif role == 'rider':
            required_fields = ['username', 'email', 'phone', 'password']
        elif role == 'vendor':
            required_fields = ['username', 'email', 'password']
        else:
            return jsonify({"error": f"Invalid role: {role}. Must be 'customer', 'rider', or 'vendor'"}), 400
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        email = data['email'].lower().strip()
        
        # Check if email already exists (for all user types)
        existing_customer = Customer.query.filter_by(email=email).first()
        existing_rider = Rider.query.filter_by(email=email).first()
        existing_vendor = Vendor.query.filter_by(email=email).first()
        
        if existing_customer or existing_rider or existing_vendor:
            return jsonify({"error": "Email already registered"}), 400
        
        # ✅ SINGLE SOURCE OF TRUTH: Only backend decides if email is verified
        # ✅ BUG #2 FIX: Email verification is a boolean fact, not token recency
        # Check if email was EVER verified (any used token), not "most recent token"
        verified = db.session.query(
            EmailVerificationToken.id
        ).filter(
            EmailVerificationToken.email == email,
            EmailVerificationToken.user_role == role,
            EmailVerificationToken.used == True,
            EmailVerificationToken.purpose == 'pre_registration'
        ).first()
        
        if not verified:
            return jsonify({
                "error": "Please verify your email before creating an account. Click the verification link sent to your email."
            }), 403
        
        email_was_verified = True
        
        user_id = None
        user_role = role
        
        # Create user based on role
        if role == 'customer':
            # Check if phone already exists (if provided)
            phone = data.get('phone', '').strip() if data.get('phone') else None
            if phone:
                existing_phone = Customer.query.filter_by(phone=phone).first()
                if existing_phone:
                    return jsonify({"error": "Phone number already registered"}), 400
            
            new_user = Customer(
                username=sanitize_text(data['username']),
                email=email,
                phone=phone,
                password_hash=generate_password_hash(data['password']),
                is_email_verified=email_was_verified,  # Set based on pre-registration verification
                created_at=datetime.utcnow()
            )
            db.session.add(new_user)
            db.session.flush()  # Get the ID without committing
            user_id = new_user.id
            
        elif role == 'rider':
            phone = data['phone'].strip()
            existing_phone = Rider.query.filter_by(phone=phone).first()
            if existing_phone:
                return jsonify({"error": "Phone number already registered"}), 400
            
            new_user = Rider(
                name=sanitize_text(data['username']),
                email=email,
                phone=phone,
                password_hash=generate_password_hash(data['password']),
                is_email_verified=email_was_verified,  # Set based on pre-registration verification
                created_at=datetime.utcnow()
            )
            db.session.add(new_user)
            db.session.flush()  # Get the ID without committing
            user_id = new_user.id
            
        elif role == 'vendor':
            # Check if phone already exists (if provided)
            phone = data.get('phone', '').strip() if data.get('phone') else None
            if phone:
                existing_phone = Vendor.query.filter_by(phone=phone).first()
                if existing_phone:
                    return jsonify({"error": "Phone number already registered"}), 400
            
            new_user = Vendor(
                username=sanitize_text(data['username']),
                email=email,
                phone=phone,
                password_hash=generate_password_hash(data['password']),
                business_name=data.get('business_name', '').strip() if data.get('business_name') else None,
                is_email_verified=email_was_verified,  # Set based on pre-registration verification
                created_at=datetime.utcnow()
            )
            db.session.add(new_user)
            db.session.flush()  # Get the ID without committing
            user_id = new_user.id
        
        # ✅ Link any verified pre-registration token to the new user (for audit trail)
        # Find the most recent verified token to link
        verified_token = EmailVerificationToken.query.filter(
            EmailVerificationToken.email == email,
            EmailVerificationToken.user_role == role,
            EmailVerificationToken.used == True,
            EmailVerificationToken.purpose == 'pre_registration'
        ).order_by(
            EmailVerificationToken.used_at.desc()
        ).first()
        
        if verified_token and verified_token.user_id is None:
            # Update the pre-registration token to link it to the new user
            # ✅ CRITICAL: Do NOT reset used = False. Token is a one-way fuse - once used, never reset.
            verified_token.user_id = user_id
            # verified_token.used stays True (it was already set to True when user clicked the link)
            db.session.commit()
            app_logger.info(f"Linked pre-registration token to user {user_id} (email: {email}, role: {role})")
        # ✅ REMOVED: Post-registration token creation block
        # This branch was unreachable because:
        # 1. Registration requires pre-registration email verification (returns 403 if not verified)
        # 2. Therefore email_was_verified is always True when we reach user creation
        # 3. Login already requires is_email_verified=True, so post-registration tokens serve no purpose
        # If post-registration verification is needed in the future, implement a separate flow
        
        log_auth_event('register', True, email, user_id, user_role, request.remote_addr)
        
        # ✅ LOGIC FIX: email_was_verified is always True here (we return 403 earlier if not verified)
        # Removed unreachable else branch for cleaner code
        return jsonify({
            "success": True,
            "message": "Account created successfully. Your email was already verified."
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Registration error: {e}")
        return jsonify({"error": "Registration failed. Please try again."}), 500


@bp.route('/send-email-verification-link', methods=['POST'])
def send_email_verification_link():
    """
    POST /api/send-email-verification-link
    Send email verification link before registration
    Creates a pre-registration verification token
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        role = data.get('role', '').strip().lower()
        
        if not email or not role:
            return jsonify({"error": "Email and role are required"}), 400
        
        # Validate role
        if role not in ['customer', 'vendor', 'rider']:
            return jsonify({"error": "Invalid role. Must be 'customer', 'vendor', or 'rider'"}), 400
        
        # Validate email format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({"error": "Invalid email address format"}), 400
        
        # Check if email already registered
        existing_customer = Customer.query.filter_by(email=email).first()
        existing_rider = Rider.query.filter_by(email=email).first()
        existing_vendor = Vendor.query.filter_by(email=email).first()
        
        if existing_customer or existing_rider or existing_vendor:
            # ✅ ISSUE #2 FIX: Return 200 with status (not 400) so frontend can handle it properly
            # Frontend expects status-based responses, not HTTP error codes for business states
            return jsonify({
                "success": True,  # Transport success (request processed)
                "status": "already_registered",
                "verified": True,  # If registered, email was verified
                "message": "This email is already registered. Please log in."
            }), 200
        
        # ✅ BUG #1 FIX: Check if email is already verified BEFORE creating new tokens
        # Email verification is a boolean fact - once verified, never re-tokenize
        already_verified = EmailVerificationToken.query.filter(
            EmailVerificationToken.email == email,
            EmailVerificationToken.user_role == role,
            EmailVerificationToken.used == True,
            EmailVerificationToken.purpose == 'pre_registration'
        ).first()
        
        if already_verified:
            app_logger.info(f"Email verification requested for already-verified email: {email} ({role})")
            return jsonify({
                "success": True,
                "status": "already_verified",
                "verified": True,
                "message": "Email already verified. You can proceed to create your account."
            }), 200
        
        # ✅ DATA HYGIENE: Mark expired tokens as used (prevents accumulation of garbage tokens)
        expired_tokens = EmailVerificationToken.query.filter_by(
            email=email,
            user_role=role,
            used=False,
            purpose='pre_registration'
        ).filter(
            EmailVerificationToken.expires_at < datetime.utcnow()
        ).all()
        
        if expired_tokens:
            for token in expired_tokens:
                token.used = True  # Mark as used to prevent accumulation
            db.session.commit()
            app_logger.debug(f"Marked {len(expired_tokens)} expired token(s) as used for {email} ({role})")
        
        # Check if there's already a valid unexpired token for this email+role with pre_registration purpose
        existing_token = EmailVerificationToken.query.filter_by(
            email=email,
            user_role=role,
            used=False,
            purpose='pre_registration'
        ).filter(
            EmailVerificationToken.expires_at > datetime.utcnow()
        ).first()
        
        if existing_token:
            # Resend email with existing token
            try:
                send_verification_email(email, existing_token.token)
                app_logger.info(f"Resent verification email to {email} (role: {role})")
                return jsonify({
                    "success": True,
                    "status": "link_sent",
                    "verified": False,
                    "message": "Verification link sent"
                }), 200
            except Exception as email_err:
                app_logger.exception(f"Failed to resend verification email: {email_err}")
                return jsonify({"error": "Failed to send verification email"}), 500
        
        # Create new verification token (user_id=None for pre-registration)
        # ✅ Use centralized timeout from config
        token = secrets.token_urlsafe(48)
        expires_at = datetime.utcnow() + timedelta(seconds=Config.EMAIL_VERIFICATION_TTL)
        
        # ✅ SECURITY: Hash user agent for tracking (don't store full UA)
        user_agent = request.headers.get('User-Agent', '')
        user_agent_hash = hashlib.sha256(user_agent.encode()).hexdigest() if user_agent else None
        
        verification_record = EmailVerificationToken(
            user_id=None,  # None for pre-registration
            email=email,  # Store email for matching during registration
            user_role=role,
            token=token,
            expires_at=expires_at,
            used=False,
            purpose='pre_registration',  # ✅ Purpose-bound token (required for registration check)
            ip_address=request.remote_addr,  # ✅ Track IP for security
            user_agent_hash=user_agent_hash  # ✅ Track UA hash for security
        )
        
        db.session.add(verification_record)
        # ✅ CRITICAL FIX: Commit AFTER successful email send (not before)
        # This ensures token is only stored if email actually sent
        try:
            send_verification_email(email, token)
            db.session.commit()  # Only commit if email send succeeded
            app_logger.info(f"Sent pre-registration verification email to {email} (role: {role})")
        except Exception as email_err:
            db.session.rollback()  # Now rollback actually works (before commit)
            app_logger.exception(f"Failed to send verification email: {email_err}")
            return jsonify({"error": "Failed to send verification email"}), 500
        
        return jsonify({
            "success": True,
            "status": "link_sent",
            "verified": False,
            "message": "Verification link sent. Check your inbox."
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Error sending email verification link: {e}")
        return jsonify({"error": "Failed to send verification link"}), 500


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
                
                # ✅ CRITICAL FIX: Make email send synchronous for OTP (critical path)
                # OTP must only be stored if email actually sent successfully
                # Background thread exceptions don't propagate, so we can't know if send failed
                try:
                    from flask_mail import Mail
                    mail = Mail(current_app)
                    msg = Message(
                        subject='Your ImpromptuIndian OTP Code',
                        recipients=[recipient],
                        body=f'Your OTP code is: {otp}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this code, please ignore this email.\n\nBest regards,\nImpromptuIndian Team'
                    )
                    mail.send(msg)
                    app_logger.info(f"OTP email sent successfully to {recipient}")
                    
                    # ✅ Only store OTP after successful send
                    expires_at = time.time() + OTP_TTL_SECONDS
                    otp_storage[recipient] = (otp, expires_at)
                except Exception as email_err:
                    app_logger.exception("OTP email sending failed", extra={"recipient": recipient})
                    # Don't store OTP if email send failed - re-raise to trigger outer exception handler
                    raise
                
                # Save OTP to Database (after send attempt)
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
                    app_logger.warning(f"Failed to log OTP to database: {db_err}")
                
                return jsonify({"message": f"OTP sent successfully to {recipient}"}), 200

            elif type_ == 'phone':
                # ✅ FIX: Phone OTP is disabled - return clear error
                return jsonify({"error": "Phone OTP authentication is currently disabled. Please use email for OTP verification."}), 400
            else:
                return jsonify({"error": "Invalid OTP type. Use 'email' or 'phone'."}), 400
                
        except Exception as send_err:
            # ✅ CRITICAL FIX: Return error if sending fails (don't lie to frontend)
            app_logger.exception("OTP sending error", extra={"recipient": recipient, "type": type_})
            # Clean up stored OTP since send failed
            if recipient in otp_storage:
                del otp_storage[recipient]
            return jsonify({"error": "Failed to send OTP. Please try again later."}), 500
            
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


@bp.route('/verify-email', methods=['GET'])
def verify_email():
    """
    GET /api/verify-email?token=<token>
    Verify user email using token from verification link
    
    ⚠️ NON-IDEMPOTENT:
    - Token is one-time use (one-way fuse)
    - Used or expired tokens return 410 Gone
    - After successful verification, token is marked used and cannot be reused
    """
    try:
        token = request.args.get('token')
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
        
        # ✅ SECURITY HARDENING: Find verification record with purpose check
        # Only allow pre_registration or post_registration tokens (not password_reset, etc.)
        record = EmailVerificationToken.query.filter(
            EmailVerificationToken.token == token,
            EmailVerificationToken.purpose.in_(['pre_registration', 'post_registration'])
        ).first()
        
        if not record:
            app_logger.warning(f"Email verification attempt with invalid token from IP: {request.remote_addr}")
            return jsonify({"error": "Invalid or expired link"}), 400
        
        # ✅ PART 2: Hard expiry - used tokens are expired (one-time use)
        if record.used:
            app_logger.info(f"Email verification token already used (expired): {record.email} ({record.user_role})")
            
            # ✅ FIX #1: Properly detect API requests (not just by Accept header)
            # Browsers send Accept: text/html even for fetch() requests, so we need better detection
            # Note: Content-Type is often None on GET requests, so we don't check it
            accept_header = request.headers.get('Accept', '')
            is_api_request = (
                request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                or 'application/json' in accept_header
            )
            
            # For browser navigation, redirect to error page
            if not is_api_request:
                from flask import redirect
                redirect_url = f"{Config.APP_BASE_URL}/verify-email.html?error=expired&reason=used"
                return redirect(redirect_url), 302
            
            # ✅ Return 410 Gone for expired (used) tokens
            return jsonify({
                "success": False,
                "error": "Link expired",
                "reason": "used"
            }), 410
        
        # ✅ PART 2: Hard expiry - check TTL expiration
        if record.expires_at < datetime.utcnow():
            app_logger.warning(
                f"Email verification attempt with expired token: {record.email} ({record.user_role}), "
                f"token_id={record.id}, expired_at={record.expires_at}, now={datetime.utcnow()}"
            )
            
            # For browser navigation, redirect to error page
            accept_header = request.headers.get('Accept', '')
            is_api_request = (
                request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                or 'application/json' in accept_header
            )
            
            if not is_api_request:
                from flask import redirect
                redirect_url = f"{Config.APP_BASE_URL}/verify-email.html?error=expired&reason=timeout"
                return redirect(redirect_url), 302
            
            # ✅ Return 410 Gone for expired (timeout) tokens
            return jsonify({
                "success": False,
                "error": "Link expired",
                "reason": "timeout"
            }), 410
        
        # ✅ SECURITY: Log suspicious usage (IP/UA mismatch) but don't reject
        # This is how real systems work (Stripe, GitHub, etc.) - log but allow
        current_ua = request.headers.get('User-Agent', '')
        current_ua_hash = hashlib.sha256(current_ua.encode()).hexdigest() if current_ua else None
        
        if record.ip_address and record.ip_address != request.remote_addr:
            app_logger.warning(
                f"Email verification IP mismatch: {record.email} ({record.user_role}), "
                f"token_id={record.id}, created_ip={record.ip_address}, current_ip={request.remote_addr}"
            )
        
        if record.user_agent_hash and record.user_agent_hash != current_ua_hash:
            app_logger.warning(
                f"Email verification UA mismatch: {record.email} ({record.user_role}), "
                f"token_id={record.id}"
            )
        
        # Handle pre-registration verification (user_id is None)
        if record.user_id is None:
            # ✅ PRE-REGISTRATION VERIFICATION - DB is the single source of truth
            # Mark token as used in database (this is the verification)
            # ✅ RACE CONDITION FIX: Set used_at timestamp for atomic verification
            record.used = True
            record.used_at = datetime.utcnow()  # Timestamp for race condition protection
            db.session.commit()  # CRITICAL: Commit immediately before response
            
            app_logger.info(
                f"Email verified via magic link: {record.email} ({record.user_role}), token_id={record.id}"
            )
            
            # ✅ FIX #1: Properly detect API requests (not just by Accept header)
            # Browsers send Accept: text/html even for fetch() requests, so we need better detection
            # Note: Content-Type is often None on GET requests, so we don't check it
            accept_header = request.headers.get('Accept', '')
            is_api_request = (
                request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                or 'application/json' in accept_header
            )
            
            # Only redirect for actual browser navigation (not polling/fetch)
            if not is_api_request:
                # Browser request - redirect to success page with email/role for auto-fill
                from flask import redirect
                redirect_url = f"{Config.APP_BASE_URL}/verify-email.html?token={token}&verified=1&email={record.email}&role={record.user_role}"
                return redirect(redirect_url), 302
            
            # ✅ ALWAYS return JSON for API/polling requests
            return jsonify({
                "success": True,
                "pre_registration": True,
                "email": record.email,
                "role": record.user_role
            }), 200
        
        # Handle post-registration verification (user_id exists)
        if record.user_role == 'customer':
            user = Customer.query.get(record.user_id)
        elif record.user_role == 'rider':
            user = Rider.query.get(record.user_id)
        elif record.user_role == 'vendor':
            user = Vendor.query.get(record.user_id)
        else:
            return jsonify({"error": "Invalid user role"}), 400
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        user.is_email_verified = True
        record.used = True
        record.used_at = datetime.utcnow()  # ✅ CONSISTENCY FIX: Set used_at for post-registration tokens too
        db.session.commit()  # CRITICAL: Commit immediately before response
        
        log_auth_event('email_verified', True, user.email, user.id, record.user_role, request.remote_addr)
        
        # ✅ UX IMPROVEMENT: Detect browser requests and redirect to success page
        accept_header = request.headers.get('Accept', '')
        if 'text/html' in accept_header:
            from flask import redirect
            redirect_url = f"{Config.APP_BASE_URL}/verify-email.html?token={token}&verified=1"
            return redirect(redirect_url), 302
        
        return jsonify({"success": True, "message": "Email verified successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Email verification error: {e}")
        return jsonify({"error": "Verification failed. Please try again."}), 500


# ✅ REMOVED: /email-verification-status-by-email endpoint
# No longer needed - frontend doesn't poll. Backend enforces verification at /register endpoint only.
# Email verification is a backend fact, not a frontend state.


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
