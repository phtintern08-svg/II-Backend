"""
Authentication Routes Blueprint
Handles login, registration, OTP, and authentication-related endpoints
"""
from flask import Blueprint, request, jsonify, send_from_directory, current_app, session
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import random
import time
import threading
import os
from datetime import datetime, timedelta

from app_pkg.models import db, Admin, Customer, Vendor, Rider, Support, OTPLog, EmailVerificationToken
from app_pkg.auth import generate_token, verify_token, login_required, get_token_from_request, send_verification_email
import secrets
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
        
        # ✅ SECURITY CHECK: Verify that email was actually verified via link click
        # This is the ONLY way to ensure email ownership
        verified_token = EmailVerificationToken.query.filter_by(
            email=email,
            user_role=role,
            used=True  # Token must be used (link was clicked)
        ).filter(
            EmailVerificationToken.expires_at > datetime.utcnow()  # Token must not be expired
        ).order_by(
            EmailVerificationToken.created_at.desc()
        ).first()
        
        if not verified_token:
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
        
        # Link pre-registration token to user if email was verified before registration
        if email_was_verified and verified_token:
            # Update the pre-registration token to link it to the new user
            # ✅ CRITICAL: Do NOT reset used = False. Token is a one-way fuse - once used, never reset.
            verified_token.user_id = user_id
            # verified_token.used stays True (it was already set to True when user clicked the link)
            db.session.commit()
            app_logger.info(f"Linked pre-registration token to user {user_id} (email: {email}, role: {role})")
        else:
            # Generate new verification token (for post-registration verification)
            token = secrets.token_urlsafe(48)
            expires_at = datetime.utcnow() + timedelta(minutes=30)
            
            verification_record = EmailVerificationToken(
                user_id=user_id,
                email=email,  # Also store email for consistency
                user_role=user_role,
                token=token,
                expires_at=expires_at,
                used=False
            )
            db.session.add(verification_record)
            db.session.commit()
            
            # Send verification email only if email wasn't verified before registration
            if not email_was_verified:
                try:
                    send_verification_email(email, token)
                except Exception as email_err:
                    app_logger.exception(f"Failed to send verification email: {email_err}")
                    # Don't fail registration if email fails - user can request resend later
                    # But log the error
        
        log_auth_event('register', True, email, user_id, user_role, request.remote_addr)
        
        # Return appropriate message based on whether email was pre-verified
        if email_was_verified:
            return jsonify({
                "success": True,
                "message": "Account created successfully. Your email was already verified."
            }), 201
        else:
            return jsonify({
                "success": True,
                "message": "Verification link sent to your email"
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
            return jsonify({"error": "Email already registered"}), 400
        
        # Check if there's already a valid unexpired token for this email+role
        existing_token = EmailVerificationToken.query.filter_by(
            email=email,
            user_role=role,
            used=False
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
                    "message": "Verification link sent"
                }), 200
            except Exception as email_err:
                app_logger.exception(f"Failed to resend verification email: {email_err}")
                return jsonify({"error": "Failed to send verification email"}), 500
        
        # Create new verification token (user_id=None for pre-registration)
        token = secrets.token_urlsafe(48)
        expires_at = datetime.utcnow() + timedelta(minutes=30)
        
        verification_record = EmailVerificationToken(
            user_id=None,  # None for pre-registration
            email=email,  # Store email for matching during registration
            user_role=role,
            token=token,
            expires_at=expires_at,
            used=False
        )
        
        db.session.add(verification_record)
        db.session.commit()
        
        # Send verification email
        try:
            send_verification_email(email, token)
            app_logger.info(f"Sent pre-registration verification email to {email} (role: {role})")
        except Exception as email_err:
            db.session.rollback()
            app_logger.exception(f"Failed to send verification email: {email_err}")
            return jsonify({"error": "Failed to send verification email"}), 500
        
        return jsonify({
            "success": True,
            "message": "Verification link sent"
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


@bp.route('/verify-email', methods=['GET'])
def verify_email():
    """
    GET /api/verify-email?token=<token>
    Verify user email using token from verification link
    """
    try:
        token = request.args.get('token')
        
        if not token:
            return jsonify({"error": "Token is required"}), 400
        
        # Find verification record
        record = EmailVerificationToken.query.filter_by(
            token=token,
            used=False
        ).first()
        
        if not record:
            return jsonify({"error": "Invalid or expired link"}), 400
        
        # Check expiration
        if record.expires_at < datetime.utcnow():
            return jsonify({"error": "Invalid or expired link"}), 400
        
        # Handle pre-registration verification (user_id is None)
        if record.user_id is None:
            # Pre-registration token - ONLY mark as used (this is the verification)
            # Do NOT create user, do NOT auto-login, do NOT set any other flags
            record.used = True
            db.session.commit()
            
            # ✅ Store verification in server-side session (refresh-proof)
            session['email_verified'] = True
            session['verified_email'] = record.email
            session['verified_role'] = record.user_role
            session.permanent = True  # Make session persistent
            
            app_logger.info(f"Pre-registration email verified: {record.email} (role: {record.user_role})")
            return jsonify({
                "success": True,
                "message": "Email verified successfully. You can now complete your registration.",
                "pre_registration": True,
                "email": record.email,  # Return email for frontend (backend-driven)
                "role": record.user_role  # Return role for frontend (backend-driven)
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
        db.session.commit()
        
        log_auth_event('email_verified', True, user.email, user.id, record.user_role, request.remote_addr)
        
        return jsonify({"success": True, "message": "Email verified successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Email verification error: {e}")
        return jsonify({"error": "Verification failed. Please try again."}), 500


@bp.route('/email-verification-status', methods=['GET'])
def email_verification_status():
    """
    GET /api/email-verification-status
    Check if email was verified in current session (for pre-registration)
    Returns verification status from server-side session (refresh-proof)
    """
    try:
        return jsonify({
            "verified": session.get('email_verified', False),
            "email": session.get('verified_email'),
            "role": session.get('verified_role')
        }), 200
    except Exception as e:
        app_logger.exception(f"Error checking email verification status: {e}")
        return jsonify({
            "verified": False,
            "email": None,
            "role": None
        }), 200


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
