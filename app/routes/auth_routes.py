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

from app.models import db, Admin, Customer, Vendor, Rider, Support, OTPLog
from app.auth import generate_token, verify_token, login_required
from app.validation import validate_request_data, LoginSchema, sanitize_text
from config import Config
from app.logger_config import app_logger, access_logger

# Create blueprint
bp = Blueprint('auth', __name__, url_prefix='/api')

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
    if Config.ENV == 'production':
        return f"https://{subdomain}.{Config.BASE_DOMAIN}{path}"
    else:
        return f"http://{subdomain}.{Config.BASE_DOMAIN}{path}"

# Helper function for logging auth events
def log_auth_event(event_type, success, identifier, user_id=None, role=None, ip_address=None, error=None):
    """Log authentication events"""
    try:
        log_entry = OTPLog(
            recipient=identifier,
            event_type=event_type,
            success=success,
            user_id=user_id,
            role=role,
            ip_address=ip_address,
            error_message=error,
            timestamp=datetime.utcnow()
        )
        db.session.add(log_entry)
        db.session.commit()
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
    try:
        # Validate JSON request
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        # Validate input data
        validated_data, errors = validate_request_data(LoginSchema, data)
        if errors:
            return jsonify({"error": "Validation failed", "details": errors}), 400
        
        identifier = validated_data['identifier']
        password = validated_data['password']
        
        # 1. Check Admin table (by username only)
        admin = Admin.query.filter_by(username=identifier).first()
        if admin and check_password_hash(admin.password_hash, password):
            token = generate_token(
                user_id=admin.id,
                role="admin",
                username=admin.username
            )
            log_auth_event('login', True, identifier, admin.id, 'admin', request.remote_addr)
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": "admin",
                "user_id": admin.id,
                "username": admin.username,
                "redirect_url": "/admin/home.html"
            }), 200
        
        # 2. Check Customer table (by email)
        customer = Customer.query.filter_by(email=identifier).first()
        if customer and check_password_hash(customer.password_hash, password):
            token = generate_token(
                user_id=customer.id,
                role="customer",
                username=customer.username,
                email=customer.email,
                phone=customer.phone
            )
            log_auth_event('login', True, identifier, customer.id, 'customer', request.remote_addr)
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": "customer",
                "user_id": customer.id,
                "username": customer.username,
                "email": customer.email,
                "phone": customer.phone,
                "redirect_url": "/customer/home.html"
            }), 200
        
        # 3. Check Vendor table (by email)
        vendor = Vendor.query.filter_by(email=identifier).first()
        if vendor and check_password_hash(vendor.password_hash, password):
            token = generate_token(
                user_id=vendor.id,
                role="vendor",
                username=vendor.username,
                email=vendor.email,
                phone=vendor.phone
            )
            log_auth_event('login', True, identifier, vendor.id, 'vendor', request.remote_addr)
            redirect_url = build_subdomain_url('vendor', '/home.html')
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": "vendor",
                "user_id": vendor.id,
                "business_name": vendor.business_name,
                "username": vendor.username,
                "email": vendor.email,
                "phone": vendor.phone,
                "redirect_url": redirect_url
            }), 200
        
        # 4. Check Rider table (by email)
        rider = Rider.query.filter_by(email=identifier).first()
        if rider and check_password_hash(rider.password_hash, password):
            token = generate_token(
                user_id=rider.id,
                role="rider",
                username=rider.name,
                email=rider.email,
                phone=rider.phone
            )
            log_auth_event('login', True, identifier, rider.id, 'rider', request.remote_addr)
            redirect_url = build_subdomain_url('rider', '/home.html')
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": "rider",
                "user_id": rider.id,
                "username": rider.name,
                "email": rider.email,
                "phone": rider.phone,
                "verification_status": rider.verification_status,
                "redirect_url": redirect_url
            }), 200
        
        # 5. Check Support table (by email)
        support = Support.query.filter_by(email=identifier).first()
        if support and check_password_hash(support.password_hash, password):
            token = generate_token(
                user_id=support.id,
                role="support",
                username=support.username,
                email=support.email,
                phone=support.phone
            )
            log_auth_event('login', True, identifier, support.id, 'support', request.remote_addr)
            return jsonify({
                "message": "Login successful",
                "token": token,
                "role": "support",
                "user_id": support.id,
                "username": support.username,
                "email": support.email,
                "phone": support.phone,
                "redirect_url": "/support/home.html"
            }), 200
        
        # No user found or invalid credentials
        log_auth_event('login', False, identifier, None, None, request.remote_addr, error="Invalid credentials")
        return jsonify({"error": "Invalid credentials"}), 401
        
    except Exception as e:
        app_logger.exception(f"Authentication error: {e}")
        return jsonify({"error": "Login failed. Please try again."}), 500


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
        
        return jsonify({
            "message": "Registration successful",
            "token": token,
            "user_id": new_customer.id,
            "redirect_url": "/customer/home.html"
        }), 201
        
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


@bp.route('/verify-token', methods=['POST'])
def verify_token_endpoint():
    """
    POST /api/verify-token
    Verify JWT token validity
    """
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Missing or invalid authorization header"}), 401
        
        token = auth_header.split(' ')[1]
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
@login_required
def logout():
    """
    POST /api/logout
    Logout user (client-side token removal)
    """
    # Since JWT is stateless, logout is handled client-side
    # This endpoint exists for logging purposes
    try:
        user_id = request.user_id
        role = request.role
        log_auth_event('logout', True, f"user_{user_id}", user_id, role, request.remote_addr)
        return jsonify({"message": "Logout successful"}), 200
    except Exception as e:
        app_logger.error(f"Logout error: {e}")
        return jsonify({"error": "Logout failed"}), 500
