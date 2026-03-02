"""
Support Routes Blueprint
Handles support endpoints like config, geocoding, categories, threads, and profile updates
"""
from flask import Blueprint, request, jsonify, current_app, send_file
from datetime import datetime
import os
import requests

from config import Config
from app_pkg.models import db, Category, Thread, Comment, Customer, Vendor, SupportUser, SupportTicket, SupportTicketCategory, Notification, ProductCatalog, MarketplaceProduct, CartProduct, ProductType
from werkzeug.security import check_password_hash, generate_password_hash
from app_pkg.auth import login_required, role_required
from app_pkg.schemas import category_schema, categories_schema, thread_schema, threads_schema, comment_schema, comments_schema
from app_pkg.logger_config import app_logger
from app_pkg.activity_logger import log_activity
from app_pkg.file_upload import get_file_path_from_db

# Create blueprint
bp = Blueprint('support', __name__)


@bp.route('/config', methods=['GET'])
@login_required
def get_config():
    """
    GET /api/config
    Get configuration values needed by frontend (e.g., Mappls API key)
    Only accessible to authenticated users
    """
    try:
        from config import Config
        # Use JS key for frontend map rendering (maps-js-key)
        api_key = Config.MAPPLS_JS_KEY or Config.MAPPLS_API_KEY
        
        return jsonify({
            "mappls": {
                "apiKey": api_key
            }
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get config error: {e}")
        return jsonify({"error": "Failed to retrieve config"}), 500


@bp.route('/reverse-geocode', methods=['GET'])
def reverse_geocode():
    """
    GET /api/reverse-geocode
    Reverse geocode coordinates to address
    Rate limited to prevent abuse of paid API
    Public endpoint - no authentication required
    """
    # Rate limit: 10 requests per minute per IP address
    # This prevents abuse of paid Mappls API
    if not hasattr(reverse_geocode, '_last_requests'):
        reverse_geocode._last_requests = {}
    
    # Use IP address for rate limiting instead of user_id (works for unauthenticated requests)
    # Proper IP extraction for production (handles Nginx, Cloudflare, load balancers)
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(',')[0].strip()
    if not client_ip:
        client_ip = 'unknown'
    current_time = datetime.utcnow().timestamp()
    
    # Clean old entries (older than 1 minute)
    reverse_geocode._last_requests = {
        ip: times for ip, times in reverse_geocode._last_requests.items()
        if any(t > current_time - 60 for t in times)
    }
    
    # 🔥 PRODUCTION SAFETY: Hard cap to prevent memory exhaustion under attack
    # If dict grows beyond 10,000 IPs, clear it (prevents unbounded memory growth)
    if len(reverse_geocode._last_requests) > 10000:
        ips_count = len(reverse_geocode._last_requests)
        reverse_geocode._last_requests.clear()
        app_logger.warning(
            "Cache cleared: rate_limiter (reverse_geocode) | ips_cleared=%d | cap=10000 | at=%s",
            ips_count,
            datetime.utcnow().isoformat()
        )
    
    # Get IP's request times in last minute
    ip_requests = reverse_geocode._last_requests.get(client_ip, [])
    ip_requests = [t for t in ip_requests if t > current_time - 60]
    
    if len(ip_requests) >= 10:
        return jsonify({
            "error": "Rate limit exceeded. Maximum 10 requests per minute.",
            "retry_after": max(1, int(60 - (current_time - ip_requests[0])))
        }), 429
    
    # Add current request
    ip_requests.append(current_time)
    reverse_geocode._last_requests[client_ip] = ip_requests
    
    try:
        lat = request.args.get('lat')
        lng = request.args.get('lng')
        
        if not lat or not lng:
            return jsonify({"error": "Latitude and longitude required"}), 400
        
        # Validate lat/lng are numeric
        try:
            lat_float = float(lat)
            lng_float = float(lng)
            if not (-90 <= lat_float <= 90) or not (-180 <= lng_float <= 180):
                return jsonify({"error": "Invalid latitude or longitude values"}), 400
        except ValueError:
            return jsonify({"error": "Latitude and longitude must be valid numbers"}), 400
        
        # Use REST key for backend reverse geocoding (not JS key)
        api_key = current_app.config.get('MAPPLS_REST_KEY') or os.environ.get('MAPPLS_REST_KEY')
        if not api_key:
            app_logger.error("MAPPLS_REST_KEY not configured")
            return jsonify({"error": "Map service not configured"}), 500
        
        url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/rev_geocode"
        params = {"lat": lat, "lng": lng}
        
        response = requests.get(url, params=params, timeout=10)
        if response.status_code != 200:
            # Log detailed error internally, but return generic message to client (prevent info leakage)
            app_logger.warning(f"Mappls reverse geocode API returned {response.status_code}: {response.text[:200]}")
            return jsonify({"error": "Map service error"}), 502
        
        data = response.json()
        
        # Validate response structure
        if not data or not isinstance(data, dict):
            app_logger.warning(f"Invalid Mappls response format: {type(data)}")
            return jsonify({"error": "Invalid response from map service"}), 502
        
        # Ensure response has results array (Mappls format)
        if "results" not in data:
            # Some Mappls responses might have different structure, try to normalize
            if "responseCode" in data and data.get("responseCode") != 200:
                # Log detailed error internally, but return generic message to client (prevent info leakage)
                error_msg = data.get("error", "Unknown error from map service")
                app_logger.warning(f"Mappls API error: {error_msg}")
                return jsonify({"error": "Map service error"}), 502
            # If no results key, wrap the response
            data = {"results": [data]} if data else {"results": []}
        
        return jsonify(data), 200
        
    except requests.exceptions.Timeout:
        app_logger.error("Mappls reverse geocode timeout")
        return jsonify({"error": "Request timeout. Please try again."}), 504
    except requests.exceptions.RequestException as e:
        app_logger.exception(f"Network error in reverse geocode: {e}")
        return jsonify({"error": "Network error connecting to map service"}), 503
    except Exception as e:
        app_logger.exception(f"Reverse geocode error: {e}")
        return jsonify({"error": "Failed to reverse geocode"}), 500


@bp.route('/geocode', methods=['GET'])
@login_required
def geocode():
    """
    GET /api/geocode
    Geocode address to coordinates
    """
    try:
        query = request.args.get('query')
        if not query:
            return jsonify({"error": "Query parameter required"}), 400
        
        # 🔥 PRODUCTION SAFETY: Restrict query length to prevent abuse/attacks
        if len(query) > 200:
            return jsonify({"error": "Query too long. Maximum 200 characters."}), 400
        
        # Use REST key for backend geocoding (Default Key)
        api_key = current_app.config.get('MAPPLS_REST_KEY') or os.environ.get('MAPPLS_REST_KEY')
        if not api_key:
            return jsonify({"error": "MAPPLS_REST_KEY environment variable is required"}), 500
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': request.host_url,
            'Origin': request.host_url.rstrip('/')
        }
        
        autosuggest_url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/autosuggest?query={query}"
        
        try:
            response = requests.get(autosuggest_url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'suggestedLocations' in data:
                    return jsonify({"copResults": data['suggestedLocations']}), 200
                return jsonify(data), 200
        except (requests.RequestException, ValueError):
            pass
        
        # Fallback to geo_code API
        geo_url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/geo_code?addr={query}"
        try:
            response = requests.get(geo_url, headers=headers, timeout=10)
            if response.status_code == 200:
                return jsonify(response.json()), 200
        except (requests.RequestException, ValueError):
            pass
        
        return jsonify({"error": "Geocoding service unavailable"}), 500
        
    except Exception as e:
        app_logger.exception(f"Geocode error: {e}")
        return jsonify({"error": "Failed to geocode"}), 500


@bp.route('/categories', methods=['GET'])
@login_required
def get_categories():
    """
    GET /api/categories
    Get all categories
    """
    try:
        all_categories = Category.query.all()
        return categories_schema.jsonify(all_categories), 200
    except Exception as e:
        app_logger.exception(f"Get categories error: {e}")
        return jsonify({"error": "Failed to retrieve categories"}), 500


@bp.route('/categories', methods=['POST'])
@login_required
@role_required(['admin'])
def create_category():
    """
    POST /api/categories
    Create a new category
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        name = data.get('name')
        description = data.get('description')
        
        if not name:
            return jsonify({"error": "Name required"}), 400
        
        new_category = Category(name=name, description=description)
        db.session.add(new_category)
        db.session.commit()
        
        return category_schema.jsonify(new_category), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Create category error: {e}")
        return jsonify({"error": "Failed to create category"}), 500


@bp.route('/threads', methods=['GET'])
@login_required
def get_threads():
    """
    GET /api/threads
    Get all threads
    """
    try:
        all_threads = Thread.query.order_by(Thread.created_at.desc()).all()
        return threads_schema.jsonify(all_threads), 200
    except Exception as e:
        app_logger.exception(f"Get threads error: {e}")
        return jsonify({"error": "Failed to retrieve threads"}), 500


@bp.route('/threads', methods=['POST'])
@login_required
def create_thread():
    """
    POST /api/threads
    Create a new thread
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        title = data.get('title')
        content = data.get('content')
        # SECURITY: Always use user_id from JWT, never from request body
        user_id = request.user_id
        category_id = data.get('category_id')
        
        if not title or not content:
            return jsonify({"error": "Title and content required"}), 400
        
        # 🔥 FIX: Validate content length to prevent abuse (50MB content attacks)
        if len(title) > 255:
            return jsonify({"error": "Title too long. Maximum 255 characters."}), 400
        
        if len(content) > 10000:  # Reasonable limit for thread content
            return jsonify({"error": "Content too long. Maximum 10,000 characters."}), 400
        
        new_thread = Thread(
            title=title,
            content=content,
            user_id=user_id,
            category_id=category_id
        )
        
        db.session.add(new_thread)
        db.session.commit()
        
        # Determine user type (customer or support)
        user_type = request.role if hasattr(request, 'role') else 'customer'
        # Log activity
        log_activity(
            user_id=user_id,
            user_type=user_type,
            action=f"Created support thread: {title[:50]}{'...' if len(title) > 50 else ''}",
            action_type="support_thread",
            entity_type="thread",
            entity_id=new_thread.id,
            details=content[:100] + '...' if len(content) > 100 else content
        )
        
        return thread_schema.jsonify(new_thread), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Create thread error: {e}")
        return jsonify({"error": "Failed to create thread"}), 500


@bp.route('/threads/<int:thread_id>', methods=['GET'])
@login_required
def get_thread(thread_id):
    """
    GET /api/threads/<thread_id>
    Get a specific thread
    """
    try:
        thread = Thread.query.get(thread_id)
        if not thread:
            return jsonify({"error": "Thread not found"}), 404
        return thread_schema.jsonify(thread), 200
    except Exception as e:
        app_logger.exception(f"Get thread error: {e}")
        return jsonify({"error": "Failed to retrieve thread"}), 500


@bp.route('/threads/<int:thread_id>/comments', methods=['GET'])
@login_required
def get_comments(thread_id):
    """
    GET /api/threads/<thread_id>/comments
    Get all comments for a thread
    """
    try:
        comments = Comment.query.filter_by(thread_id=thread_id).order_by(Comment.created_at.asc()).all()
        return comments_schema.jsonify(comments), 200
    except Exception as e:
        app_logger.exception(f"Get comments error: {e}")
        return jsonify({"error": "Failed to retrieve comments"}), 500


@bp.route('/threads/<int:thread_id>/comments', methods=['POST'])
@login_required
def add_comment(thread_id):
    """
    POST /api/threads/<thread_id>/comments
    Add a comment to a thread
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        content = data.get('content')
        # SECURITY: Always use user_id from JWT, never from request body
        user_id = request.user_id
        parent_comment_id = data.get('parent_comment_id')
        
        if not content:
            return jsonify({"error": "Content required"}), 400
        
        # 🔥 FIX: Validate content length to prevent abuse (50MB content attacks)
        if len(content) > 5000:  # Reasonable limit for comment content
            return jsonify({"error": "Content too long. Maximum 5,000 characters."}), 400
        
        # Verify thread exists
        thread = Thread.query.get(thread_id)
        if not thread:
            return jsonify({"error": "Thread not found"}), 404
        
        new_comment = Comment(
            content=content,
            user_id=user_id,
            thread_id=thread_id,
            parent_comment_id=parent_comment_id
        )
        
        db.session.add(new_comment)
        db.session.commit()
        
        # Determine user type (customer or support)
        user_type = request.role if hasattr(request, 'role') else 'customer'
        thread_title = thread.title[:30] + '...' if len(thread.title) > 30 else thread.title
        # Log activity
        log_activity(
            user_id=user_id,
            user_type=user_type,
            action=f"Added comment to thread: {thread_title}",
            action_type="support_comment",
            entity_type="thread",
            entity_id=thread_id,
            details=content[:100] + '...' if len(content) > 100 else content
        )
        
        return comment_schema.jsonify(new_comment), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Add comment error: {e}")
        return jsonify({"error": "Failed to add comment"}), 500


@bp.route('/update-profile', methods=['PUT'])
@login_required
def update_profile():
    """
    PUT /api/update-profile
    Update user profile (customer or vendor)
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        # SECURITY: Always use user_id and role from JWT, never from request body
        user_id = request.user_id
        role = request.role
        username = data.get('username')
        email = data.get('email')
        phone = data.get('phone')
        
        if role == 'customer':
            user = Customer.query.get(user_id)
        elif role == 'vendor':
            user = Vendor.query.get(user_id)
        else:
            return jsonify({"error": "Invalid role"}), 400
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Check if email already exists for another user (only if email is provided)
        if email:
            if role == 'customer':
                existing = Customer.query.filter(Customer.email == email, Customer.id != user_id).first()
            else:
                existing = Vendor.query.filter(Vendor.email == email, Vendor.id != user_id).first()
            
            if existing:
                return jsonify({"error": "Email already in use"}), 400
        
        # Check if phone already exists for another user (only if phone is provided)
        if phone:
            if role == 'customer':
                existing = Customer.query.filter(Customer.phone == phone, Customer.id != user_id).first()
            else:
                existing = Vendor.query.filter(Vendor.phone == phone, Vendor.id != user_id).first()
            
            if existing:
                return jsonify({"error": "Phone number already in use"}), 400
        
        # Update user data
        if username:
            user.username = username
        if email:
            user.email = email
        if phone:
            user.phone = phone
        
        db.session.commit()
        
        return jsonify({
            "message": "Profile updated successfully",
            "username": user.username,
            "email": user.email,
            "phone": user.phone
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update profile error: {e}")
        return jsonify({"error": "Failed to update profile"}), 500


@bp.route('/support/profile', methods=['GET'])
@login_required
@role_required(['support'])
def get_support_profile():
    """
    GET /api/support/profile
    Get support profile information
    """
    try:
        support = SupportUser.query.get(request.user_id)
        if not support:
            return jsonify({"error": "Support user not found"}), 404
        
        support_data = {
            "id": support.id,
            "name": support.name,
            "email": support.email,
            "phone": support.phone,
            "role": support.role,
            "is_active": support.is_active,
            "created_at": support.created_at.isoformat() if support.created_at else None
        }
        
        return jsonify(support_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get support profile error: {e}")
        return jsonify({"error": "Failed to retrieve profile"}), 500


@bp.route('/support/profile', methods=['PUT'])
@login_required
@role_required(['support'])
def update_support_profile():
    """
    PUT /api/support/profile
    Update support profile information
    """
    try:
        data = request.get_json()
        support = SupportUser.query.get(request.user_id)
        
        if not support:
            return jsonify({"error": "Support user not found"}), 404
        
        # Update allowed fields (SupportUser doesn't have username, only name)
        allowed_fields = ['name', 'phone']
        for field in allowed_fields:
            if field in data:
                setattr(support, field, data[field])
        
        support.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"message": "Profile updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update support profile error: {e}")
        return jsonify({"error": "Failed to update profile"}), 500


@bp.route('/support/notifications', methods=['GET'])
@login_required
@role_required(['support'])
def get_support_notifications():
    """
    GET /api/support/notifications
    Get support notifications
    """
    try:
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        query = Notification.query.filter_by(user_id=request.user_id, user_type='support')
        
        if unread_only:
            query = query.filter_by(is_read=False)
        
        notifs = query.order_by(Notification.created_at.desc()).limit(50).all()
        
        return jsonify([{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'type': n.type,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat() if n.created_at else None
        } for n in notifs]), 200
        
    except Exception as e:
        app_logger.exception(f"Get support notifications error: {e}")
        return jsonify({"error": "Failed to retrieve notifications"}), 500


@bp.route('/support/notifications/<int:notif_id>/read', methods=['POST'])
@login_required
@role_required(['support'])
def mark_support_notification_read(notif_id):
    """
    POST /api/support/notifications/<notif_id>/read
    Mark notification as read
    """
    try:
        notif = Notification.query.get(notif_id)
        if not notif:
            return jsonify({"error": "Notification not found"}), 404
        
        if notif.user_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        notif.is_read = True
        db.session.commit()
        
        return jsonify({"message": "Notification marked as read"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Mark notification read error: {e}")
        return jsonify({"error": "Failed to mark notification as read"}), 500


@bp.route('/support/change-password', methods=['PUT'])
@login_required
@role_required(['support'])
def change_support_password():
    """
    PUT /api/support/change-password
    Change support password
    """
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({"error": "Current password and new password are required"}), 400
        
        support = SupportUser.query.get(request.user_id)
        if not support:
            return jsonify({"error": "Support user not found"}), 404
        
        if not check_password_hash(support.password_hash, current_password):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        support.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({"message": "Password changed successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Change password error: {e}")
        return jsonify({"error": "Failed to change password"}), 500


@bp.route('/change-password', methods=['PUT'])
@login_required
def change_password():
    """
    PUT /api/change-password
    Change user password (customer or vendor) - Legacy endpoint for backward compatibility
    """
    try:
        data = request.get_json()
        # SECURITY: Always use user_id and role from JWT, never from request body
        user_id = request.user_id
        role = request.role
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not all([current_password, new_password]):
            return jsonify({"error": "Current password and new password are required"}), 400
        
        if role == 'customer':
            user = Customer.query.get(user_id)
        elif role == 'vendor':
            user = Vendor.query.get(user_id)
        else:
            return jsonify({"error": "Invalid role"}), 400
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if not check_password_hash(user.password_hash, current_password):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({"message": "Password changed successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Change password error: {e}")
        return jsonify({"error": "Failed to change password"}), 500


@bp.route('/estimate-price', methods=['POST'])
@login_required
@role_required(['customer'])  # Restrict to customers only - pricing logic should not be exposed
def estimate_price():
    """
    POST /api/estimate-price
    Estimate price for a product configuration
    """
    try:
        data = request.get_json() or {}  # Guard against None
        
        # 🔥 DEBUG: Log raw payload to diagnose 400 errors
        app_logger.info(f"RAW ESTIMATE PAYLOAD RECEIVED: {data}")
        
        # Normalization helper functions
        def normalize_text(val):
            """Normalize text fields to lowercase for consistent matching"""
            if not val:
                return None
            if isinstance(val, str):
                return val.strip().lower()
            return val
        
        def normalize_size(val):
            """Normalize size to uppercase for consistent matching"""
            if not val:
                return None
            if isinstance(val, str):
                return val.strip().upper()
            return val
        
        # Normalize all incoming values (lowercase for text, uppercase for size)
        product_type = normalize_text(data.get('product_type'))
        category = normalize_text(data.get('category'))
        size = normalize_size(data.get('size'))  # 🔥 FIX: size was never defined - this was causing NameError or validation to always fail
        
        # 🔥 FIX: Handle empty string neck_type properly (frontend might send "" which should become None, not "none")
        neck_type_raw = data.get('neck_type')
        neck_type_normalized = normalize_text(neck_type_raw) if (neck_type_raw and neck_type_raw.strip()) else None
        
        # Validate required fields BEFORE defaulting neck_type (prevents misleading validation)
        # 🔥 DEBUG: Log received values to diagnose 400 errors
        if not product_type or not category or not size:
            app_logger.warning(
                f"Estimate validation failed - missing required fields: "
                f"product_type={product_type}, category={category}, size={size}, "
                f"raw_data={data}"
            )
            return jsonify({
                "error": "Product type, category, and size are required",
                "received": {
                    "product_type": product_type,
                    "category": category,
                    "size": size
                }
            }), 400
        
        # If neck_type is None, default to "none" for query matching (DB stores "none" as string)
        if neck_type_normalized is None:
            neck_type = "none"
        else:
            neck_type = neck_type_normalized
            
        fabric = normalize_text(data.get('fabric')) if data.get('fabric') else None
        
        # Debug logging
        app_logger.info(
            f"Estimate price request: product_type={product_type}, category={category}, "
            f"neck_type={neck_type}, fabric={fabric}, size={size}"
        )
        
        # Use correct import path
        from app_pkg.models import ProductCatalog
        
        # Build query with CASE-INSENSITIVE match (bulletproof against DB case variations)
        # All text fields normalized to lowercase, size to uppercase
        # If fabric is not provided, don't filter by fabric (match any fabric for that product)
        from sqlalchemy import func
        
        query = ProductCatalog.query.filter(
            func.lower(ProductCatalog.product_type) == product_type,
            func.lower(ProductCatalog.category) == category,
            func.lower(ProductCatalog.neck_type) == neck_type,  # lowercase "none" if not provided
            ProductCatalog.size == size,
            ProductCatalog.vendor_count > 0  # Only match products with vendors
        )
        
        # Only filter by fabric if it's provided
        if fabric:
            query = query.filter(func.lower(ProductCatalog.fabric) == fabric)
        # If fabric not provided, don't filter - match any fabric
        
        product = query.first()
        
        # Debug logging for query result
        if product:
            app_logger.info(
                f"Product found: id={product.id}, final_price={product.final_price}, "
                f"average_price={product.average_price}, vendor_count={product.vendor_count}"
            )
        else:
            app_logger.warning(
                f"No product found matching: product_type={product_type}, category={category}, "
                f"neck_type={neck_type}, fabric={fabric}, size={size}"
            )
        
        if product:
            # Calculate final_price if not set
            final_price = float(product.final_price) if product.final_price else (float(product.average_price) * 1.30 if product.average_price else 0)
            return jsonify({
                "estimated_price": final_price,
                "vendor_count": product.vendor_count,
                "found": True
            }), 200
        else:
            # Try to find match with same Product, Category, Neck Type AND Size (relaxed matching)
            # Use case-insensitive matching for consistency
            # Include neck_type for more accurate relaxed matching
            query_size = ProductCatalog.query.filter(
                func.lower(ProductCatalog.product_type) == product_type,
                func.lower(ProductCatalog.category) == category,
                func.lower(ProductCatalog.neck_type) == neck_type,  # Match neck_type in relaxed too
                ProductCatalog.vendor_count > 0
            )
            
            if size:
                query_size = query_size.filter(ProductCatalog.size == size)
            
            similar_by_size = query_size.all()
            
            if similar_by_size:
                # Calculate average final_price
                prices = []
                for p in similar_by_size:
                    final_price = float(p.final_price) if p.final_price else (float(p.average_price) * 1.30 if p.average_price else 0)
                    if final_price > 0:
                        prices.append(final_price)
                
                if prices:
                    avg = sum(prices) / len(prices)
                    return jsonify({
                        "estimated_price": round(avg, 2),
                        "vendor_count": len(similar_by_size),
                        "found": False,
                        "message": f"Estimate based on size {size}"
                    }), 200
            
            # Fallback: Average of all items in this category with same neck_type
            # Use case-insensitive matching for consistency
            # Include neck_type in final fallback for better UX integrity
            similar = ProductCatalog.query.filter(
                func.lower(ProductCatalog.product_type) == product_type,
                func.lower(ProductCatalog.category) == category,
                func.lower(ProductCatalog.neck_type) == neck_type,  # Match neck_type in final fallback too
                ProductCatalog.vendor_count > 0
            ).all()
            
            if similar:
                prices = []
                for p in similar:
                    final_price = float(p.final_price) if p.final_price else (float(p.average_price) * 1.30 if p.average_price else 0)
                    if final_price > 0:
                        prices.append(final_price)
                
                if prices:
                    avg = sum(prices) / len(prices)
                    return jsonify({
                        "estimated_price": round(avg, 2),
                        "vendor_count": len(similar),
                        "found": False,
                        "message": "Estimate based on category average"
                    }), 200
            
            return jsonify({
                "estimated_price": 0,
                "vendor_count": 0,
                "found": False,
                "message": "No quotations found for this configuration"
            }), 200
            
    except Exception as e:
        app_logger.exception(f"Estimate price error: {e}")
        return jsonify({"error": "Failed to estimate price"}), 500


@bp.route('/product-price/<int:product_id>', methods=['GET'])
@login_required
@role_required(['customer', 'vendor', 'admin'])
def get_product_price(product_id):
    """
    GET /api/product-price/<product_id>
    Get final price for a specific product
    """
    try:
        from app_pkg.models import ProductCatalog, compute_price_splits
        product = ProductCatalog.query.get(product_id)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        final_price = float(product.final_price) if product.final_price else 0
        splits = compute_price_splits(final_price)
        
        return jsonify({
            'id': product.id,
            'product_type': product.product_type,
            'category': product.category,
            'final_price': final_price,
            'average_price': float(product.average_price) if product.average_price else 0,
            'vendor_pay': splits['vendor_pay'],
            'platform_pay': splits['platform_pay'],
            'rider_pay': splits['rider_pay'],
            'support_pay': splits['support_pay'],
            'vendor_count': product.vendor_count or 0
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get product price error: {e}")
        return jsonify({"error": "Failed to retrieve product price"}), 500


@bp.route('/product-catalog', methods=['GET'])
@login_required
@role_required(['admin', 'customer', 'vendor'])
def get_product_catalog():
    """
    GET /api/product-catalog
    Get all products in catalog (aggregated from approved quotations)
    Accessible to admin, customer, and vendor
    
    Query parameters:
    - product_type: Filter by product type
    - category: Filter by category
    - size: Filter by size
    - grouped: If 'true', returns grouped view (product_type, category, neck_type, fabric) with size arrays
    """
    try:
        from sqlalchemy import text
        
        # Get query parameters
        product_type = request.args.get('product_type')
        category = request.args.get('category')
        size = request.args.get('size')
        grouped = request.args.get('grouped', 'false').lower() == 'true'
        
        # 🔥 PRODUCTION SAFETY: Build SQL safely (never interpolate user input into SQL string)
        # Base SQL with static WHERE condition
        base_where = "vendor_count > 0"
        params = {}
        
        # Add conditions safely (each condition is static string, params bound separately)
        if product_type:
            base_where += " AND LOWER(product_type) = LOWER(:product_type)"
            params['product_type'] = product_type
        if category:
            base_where += " AND LOWER(category) = LOWER(:category)"
            params['category'] = category
        if size:
            base_where += " AND size = :size"  # Size is case-sensitive (uppercase)
            params['size'] = size
        
        if grouped:
            # Grouped view: group by product_type, category, neck_type, fabric
            # Show sizes as arrays with price ranges
            sql = text("""
                SELECT
                    product_type,
                    category,
                    neck_type,
                    fabric,
                    notes,
                    MIN(final_price) AS min_price,
                    MAX(final_price) AS max_price,
                    AVG(average_price) AS avg_price,
                    SUM(vendor_count) AS total_vendors,
                    GROUP_CONCAT(DISTINCT size ORDER BY size SEPARATOR ',') AS sizes,
                    MAX(updated_at) AS updated_at
                FROM product_catalog
                WHERE """ + base_where + """
                GROUP BY product_type, category, neck_type, fabric, notes
                ORDER BY updated_at DESC
            """)
            
            rows = db.session.execute(sql, params).mappings().all()
            
            from app_pkg.models import compute_price_splits
            result = []
            for row in rows:
                min_price = float(row['min_price']) if row['min_price'] else 0.0
                max_price = float(row['max_price']) if row['max_price'] else 0.0
                avg_final = (min_price + max_price) / 2 if (min_price or max_price) else 0.0
                splits = compute_price_splits(avg_final)
                result.append({
                    'product_type': row['product_type'],
                    'category': row['category'],
                    'neck_type': row['neck_type'],
                    'fabric': row['fabric'],
                    'notes': row['notes'],
                    'min_price': min_price,
                    'max_price': max_price,
                    'avg_price': float(row['avg_price']) if row['avg_price'] else 0.0,
                    'vendor_pay': splits['vendor_pay'],
                    'platform_pay': splits['platform_pay'],
                    'rider_pay': splits['rider_pay'],
                    'support_pay': splits['support_pay'],
                    'total_vendors': row['total_vendors'] or 0,
                    'sizes': row['sizes'].split(',') if row['sizes'] else [],
                    'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None
                })
        else:
            # Detailed view: all rows with individual sizes
            sql = text("""
                SELECT
                    id,
                    product_type,
                    category,
                    neck_type,
                    fabric,
                    size,
                    average_price,
                    final_price,
                    vendor_count,
                    notes,
                    updated_at
                FROM product_catalog
                WHERE """ + base_where + """
                ORDER BY updated_at DESC
            """)
            
            rows = db.session.execute(sql, params).mappings().all()
            
            from app_pkg.models import compute_price_splits
            result = []
            for row in rows:
                final_price = float(row['final_price']) if row['final_price'] else 0.0
                splits = compute_price_splits(final_price)
                result.append({
                    'id': row['id'],
                    'product_type': row['product_type'],
                    'category': row['category'],
                    'neck_type': row['neck_type'],
                    'fabric': row['fabric'],
                    'size': row['size'],
                    'average_price': float(row['average_price']) if row['average_price'] else 0.0,
                    'final_price': final_price,
                    'vendor_pay': splits['vendor_pay'],
                    'platform_pay': splits['platform_pay'],
                    'rider_pay': splits['rider_pay'],
                    'support_pay': splits['support_pay'],
                    'vendor_count': row['vendor_count'] or 0,
                    'notes': row['notes'],
                    'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None
                })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get product catalog error: {e}")
        return jsonify({"error": "Failed to retrieve product catalog"}), 500


@bp.route('/products', methods=['GET'])
def get_products():
    """
    GET /api/products?product_type=<type>
    Get all APPROVED cart products (public endpoint - no auth required)
    Customers only see APPROVED products (PENDING and REJECTED are hidden)
    
    Query Parameters:
    - product_type (optional): Filter by product type name (e.g., 'T-Shirt', 'Hoodie')
    
    Returns product listing with:
    - Product image
    - Product name
    - Cost price
    - Available sizes
    - Product type
    - Category
    """
    try:
        import json
        
        product_type = request.args.get('product_type', '').strip()
        
        # Build query - always filter by approved status
        query = CartProduct.query.filter_by(status='approved')
        
        # Filter by product_type if provided
        if product_type:
            query = query.filter(CartProduct.product_type == product_type)
        
        products = query.order_by(CartProduct.created_at.desc()).all()
        
        products_list = []
        for p in products:
            # Parse JSON strings to arrays (MySQL JSON columns return as strings)
            sizes = p.sizes
            if isinstance(sizes, str):
                try:
                    sizes = json.loads(sizes)
                except (json.JSONDecodeError, TypeError):
                    sizes = []
            if not isinstance(sizes, list):
                sizes = []
            
            images = p.images
            if isinstance(images, str):
                try:
                    images = json.loads(images)
                except (json.JSONDecodeError, TypeError):
                    images = []
            if not isinstance(images, list):
                images = []
            
            # Get first image or default
            image_url = None
            if images and len(images) > 0:
                image_url = f"/api/uploads/{images[0]}"
            else:
                image_url = "https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?q=80"
            
            # Format all images for gallery
            formatted_images = []
            if images and len(images) > 0:
                formatted_images = [f"/api/uploads/{img}" for img in images]
            else:
                formatted_images = [image_url]
            
            products_list.append({
                "id": f"cp_{p.id}",
                "name": p.product_name,
                "description": p.description or "",
                "price": float(p.cost_price) if p.cost_price else 0,
                "product_type": p.product_type or 'Unknown',
                "category": p.category or 'N/A',
                "image": image_url,
                "images": formatted_images,  # Array of all images for gallery
                "sizes": sizes,
                "colors": []  # Cart products don't have colors, but keeping for compatibility
            })
        
        return jsonify({
            "products": products_list,
            "count": len(products_list)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get products error: {e}")
        return jsonify({"error": "Failed to retrieve products"}), 500


@bp.route('/product-types', methods=['GET'])
def get_product_types():
    """
    GET /api/product-types
    Get all active product types (standardized categories)
    Public endpoint - no auth required
    Used by vendors when creating products and customers when browsing by category
    """
    try:
        product_types = ProductType.query.filter_by(is_active=True).order_by(ProductType.name).all()
        
        types_list = []
        for pt in product_types:
            types_list.append({
                "id": pt.id,
                "name": pt.name,
                "slug": pt.slug
            })
        
        return jsonify(types_list), 200
        
    except Exception as e:
        app_logger.exception(f"Get product types error: {e}")
        return jsonify({"error": "Failed to retrieve product types"}), 500


@bp.route('/cart-products', methods=['GET'])
def get_cart_products():
    """
    GET /api/cart-products?category=<slug>
    Get all APPROVED cart products (public endpoint - no auth required)
    Customers only see APPROVED products (PENDING and REJECTED are hidden)
    
    Query Parameters:
    - category (optional): Filter by product type slug (e.g., 't-shirt', 'hoodie')
    
    Returns product listing with:
    - Product images
    - Product name
    - Cost price
    - Available sizes
    - Vendor information
    - Product type name and slug
    """
    try:
        category_slug = request.args.get('category', '').strip()
        
        # Build query - always filter by approved status
        query = CartProduct.query.filter_by(status='approved')
        
        # Filter by category slug if provided
        if category_slug:
            # Join with product_types to filter by slug
            query = query.join(ProductType, CartProduct.product_type_id == ProductType.id).filter(
                ProductType.slug == category_slug,
                ProductType.is_active == True
            )
        
        products = query.order_by(CartProduct.created_at.desc()).all()
        
        products_list = []
        for p in products:
            # Parse JSON strings to arrays (MySQL JSON columns return as strings)
            sizes = p.sizes
            if isinstance(sizes, str):
                try:
                    import json
                    sizes = json.loads(sizes)
                except (json.JSONDecodeError, TypeError):
                    sizes = []
            if not isinstance(sizes, list):
                sizes = []
            
            images = p.images
            if isinstance(images, str):
                try:
                    import json
                    images = json.loads(images)
                except (json.JSONDecodeError, TypeError):
                    images = []
            if not isinstance(images, list):
                images = []
            
            # Get vendor info
            vendor = Vendor.query.get(p.vendor_id)
            vendor_name = vendor.business_name if vendor else f"Vendor #{p.vendor_id}"
            
            # Get product type info
            product_type = p.product_type_ref if hasattr(p, 'product_type_ref') and p.product_type_ref else None
            product_type_name = product_type.name if product_type else (p.product_type or 'Unknown')
            product_type_slug = product_type.slug if product_type else None
            
            products_list.append({
                "id": f"cp_{p.id}",
                "name": p.product_name,
                "product_type": product_type_name,
                "product_type_slug": product_type_slug,
                "category": p.category or 'N/A',
                "description": p.description or "",
                "cost_price": float(p.cost_price) if p.cost_price else 0,
                "sizes": sizes,
                "images": images,
                "vendor_id": p.vendor_id,
                "vendor_name": vendor_name,
                "created_at": p.created_at.isoformat() if p.created_at else None
            })
        
        return jsonify({
            "products": products_list,
            "count": len(products_list)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get cart products error: {e}")
        return jsonify({"error": "Failed to retrieve cart products"}), 500


@bp.route('/uploads/<path:file_path>', methods=['GET'])
def serve_uploaded_file(file_path):
    """
    GET /api/uploads/<file_path>
    Serve uploaded files (images, documents, etc.)
    Public endpoint - no auth required for viewing uploaded content
    """
    try:
        # Security: Prevent path traversal attacks
        if '..' in file_path or file_path.startswith('/'):
            return jsonify({"error": "Invalid file path"}), 400
        
        # Get absolute file path
        upload_folder = current_app.config.get('UPLOAD_FOLDER')
        if not upload_folder:
            return jsonify({"error": "Upload folder not configured"}), 500
        
        absolute_path = os.path.join(upload_folder, file_path)
        
        # Verify file exists
        if not os.path.exists(absolute_path) or not os.path.isfile(absolute_path):
            return jsonify({"error": "File not found"}), 404
        
        # Determine MIME type from extension
        import mimetypes
        mimetype, _ = mimetypes.guess_type(absolute_path)
        if not mimetype:
            mimetype = 'application/octet-stream'
        
        return send_file(
            absolute_path,
            mimetype=mimetype,
            as_attachment=False
        )
        
    except Exception as e:
        app_logger.exception(f"Serve uploaded file error: {e}")
        return jsonify({"error": "Failed to serve file"}), 500


# ============================================================================
# Support Ticket Routes for Customer Frontend
# ============================================================================

@bp.route('/tickets/customer/<int:customer_id>', methods=['GET'])
def get_customer_tickets(customer_id):
    """
    GET /api/tickets/customer/<customer_id>
    Get all tickets for a customer
    Returns empty array if no tickets exist (not 404)
    """
    try:
        # Query tickets for this customer
        tickets = SupportTicket.query.filter_by(
            user_id=customer_id,
            user_type='customer'
        ).order_by(SupportTicket.created_at.desc()).all()
        
        # Format tickets for frontend
        tickets_data = []
        for ticket in tickets:
            # Use ticket_number as ticket_id, fallback to id
            ticket_id = ticket.ticket_number or str(ticket.id)
            
            tickets_data.append({
                'ticket_id': ticket_id,
                'id': ticket.id,
                'subject': ticket.subject,
                'category': ticket.category.name if ticket.category else 'Other',
                'status': ticket.status,
                'priority': ticket.priority,
                'created_at': ticket.created_at.isoformat() if ticket.created_at else None,
                'updated_at': ticket.updated_at.isoformat() if ticket.updated_at else None,
                'resolved_at': ticket.resolved_at.isoformat() if ticket.resolved_at else None,
                'sla_deadline': getattr(ticket, 'sla_deadline', None),
                'sla_due_at': getattr(ticket, 'sla_due_at', None) or getattr(ticket, 'sla_deadline', None),
                'assigned_to': ticket.assigned_to,
                'order_id': getattr(ticket, 'order_id', None),
                'vendor_id': getattr(ticket, 'vendor_id', None),
                'rider_id': getattr(ticket, 'rider_id', None),
                'issue_type': getattr(ticket, 'issue_type', None)
            })
        
        # Return empty array if no tickets (not 404)
        return jsonify(tickets_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get customer tickets error: {e}")
        # Return empty array on error instead of 404
        return jsonify([]), 200


@bp.route('/tickets/<ticket_id>', methods=['GET'])
def get_ticket_details(ticket_id):
    """
    GET /api/tickets/<ticket_id>
    Get ticket details by ID or ticket number
    """
    try:
        # Try to find by ticket_number first, then by id (handle both string and int)
        try:
            ticket_id_int = int(ticket_id)
        except ValueError:
            ticket_id_int = None
        
        if ticket_id_int:
            ticket = SupportTicket.query.filter(
                (SupportTicket.ticket_number == ticket_id) | 
                (SupportTicket.id == ticket_id_int)
            ).first()
        else:
            ticket = SupportTicket.query.filter(
                SupportTicket.ticket_number == ticket_id
            ).first()
        
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        
        ticket_data = {
            'ticket_id': ticket.ticket_number or f"TKT-{ticket.id}",
            'id': ticket.id,
            'subject': ticket.subject,
            'description': ticket.description,
            'category': ticket.category.name if ticket.category else 'Other',
            'status': ticket.status,
            'priority': ticket.priority,
            'created_at': ticket.created_at.isoformat() if ticket.created_at else None,
            'updated_at': ticket.updated_at.isoformat() if ticket.updated_at else None,
            'resolved_at': ticket.resolved_at.isoformat() if ticket.resolved_at else None,
            'sla_deadline': ticket.sla_deadline.isoformat() if ticket.sla_deadline else None,
            'assigned_to': ticket.assigned_to,
            'order_id': getattr(ticket, 'order_id', None),
            'vendor_id': getattr(ticket, 'vendor_id', None),
            'rider_id': getattr(ticket, 'rider_id', None),
            'issue_type': getattr(ticket, 'issue_type', None)
        }
        
        return jsonify(ticket_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get ticket details error: {e}")
        return jsonify({"error": "Failed to retrieve ticket"}), 500


@bp.route('/tickets/<ticket_id>/messages', methods=['GET'])
def get_ticket_messages(ticket_id):
    """
    GET /api/tickets/<ticket_id>/messages
    Get all messages for a ticket
    Returns empty array if no messages exist
    """
    try:
        # Find ticket (handle both string and int)
        try:
            ticket_id_int = int(ticket_id)
        except ValueError:
            ticket_id_int = None
        
        if ticket_id_int:
            ticket = SupportTicket.query.filter(
                (SupportTicket.ticket_number == ticket_id) | 
                (SupportTicket.id == ticket_id_int)
            ).first()
        else:
            ticket = SupportTicket.query.filter(
                SupportTicket.ticket_number == ticket_id
            ).first()
        
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        
        # Get messages from Thread table (ticket_id foreign key)
        messages = Thread.query.filter_by(ticket_id=ticket.id).order_by(Thread.created_at.asc()).all()
        
        messages_data = []
        for msg in messages:
            # Get comments for this thread
            comments = Comment.query.filter_by(thread_id=msg.id).order_by(Comment.created_at.asc()).all()
            
            # Add thread as first message
            messages_data.append({
                'id': msg.id,
                'message': msg.content,
                'sender_id': msg.user_id,
                'sender_type': 'customer',  # Assuming thread is from customer
                'sender_name': 'Customer',
                'created_at': msg.created_at.isoformat() if msg.created_at else None,
                'timestamp': msg.created_at.isoformat() if msg.created_at else None,
                'is_read': getattr(msg, 'is_read', False)
            })
            
            # Add comments as messages
            for comment in comments:
                messages_data.append({
                    'id': comment.id,
                    'message': comment.content,
                    'sender_id': comment.user_id,
                    'sender_type': 'support_agent',  # Comments are typically from support
                    'sender_name': 'Support Agent',
                    'created_at': comment.created_at.isoformat() if comment.created_at else None,
                    'timestamp': comment.created_at.isoformat() if comment.created_at else None,
                    'is_read': getattr(comment, 'is_read', False)
                })
        
        # Return empty array if no messages (not 404)
        return jsonify(messages_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get ticket messages error: {e}")
        # Return empty array on error instead of 404
        return jsonify([]), 200


@bp.route('/tickets/<ticket_id>/messages', methods=['POST'])
def create_ticket_message(ticket_id):
    """
    POST /api/tickets/<ticket_id>/messages
    Create a new message in a ticket
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        # Find ticket (handle both string and int)
        try:
            ticket_id_int = int(ticket_id)
        except ValueError:
            ticket_id_int = None
        
        if ticket_id_int:
            ticket = SupportTicket.query.filter(
                (SupportTicket.ticket_number == ticket_id) | 
                (SupportTicket.id == ticket_id_int)
            ).first()
        else:
            ticket = SupportTicket.query.filter(
                SupportTicket.ticket_number == ticket_id
            ).first()
        
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        
        customer_id = data.get('customer_id')
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({"error": "Message is required"}), 400
        
        if not customer_id:
            return jsonify({"error": "Customer ID is required"}), 400
        
        # Verify customer owns this ticket
        if ticket.user_id != customer_id or ticket.user_type != 'customer':
            return jsonify({"error": "Unauthorized"}), 403
        
        # Create message as Thread
        new_thread = Thread(
            title=ticket.subject,
            content=message,
            user_id=customer_id,
            ticket_id=ticket.id
        )
        
        db.session.add(new_thread)
        db.session.commit()
        
        # Update ticket updated_at
        ticket.updated_at = datetime.utcnow()
        
        # Update first_response_at if this is first message from customer
        if not hasattr(ticket, 'first_response_at') or not ticket.first_response_at:
            try:
                ticket.first_response_at = datetime.utcnow()
            except:
                pass  # Column might not exist yet
        
        db.session.commit()
        
        return jsonify({
            "success": True,
            "message_id": new_thread.id,
            "ticket_id": ticket.ticket_number or f"TKT-{ticket.id}"
        }), 201
        
    except Exception as e:
        app_logger.exception(f"Create ticket message error: {e}")
        db.session.rollback()
        return jsonify({"error": "Failed to create message"}), 500


@bp.route('/tickets/unread-count', methods=['GET'])
def get_unread_count():
    """
    GET /api/tickets/unread-count?customer_id=<id>
    Get unread message count for a customer
    Returns 0 if no unread messages (not 404)
    """
    try:
        customer_id = request.args.get('customer_id', type=int)
        
        if not customer_id:
            return jsonify({"error": "customer_id parameter required"}), 400
        
        # Get customer tickets
        tickets = SupportTicket.query.filter_by(
            user_id=customer_id,
            user_type='customer'
        ).all()
        
        if not tickets:
            return jsonify({"count": 0}), 200
        
        # Count unread messages
        unread_count = 0
        
        for ticket in tickets:
            # Get messages for this ticket
            messages = Thread.query.filter_by(ticket_id=ticket.id).all()
            
            for msg in messages:
                # Check if message is read (default to False if column doesn't exist)
                is_read = getattr(msg, 'is_read', False)
                if not is_read:
                    # Only count messages not from customer
                    if msg.user_id != customer_id:
                        unread_count += 1
                
                # Check comments
                comments = Comment.query.filter_by(thread_id=msg.id).all()
                for comment in comments:
                    is_read = getattr(comment, 'is_read', False)
                    if not is_read and comment.user_id != customer_id:
                        unread_count += 1
        
        return jsonify({"count": unread_count}), 200
        
    except Exception as e:
        app_logger.exception(f"Get unread count error: {e}")
        # Return 0 on error instead of 404
        return jsonify({"count": 0}), 200


@bp.route('/tickets/<ticket_id>/mark-read', methods=['POST'])
def mark_ticket_read(ticket_id):
    """
    POST /api/tickets/<ticket_id>/mark-read
    Mark all messages in a ticket as read
    """
    try:
        data = request.get_json() or {}
        customer_id = data.get('customer_id')
        
        if not customer_id:
            return jsonify({"error": "customer_id required"}), 400
        
        # Find ticket (handle both string and int)
        try:
            ticket_id_int = int(ticket_id)
        except ValueError:
            ticket_id_int = None
        
        if ticket_id_int:
            ticket = SupportTicket.query.filter(
                (SupportTicket.ticket_number == ticket_id) | 
                (SupportTicket.id == ticket_id_int)
            ).first()
        else:
            ticket = SupportTicket.query.filter(
                SupportTicket.ticket_number == ticket_id
            ).first()
        
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
        
        # Verify customer owns this ticket
        if ticket.user_id != customer_id or ticket.user_type != 'customer':
            return jsonify({"error": "Unauthorized"}), 403
        
        # Mark messages as read
        messages = Thread.query.filter_by(ticket_id=ticket.id).all()
        updated = 0
        
        for msg in messages:
            # Only mark messages not from customer as read
            if msg.user_id != customer_id:
                try:
                    msg.is_read = True
                    if hasattr(msg, 'read_at'):
                        msg.read_at = datetime.utcnow()
                    updated += 1
                except AttributeError:
                    # Column doesn't exist yet, skip
                    pass
            
            # Mark comments as read
            comments = Comment.query.filter_by(thread_id=msg.id).all()
            for comment in comments:
                if comment.user_id != customer_id:
                    try:
                        comment.is_read = True
                        if hasattr(comment, 'read_at'):
                            comment.read_at = datetime.utcnow()
                        updated += 1
                    except AttributeError:
                        pass
        
        db.session.commit()
        
        return jsonify({
            "success": True,
            "updated": updated
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Mark ticket read error: {e}")
        db.session.rollback()
        return jsonify({"error": "Failed to mark as read"}), 500


@bp.route('/tickets/create', methods=['POST'])
def create_ticket():
    """
    POST /api/tickets/create
    Create a new support ticket
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        customer_id = data.get('customer_id')
        subject = data.get('subject', '').strip()
        description = data.get('description', '').strip()
        category = data.get('category', 'Other')
        priority = data.get('priority', 'medium')
        order_id = data.get('order_id')
        
        if not customer_id:
            return jsonify({"error": "customer_id is required"}), 400
        
        if not subject or not description:
            return jsonify({"error": "Subject and description are required"}), 400
        
        # Get or create category
        category_obj = SupportTicketCategory.query.filter_by(name=category).first()
        if not category_obj:
            # Create default category if doesn't exist
            category_obj = SupportTicketCategory(name=category, description=category, is_active=True)
            db.session.add(category_obj)
            db.session.flush()
        
        # Generate ticket number
        from datetime import datetime
        year = datetime.utcnow().year
        ticket_count = SupportTicket.query.filter(
            db.func.extract('year', SupportTicket.created_at) == year
        ).count() + 1
        ticket_number = f"TKT-{year}-{str(ticket_count).zfill(5)}"
        
        # Create ticket
        new_ticket = SupportTicket(
            ticket_number=ticket_number,
            user_id=customer_id,
            user_type='customer',
            category_id=category_obj.id,
            priority=priority,
            subject=subject,
            description=description,
            status='open'
        )
        
        # Set order_id if provided
        if order_id:
            try:
                new_ticket.order_id = order_id
            except AttributeError:
                pass  # Column might not exist yet
        
        db.session.add(new_ticket)
        db.session.commit()
        
        # Process with intelligent support (if available)
        try:
            from app_pkg.support_integration import process_new_ticket
            process_new_ticket(
                ticket_id=new_ticket.id,
                order_id=order_id,
                customer_message=description
            )
        except Exception as e:
            app_logger.warning(f"Intelligent support processing failed: {e}")
        
        return jsonify({
            "success": True,
            "ticket_id": ticket_number,
            "id": new_ticket.id
        }), 201
        
    except Exception as e:
        app_logger.exception(f"Create ticket error: {e}")
        db.session.rollback()
        return jsonify({"error": "Failed to create ticket"}), 500


# ============================================================================
# AI Support Chat Endpoint
# ============================================================================

@bp.route('/ai-chat', methods=['POST'])
def ai_chat():
    """
    POST /api/ai-chat
    AI-powered support chat that collects issue info and creates smart tickets
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        message = data.get('message', '').strip()
        order_id = data.get('order_id')
        ticket_id = data.get('ticket_id')
        customer_id = data.get('customer_id')
        
        if not message:
            return jsonify({"error": "Message is required"}), 400
        
        if not customer_id:
            return jsonify({"error": "Customer ID is required"}), 400
        
        # Import AI functions
        from app_pkg.intelligent_support import AIAutoReply, SmartTicketContext, AutoAssignment
        
        # Detect intent from message
        intent_result = AIAutoReply.detect_intent(message)
        intent = intent_result.get('intent', 'general_issue')
        confidence = intent_result.get('confidence', 0.5)
        
        # If no ticket exists, create one
        if not ticket_id:
            # Determine issue type from intent
            issue_type_map = {
                'order_status': 'order_inquiry',
                'delivery_delay': 'delivery_delay',
                'refund': 'refund_request',
                'payment_failed': 'payment_issue',
                'abuse': 'abuse_report'
            }
            issue_type = issue_type_map.get(intent, 'general_issue')
            
            # Get order details if order_id provided
            order = None
            vendor_id = None
            rider_id = None
            
            if order_id:
                try:
                    from app_pkg.models import Order
                    order = Order.query.filter_by(id=order_id).first()
                    if order:
                        vendor_id = getattr(order, 'vendor_id', None)
                        rider_id = getattr(order, 'rider_id', None)
                except Exception as e:
                    app_logger.warning(f"Error fetching order {order_id}: {e}")
            
            # Generate ticket subject from intent
            subject_map = {
                'order_status': f'Order Status Inquiry - Order #{order_id}',
                'delivery_delay': f'Delivery Delay - Order #{order_id}',
                'refund': f'Refund Request - Order #{order_id}',
                'payment_failed': f'Payment Issue - Order #{order_id}',
                'abuse': 'Priority: Abuse Report'
            }
            subject = subject_map.get(intent, f'Support Request - Order #{order_id or "N/A"}')
            
            # Create smart ticket
            new_ticket = SupportTicket(
                ticket_number=None,  # Will be generated
                user_id=customer_id,
                user_type='customer',
                subject=subject,
                description=message,
                status='open',
                priority='high' if intent == 'abuse' else 'medium'
            )
            
            # Set order context
            if order_id:
                try:
                    new_ticket.order_id = order_id
                except AttributeError:
                    pass  # Column might not exist yet
            
            if vendor_id:
                try:
                    new_ticket.vendor_id = vendor_id
                except AttributeError:
                    pass
            
            if rider_id:
                try:
                    new_ticket.rider_id = rider_id
                except AttributeError:
                    pass
            
            if issue_type:
                try:
                    new_ticket.issue_type = issue_type
                except AttributeError:
                    pass
            
            # Generate ticket number
            from datetime import datetime
            year = datetime.utcnow().year
            ticket_count = SupportTicket.query.filter(
                db.func.extract('year', SupportTicket.created_at) == year
            ).count() + 1
            new_ticket.ticket_number = f"TKT-{year}-{str(ticket_count).zfill(5)}"
            
            db.session.add(new_ticket)
            db.session.flush()  # Get ticket ID
            
            # Set assigned_at timestamp
            try:
                new_ticket.assigned_at = datetime.utcnow()
            except AttributeError:
                pass
            
            db.session.commit()
            
            ticket_id = new_ticket.id
            
            # Auto-assign agent
            try:
                agent_id = AutoAssignment.assign_agent()
                if agent_id:
                    try:
                        new_ticket.assigned_agent_id = agent_id
                    except AttributeError:
                        # Fallback to assigned_to
                        new_ticket.assigned_to = agent_id
                    
                    new_ticket.status = 'assigned'
                    db.session.commit()
                    app_logger.info(f"Ticket {ticket_id} auto-assigned to agent {agent_id}")
            except Exception as e:
                app_logger.warning(f"Auto-assignment failed: {e}")
            
            # Process with intelligent support
            try:
                from app_pkg.support_integration import process_new_ticket
                process_new_ticket(
                    ticket_id=new_ticket.id,
                    order_id=order_id,
                    customer_message=message
                )
            except Exception as e:
                app_logger.warning(f"Intelligent support processing failed: {e}")
            
            # Generate AI reply
            reply = f"✅ I've created support ticket {new_ticket.ticket_number} for your issue.\n\n"
            reply += "An agent has been assigned and will join this conversation shortly.\n\n"
            reply += "Is there anything else I can help you with?"
            
            return jsonify({
                "reply": reply,
                "ticket_id": new_ticket.ticket_number,
                "ticket_id_raw": new_ticket.id,
                "intent": intent,
                "confidence": confidence
            }), 200
        
        else:
            # Ticket exists, continue conversation
            # Find ticket (handle both string ticket_number and int id)
            try:
                ticket_id_int = int(ticket_id)
            except (ValueError, TypeError):
                ticket_id_int = None
            
            ticket = None
            if ticket_id_int:
                ticket = SupportTicket.query.filter(
                    (SupportTicket.ticket_number == str(ticket_id)) |
                    (SupportTicket.id == ticket_id_int)
                ).first()
            else:
                ticket = SupportTicket.query.filter(
                    SupportTicket.ticket_number == str(ticket_id)
                ).first()
            
            if not ticket:
                return jsonify({
                    "error": "Ticket not found",
                    "reply": "I couldn't find your ticket. Please start a new conversation."
                }), 404
            
            # Try AI auto-reply
            ai_reply_result = AIAutoReply.generate_reply(message, ticket.id)
            
            if ai_reply_result and ai_reply_result.get('confidence', 0) > 0.85:
                # High confidence AI reply
                reply = ai_reply_result.get('reply', 'I understand your concern. An agent will respond shortly.')
                
                # If resolved, update ticket
                if ai_reply_result.get('resolved', False):
                    try:
                        ticket.status = 'resolved'
                        ticket.resolved_at = datetime.utcnow()
                        db.session.commit()
                    except Exception as e:
                        app_logger.warning(f"Error updating ticket status: {e}")
                
                return jsonify({
                    "reply": reply,
                    "ticket_id": ticket.ticket_number or str(ticket.id),
                    "ai_reply": True
                }), 200
            else:
                # Low confidence, forward to agent
                reply = "I understand your concern. An agent will review your message and respond shortly."
                
                # Add message to ticket
                try:
                    from app_pkg.models import Thread
                    thread = Thread(
                        title=ticket.subject,
                        content=message,
                        user_id=customer_id,
                        ticket_id=ticket.id
                    )
                    db.session.add(thread)
                    ticket.updated_at = datetime.utcnow()
                    db.session.commit()
                except Exception as e:
                    app_logger.warning(f"Error adding message to ticket: {e}")
                
                return jsonify({
                    "reply": reply,
                    "ticket_id": ticket.ticket_number or str(ticket.id),
                    "ai_reply": False
                }), 200
        
    except Exception as e:
        app_logger.exception(f"AI chat error: {e}")
        db.session.rollback()
        return jsonify({
            "error": "Failed to process your message",
            "reply": "I'm sorry, I encountered an error. Please try again or contact support directly."
        }), 500
