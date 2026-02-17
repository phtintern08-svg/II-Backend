"""
Support Routes Blueprint
Handles support endpoints like config, geocoding, categories, threads, and profile updates
"""
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import os
import requests

from config import Config
from app_pkg.models import db, Category, Thread, Comment, Customer, Vendor, Support, Notification, ProductCatalog
from werkzeug.security import check_password_hash, generate_password_hash
from app_pkg.auth import login_required, role_required
from app_pkg.schemas import category_schema, categories_schema, thread_schema, threads_schema, comment_schema, comments_schema
from app_pkg.logger_config import app_logger
from app_pkg.activity_logger import log_activity

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
        app_logger.warning("Rate limiter memory cap reached - clearing cache")
        reverse_geocode._last_requests.clear()
    
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
        support = Support.query.get(request.user_id)
        if not support:
            return jsonify({"error": "Support user not found"}), 404
        
        support_data = {
            "id": support.id,
            "username": support.username,
            "name": support.name,
            "email": support.email,
            "phone": support.phone,
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
        support = Support.query.get(request.user_id)
        
        if not support:
            return jsonify({"error": "Support user not found"}), 404
        
        # Update allowed fields
        allowed_fields = ['username', 'name', 'phone']
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
        
        support = Support.query.get(request.user_id)
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
        from app_pkg.models import ProductCatalog
        product = ProductCatalog.query.get(product_id)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        return jsonify({
            'id': product.id,
            'product_type': product.product_type,
            'category': product.category,
            'final_price': float(product.final_price) if product.final_price else 0,  # 🔥 FIX: Return final_price (was incorrectly named average_price)
            'average_price': float(product.average_price) if product.average_price else 0,  # Also include average_price for reference
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
            
            result = []
            for row in rows:
                result.append({
                    'product_type': row['product_type'],
                    'category': row['category'],
                    'neck_type': row['neck_type'],
                    'fabric': row['fabric'],
                    'notes': row['notes'],
                    'min_price': float(row['min_price']) if row['min_price'] else 0.0,
                    'max_price': float(row['max_price']) if row['max_price'] else 0.0,
                    'avg_price': float(row['avg_price']) if row['avg_price'] else 0.0,
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
            
            result = []
            for row in rows:
                result.append({
                    'id': row['id'],
                    'product_type': row['product_type'],
                    'category': row['category'],
                    'neck_type': row['neck_type'],
                    'fabric': row['fabric'],
                    'size': row['size'],
                    'average_price': float(row['average_price']) if row['average_price'] else 0.0,
                    'final_price': float(row['final_price']) if row['final_price'] else 0.0,
                    'vendor_count': row['vendor_count'] or 0,
                    'notes': row['notes'],
                    'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None
                })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get product catalog error: {e}")
        return jsonify({"error": "Failed to retrieve product catalog"}), 500
