"""
Support Routes Blueprint
Handles support endpoints like config, geocoding, categories, threads, and profile updates
"""
from flask import Blueprint, request, jsonify
from datetime import datetime
import os
import requests

from config import Config
from app_pkg.models import db, Category, Thread, Comment, Customer, Vendor, Support, Notification
from werkzeug.security import check_password_hash, generate_password_hash
from app_pkg.auth import login_required, role_required
from app_pkg.schemas import category_schema, categories_schema, thread_schema, threads_schema, comment_schema, comments_schema
from app_pkg.logger_config import app_logger

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
        api_key = Config.MAPPLS_API_KEY
        
        return jsonify({
            "mappls": {
                "apiKey": api_key
            }
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get config error: {e}")
        return jsonify({"error": "Failed to retrieve config"}), 500


@bp.route('/reverse-geocode', methods=['GET'])
@login_required
def reverse_geocode():
    """
    GET /api/reverse-geocode
    Reverse geocode coordinates to address
    Rate limited to prevent abuse of paid API
    """
    # Rate limit: 10 requests per minute per user
    # This prevents abuse of paid Mappls API
    if not hasattr(reverse_geocode, '_last_requests'):
        reverse_geocode._last_requests = {}
    
    user_id = request.user_id
    current_time = datetime.utcnow().timestamp()
    
    # Clean old entries (older than 1 minute)
    reverse_geocode._last_requests = {
        uid: times for uid, times in reverse_geocode._last_requests.items()
        if any(t > current_time - 60 for t in times)
    }
    
    # Get user's request times in last minute
    user_requests = reverse_geocode._last_requests.get(user_id, [])
    user_requests = [t for t in user_requests if t > current_time - 60]
    
    if len(user_requests) >= 10:
        return jsonify({
            "error": "Rate limit exceeded. Maximum 10 requests per minute.",
            "retry_after": max(1, int(60 - (current_time - user_requests[0])))
        }), 429
    
    # Add current request
    user_requests.append(current_time)
    reverse_geocode._last_requests[user_id] = user_requests
    
    try:
        lat = request.args.get('lat')
        lng = request.args.get('lng')
        
        if not lat or not lng:
            return jsonify({"error": "Latitude and longitude required"}), 400
        
        api_key = os.environ.get('MAPPLS_API_KEY')
        if not api_key:
            return jsonify({"error": "MAPPLS_API_KEY environment variable is required"}), 500
        
        url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/rev_geocode?lat={lat}&lng={lng}"
        
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch from MapmyIndia"}), response.status_code
        
        return jsonify(response.json()), 200
        
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
        
        api_key = os.environ.get('MAPPLS_API_KEY')
        if not api_key:
            return jsonify({"error": "MAPPLS_API_KEY environment variable is required"}), 500
        
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
        
        new_thread = Thread(
            title=title,
            content=content,
            user_id=user_id,
            category_id=category_id
        )
        
        db.session.add(new_thread)
        db.session.commit()
        
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
        
        # Check if email already exists for another user
        if role == 'customer':
            existing = Customer.query.filter(Customer.email == email, Customer.id != user_id).first()
        else:
            existing = Vendor.query.filter(Vendor.email == email, Vendor.id != user_id).first()
        
        if existing:
            return jsonify({"error": "Email already in use"}), 400
        
        # Check if phone already exists for another user
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
@role_required(['customer', 'vendor', 'admin'])
def estimate_price():
    """
    POST /api/estimate-price
    Estimate price for a product configuration
    """
    try:
        data = request.get_json()
        product_type = data.get('product_type')
        category = data.get('category')
        neck_type = data.get('neck_type')
        fabric = data.get('fabric')
        size = data.get('size')
        
        if not product_type or not category:
            return jsonify({"error": "Product type and category are required"}), 400
        
        from app.models import ProductCatalog
        query = ProductCatalog.query.filter_by(
            product_type=product_type,
            category=category
        )
        
        if neck_type:
            query = query.filter_by(neck_type=neck_type)
        if fabric:
            query = query.filter_by(fabric=fabric)
        if size:
            query = query.filter_by(size=size)
        
        product = query.first()
        
        if product and product.vendor_count > 0:
            return jsonify({
                "estimated_price": float(product.final_price) if product.final_price else 0,
                "vendor_count": product.vendor_count,
                "found": True
            }), 200
        else:
            # Try to find match with same Product, Category AND Size
            query_size = ProductCatalog.query.filter_by(
                product_type=product_type,
                category=category
            ).filter(ProductCatalog.vendor_count > 0)
            
            if size:
                query_size = query_size.filter_by(size=size)
            
            similar_by_size = query_size.all()
            
            if similar_by_size:
                avg = sum(float(p.final_price) if p.final_price else 0 for p in similar_by_size) / len(similar_by_size)
                return jsonify({
                    "estimated_price": round(avg, 2),
                    "vendor_count": len(similar_by_size),
                    "found": False,
                    "message": f"Estimate based on size {size}"
                }), 200
            
            # Fallback: Average of all items in this category
            similar = ProductCatalog.query.filter_by(
                product_type=product_type,
                category=category
            ).filter(ProductCatalog.vendor_count > 0).all()
            
            if similar:
                avg = sum(float(p.final_price) if p.final_price else 0 for p in similar) / len(similar)
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
@role_required(['customer', 'vendor', 'admin'])
def get_product_price(product_id):
    """
    GET /api/product-price/<product_id>
    Get final price for a specific product
    """
    try:
        from app.models import ProductCatalog
        product = ProductCatalog.query.get(product_id)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        return jsonify({
            'id': product.id,
            'product_type': product.product_type,
            'category': product.category,
            'average_price': float(product.final_price) if product.final_price else 0,
            'vendor_count': product.vendor_count or 0
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get product price error: {e}")
        return jsonify({"error": "Failed to retrieve product price"}), 500
