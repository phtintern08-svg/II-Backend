"""
Customer Routes Blueprint
Handles customer-specific endpoints for profile, orders, and addresses
"""
from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import os

from app_pkg.models import db, Customer, Address, Order, Notification
from app_pkg.auth import login_required, role_required
from werkzeug.security import check_password_hash, generate_password_hash
from app_pkg.logger_config import app_logger
from app_pkg.file_upload import validate_and_save_file, delete_file

# Create blueprint
bp = Blueprint('customer', __name__, url_prefix='/api/customer')


@bp.route('/profile', methods=['GET'])
@login_required
@role_required(['customer'])
def get_customer_profile():
    """
    GET /api/customer/profile
    Get customer profile information
    """
    try:
        customer = Customer.query.get(request.user_id)
        if not customer:
            return jsonify({"error": "Customer not found"}), 404
        
        # Build avatar URL if exists
        avatar_url = None
        if customer.avatar_url:
            base_url = current_app.config.get('BASE_URL', '')
            if base_url:
                avatar_url = f"{base_url}/uploads/{customer.avatar_url}"
            else:
                avatar_url = f"/uploads/{customer.avatar_url}"
        
        customer_data = {
            "id": customer.id,
            "username": customer.username,
            "email": customer.email,
            "phone": customer.phone,
            "bio": customer.bio,
            "avatar_url": avatar_url,
            "is_email_verified": customer.is_email_verified if hasattr(customer, 'is_email_verified') else False,
            "created_at": customer.created_at.isoformat() if customer.created_at else None
        }
        
        return jsonify(customer_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get customer profile error: {e}")
        return jsonify({"error": "Failed to retrieve profile"}), 500


@bp.route('/profile', methods=['PUT'])
@login_required
@role_required(['customer'])
def update_customer_profile():
    """
    PUT /api/customer/profile
    Update customer profile information
    """
    try:
        data = request.get_json()
        customer = Customer.query.get(request.user_id)
        
        if not customer:
            return jsonify({"error": "Customer not found"}), 404
        
        # Update allowed fields
        allowed_fields = ['username', 'phone', 'bio']
        for field in allowed_fields:
            if field in data:
                setattr(customer, field, data[field])
        
        db.session.commit()
        
        return jsonify({"message": "Profile updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update customer profile error: {e}")
        return jsonify({"error": "Failed to update profile"}), 500


@bp.route('/addresses', methods=['GET'])
@login_required
@role_required(['customer'])
def get_addresses():
    """
    GET /api/customer/addresses
    Get all addresses for this customer
    """
    try:
        addresses = Address.query.filter_by(customer_id=request.user_id).all()
        
        addresses_data = [{
            "id": a.id,
            "address_type": a.address_type,
            "address_line1": a.address_line1,
            "address_line2": a.address_line2,
            "city": a.city,
            "state": a.state,
            "pincode": a.pincode,
            "landmark": a.landmark,
            "country": a.country,
            "alternative_phone": a.alternative_phone,
            "latitude": float(a.latitude) if a.latitude is not None else None,
            "longitude": float(a.longitude) if a.longitude is not None else None
        } for a in addresses]
        
        return jsonify({
            "addresses": addresses_data,
            "count": len(addresses_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get addresses error: {e}")
        return jsonify({"error": "Failed to retrieve addresses"}), 500


@bp.route('/addresses', methods=['POST'])
@login_required
@role_required(['customer'])
def add_address():
    """
    POST /api/customer/addresses
    Add a new address for this customer
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['address_type', 'address_line1', 'city', 'state', 'pincode']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Normalize address type (prevent "Home" vs "home" issues)
        address_type = data['address_type'].lower().strip()
        # Only allow: home, work, other
        valid_types = ['home', 'work', 'other']
        if address_type not in valid_types:
            return jsonify({"error": f"Invalid address_type. Must be one of: {', '.join(valid_types)}"}), 400
        
        # Check if address type already exists for this customer
        existing = Address.query.filter_by(
            customer_id=request.user_id,
            address_type=address_type
        ).first()
        
        if existing:
            return jsonify({"error": f"Address type '{data['address_type']}' already exists. Please update the existing address instead."}), 409
        
        # 🔥 GEOCODING: Extract latitude/longitude if provided (from "Use Current Location" or geocoding)
        latitude = None
        longitude = None
        if 'latitude' in data and 'longitude' in data:
            try:
                latitude = float(data['latitude']) if data['latitude'] is not None else None
                longitude = float(data['longitude']) if data['longitude'] is not None else None
                # Validate coordinates (0,0 is invalid - likely error)
                if latitude == 0.0 and longitude == 0.0:
                    latitude = None
                    longitude = None
                    app_logger.warning(f"Invalid coordinates (0,0) for address creation - ignoring")
            except (ValueError, TypeError) as e:
                app_logger.warning(f"Invalid latitude/longitude values: {e}")
        
        # If lat/lng not provided, try geocoding from address
        if latitude is None or longitude is None:
            try:
                from flask import current_app
                import requests
                geocode_query = f"{data['address_line1']}, {data['city']}, {data['state']}, {data['pincode']}, {data.get('country', 'India')}".strip()
                api_key = current_app.config.get('MAPPLS_REST_KEY') or current_app.config.get('MAPPLS_API_KEY')
                if api_key:
                    url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/geo_code"
                    params = {"addr": geocode_query}
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Referer': request.host_url,
                        'Origin': request.host_url.rstrip('/')
                    }
                    response = requests.get(url, params=params, headers=headers, timeout=5)
                    if response.status_code == 200:
                        geo_data = response.json()
                        if geo_data.get("results") and len(geo_data["results"]) > 0:
                            result = geo_data["results"][0]
                            lat_val = float(result.get("latitude", 0))
                            lon_val = float(result.get("longitude", 0))
                            if lat_val != 0.0 or lon_val != 0.0:
                                latitude = lat_val
                                longitude = lon_val
                                app_logger.info(f"Geocoded address during creation: {geocode_query} → ({latitude}, {longitude})")
            except Exception as e:
                app_logger.warning(f"Geocoding failed for address creation (non-critical): {e}")
        
        new_address = Address(
            customer_id=request.user_id,
            address_type=address_type,
            address_line1=data['address_line1'],
            address_line2=data.get('address_line2'),
            city=data['city'],
            state=data['state'],
            pincode=data['pincode'],
            landmark=data.get('landmark'),
            country=data.get('country', 'India'),
            alternative_phone=data.get('alternative_phone'),
            latitude=latitude,  # GPS coordinates from frontend or geocoded
            longitude=longitude
        )
        
        db.session.add(new_address)
        db.session.commit()
        
        # Return full address object for frontend sync
        return jsonify({
            "id": new_address.id,
            "address_type": new_address.address_type,
            "address_line1": new_address.address_line1,
            "address_line2": new_address.address_line2,
            "city": new_address.city,
            "state": new_address.state,
            "pincode": new_address.pincode,
            "landmark": new_address.landmark,
            "country": new_address.country,
            "alternative_phone": new_address.alternative_phone,
            "latitude": float(new_address.latitude) if new_address.latitude is not None else None,
            "longitude": float(new_address.longitude) if new_address.longitude is not None else None
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Add address error: {e}")
        return jsonify({"error": "Failed to add address"}), 500


@bp.route('/addresses/<int:address_id>', methods=['PUT'])
@login_required
@role_required(['customer'])
def update_address(address_id):
    """
    PUT /api/customer/addresses/<address_id>
    Update an address
    """
    try:
        data = request.get_json()
        address = Address.query.get(address_id)
        
        if not address:
            return jsonify({"error": "Address not found"}), 404
        
        # Verify ownership
        if address.customer_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        # Update fields
        updatable_fields = ['address_line1', 'address_line2', 'city', 'state', 'pincode', 'landmark', 'country']
        for field in updatable_fields:
            if field in data:
                setattr(address, field, data[field])
        
        # Handle address_type separately with normalization
        if 'address_type' in data:
            address_type = data['address_type'].lower().strip()
            # Only allow: home, work, other
            valid_types = ['home', 'work', 'other']
            if address_type not in valid_types:
                return jsonify({"error": f"Invalid address_type. Must be one of: {', '.join(valid_types)}"}), 400
            address.address_type = address_type
        
        # Also handle alternative_phone if provided
        if 'alternative_phone' in data:
            setattr(address, 'alternative_phone', data['alternative_phone'])
        
        # 🔥 GEOCODING: Update latitude/longitude if provided (from "Use Current Location" or geocoding)
        if 'latitude' in data or 'longitude' in data:
            try:
                if 'latitude' in data:
                    lat_val = float(data['latitude']) if data['latitude'] is not None else None
                    if lat_val == 0.0:
                        lat_val = None
                    address.latitude = lat_val
                if 'longitude' in data:
                    lon_val = float(data['longitude']) if data['longitude'] is not None else None
                    if lon_val == 0.0:
                        lon_val = None
                    address.longitude = lon_val
            except (ValueError, TypeError) as e:
                app_logger.warning(f"Invalid latitude/longitude values during update: {e}")
        
        # If lat/lng not provided but address fields changed, try geocoding
        if (address.latitude is None or address.longitude is None) and any(field in data for field in ['address_line1', 'city', 'state', 'pincode']):
            try:
                from flask import current_app
                import requests
                geocode_query = f"{address.address_line1}, {address.city}, {address.state}, {address.pincode}, {address.country or 'India'}".strip()
                api_key = current_app.config.get('MAPPLS_REST_KEY') or current_app.config.get('MAPPLS_API_KEY')
                if api_key:
                    url = f"https://apis.mappls.com/advancedmaps/v1/{api_key}/geo_code"
                    params = {"addr": geocode_query}
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Referer': request.host_url,
                        'Origin': request.host_url.rstrip('/')
                    }
                    response = requests.get(url, params=params, headers=headers, timeout=5)
                    if response.status_code == 200:
                        geo_data = response.json()
                        if geo_data.get("results") and len(geo_data["results"]) > 0:
                            result = geo_data["results"][0]
                            lat_val = float(result.get("latitude", 0))
                            lon_val = float(result.get("longitude", 0))
                            if lat_val != 0.0 or lon_val != 0.0:
                                address.latitude = lat_val
                                address.longitude = lon_val
                                app_logger.info(f"Geocoded address during update: {geocode_query} → ({lat_val}, {lon_val})")
            except Exception as e:
                app_logger.warning(f"Geocoding failed for address update (non-critical): {e}")
        
        db.session.commit()
        
        # Return full address object for frontend sync
        return jsonify({
            "id": address.id,
            "address_type": address.address_type,
            "address_line1": address.address_line1,
            "address_line2": address.address_line2,
            "city": address.city,
            "state": address.state,
            "pincode": address.pincode,
            "landmark": address.landmark,
            "country": address.country,
            "alternative_phone": address.alternative_phone
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update address error: {e}")
        return jsonify({"error": "Failed to update address"}), 500


@bp.route('/addresses/<int:address_id>', methods=['DELETE'])
@login_required
@role_required(['customer'])
def delete_address(address_id):
    """
    DELETE /api/customer/addresses/<address_id>
    Delete an address
    """
    try:
        address = Address.query.get(address_id)
        
        if not address:
            return jsonify({"error": "Address not found"}), 404
        
        # Verify ownership
        if address.customer_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        db.session.delete(address)
        db.session.commit()
        
        return jsonify({"message": "Address deleted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Delete address error: {e}")
        return jsonify({"error": "Failed to delete address"}), 500


@bp.route('/orders', methods=['GET'])
@login_required
@role_required(['customer'])
def get_customer_orders():
    """
    GET /api/customer/orders
    Get all orders for this customer
    """
    try:
        orders = Order.query.filter_by(customer_id=request.user_id).order_by(Order.created_at.desc()).all()
        
        # 🔥 FIX: Use full schema to return ALL order fields (not just limited subset)
        # This ensures frontend orders.js can display: neck_type, color, print_type, sample_size,
        # bulk_quantity, size_distribution, address fields, quotation_total_price, etc.
        from app_pkg.schemas import orders_schema
        orders_data = orders_schema.dump(orders)
        
        return jsonify({
            "orders": orders_data,
            "count": len(orders_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get customer orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/notifications', methods=['GET'])
@login_required
@role_required(['customer'])
def get_notifications():
    """
    GET /api/customer/notifications
    Get customer notifications
    """
    try:
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        query = Notification.query.filter_by(user_id=request.user_id, user_type='customer')
        
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
        app_logger.exception(f"Get customer notifications error: {e}")
        return jsonify({"error": "Failed to retrieve notifications"}), 500


@bp.route('/notifications/<int:notif_id>/read', methods=['POST'])
@login_required
@role_required(['customer'])
def mark_notification_read(notif_id):
    """
    POST /api/customer/notifications/<notif_id>/read
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


@bp.route('/orders/<int:order_id>', methods=['GET'])
@login_required
@role_required(['customer'])
def get_order_details(order_id):
    """
    GET /api/customer/orders/<order_id>
    Get specific order details
    """
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        if order.customer_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        from app.schemas import order_schema
        return order_schema.jsonify(order), 200
        
    except Exception as e:
        app_logger.exception(f"Get order details error: {e}")
        return jsonify({"error": "Failed to retrieve order details"}), 500


@bp.route('/change-password', methods=['PUT'])
@login_required
@role_required(['customer'])
def change_password():
    """
    PUT /api/customer/change-password
    Change customer password
    """
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({"error": "Current password and new password are required"}), 400
        
        customer = Customer.query.get(request.user_id)
        if not customer:
            return jsonify({"error": "Customer not found"}), 404
        
        if not check_password_hash(customer.password_hash, current_password):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        customer.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({"message": "Password changed successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Change password error: {e}")
        return jsonify({"error": "Failed to change password"}), 500


@bp.route('/order-stats', methods=['GET'])
@login_required
@role_required(['customer'])
def get_order_stats():
    """
    GET /api/customer/order-stats
    Get order statistics for customer
    """
    try:
        customer_id = request.user_id
        
        total_orders = Order.query.filter_by(customer_id=customer_id).count()
        
        pending_orders = Order.query.filter(
            Order.customer_id == customer_id,
            Order.status.in_(['pending_admin_review', 'quotation_sent_to_customer', 'sample_payment_received'])
        ).count()
        
        in_progress_orders = Order.query.filter(
            Order.customer_id == customer_id,
            Order.status.in_(['sample_requested', 'awaiting_advance_payment', 'in_production', 
                             'assigned', 'vendor_assigned', 'awaiting_dispatch',
                             'ready_for_dispatch', 'awaiting_delivery', 'reached_vendor', 'picked_up',
                             'out_for_delivery', 'packed_ready', 'dispatched'])
        ).count()
        
        completed_orders = Order.query.filter(
            Order.customer_id == customer_id,
            Order.status.in_(['completed', 'completed_with_penalty', 'delivered'])
        ).count()
        
        return jsonify({
            "total": total_orders,
            "pending": pending_orders,
            "in_progress": in_progress_orders,
            "completed": completed_orders
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get order stats error: {e}")
        return jsonify({"error": "Failed to retrieve order stats"}), 500


@bp.route('/profile/avatar', methods=['POST'])
@login_required
@role_required(['customer'])
def upload_profile_avatar():
    """
    POST /api/customer/profile/avatar
    Upload customer profile picture
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        file = request.files['file']
        if not file or not file.filename:
            return jsonify({"error": "No file selected"}), 400
        
        customer = Customer.query.get(request.user_id)
        if not customer:
            return jsonify({"error": "Customer not found"}), 404
        
        # Validate and save file
        file_info, error = validate_and_save_file(
            file=file,
            endpoint='/api/customer/profile/avatar',
            subfolder='customer',
            user_id=request.user_id,
            doc_type='avatar',
            scan_virus=False
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        # Delete old avatar if exists
        if customer.avatar_url:
            try:
                upload_folder = current_app.config.get('UPLOAD_FOLDER')
                if upload_folder:
                    old_path = os.path.join(upload_folder, customer.avatar_url)
                    if os.path.exists(old_path):
                        os.remove(old_path)
            except Exception as e:
                app_logger.warning(f"Failed to delete old avatar: {e}")
        
        # Update customer avatar URL
        customer.avatar_url = file_info['path']
        db.session.commit()
        
        # Return full URL for frontend
        base_url = current_app.config.get('BASE_URL', '')
        avatar_url = f"{base_url}/uploads/{file_info['path']}" if base_url else f"/uploads/{file_info['path']}"
        
        return jsonify({
            "message": "Avatar uploaded successfully",
            "avatar_url": avatar_url,
            "path": file_info['path']
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Upload avatar error: {e}")
        return jsonify({"error": "Failed to upload avatar"}), 500
