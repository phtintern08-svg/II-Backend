"""
Customer Routes Blueprint
Handles customer-specific endpoints for profile, orders, and addresses
"""
from flask import Blueprint, request, jsonify
from datetime import datetime

from app.models import db, Customer, Address, Order, Notification
from app.auth import login_required, role_required
from werkzeug.security import check_password_hash, generate_password_hash
from logger_config import app_logger

# Create blueprint
bp = Blueprint('customer', __name__, url_prefix='/api/customer')


@bp.route('/profile', methods=['GET'])
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
        
        customer_data = {
            "id": customer.id,
            "username": customer.username,
            "email": customer.email,
            "phone": customer.phone,
            "bio": customer.bio,
            "avatar_url": customer.avatar_url,
            "created_at": customer.created_at.isoformat() if customer.created_at else None
        }
        
        return jsonify(customer_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get customer profile error: {e}")
        return jsonify({"error": "Failed to retrieve profile"}), 500


@bp.route('/profile', methods=['PUT'])
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
            "landmark": a.landmark
        } for a in addresses]
        
        return jsonify({
            "addresses": addresses_data,
            "count": len(addresses_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get addresses error: {e}")
        return jsonify({"error": "Failed to retrieve addresses"}), 500


@bp.route('/addresses', methods=['POST'])
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
        
        new_address = Address(
            customer_id=request.user_id,
            address_type=data['address_type'],
            address_line1=data['address_line1'],
            address_line2=data.get('address_line2'),
            city=data['city'],
            state=data['state'],
            pincode=data['pincode'],
            landmark=data.get('landmark'),
            country=data.get('country', 'India')
        )
        
        db.session.add(new_address)
        db.session.commit()
        
        return jsonify({
            "message": "Address added successfully",
            "address_id": new_address.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Add address error: {e}")
        return jsonify({"error": "Failed to add address"}), 500


@bp.route('/addresses/<int:address_id>', methods=['PUT'])
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
        updatable_fields = ['address_type', 'address_line1', 'address_line2', 'city', 'state', 'pincode', 'landmark']
        for field in updatable_fields:
            if field in data:
                setattr(address, field, data[field])
        
        db.session.commit()
        
        return jsonify({"message": "Address updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update address error: {e}")
        return jsonify({"error": "Failed to update address"}), 500


@bp.route('/addresses/<int:address_id>', methods=['DELETE'])
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
@role_required(['customer'])
def get_customer_orders():
    """
    GET /api/customer/orders
    Get all orders for this customer
    """
    try:
        orders = Order.query.filter_by(customer_id=request.user_id).order_by(Order.created_at.desc()).all()
        
        orders_data = [{
            "id": order.id,
            "status": order.status,
            "total_amount": float(order.total_amount) if order.total_amount else 0,
            "created_at": order.created_at.isoformat() if order.created_at else None
        } for order in orders]
        
        return jsonify({
            "orders": orders_data,
            "count": len(orders_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get customer orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/notifications', methods=['GET'])
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
