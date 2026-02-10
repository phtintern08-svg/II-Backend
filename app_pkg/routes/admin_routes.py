"""
Admin Routes Blueprint
Handles admin-specific endpoints for managing users, orders, and system settings
"""
from flask import Blueprint, request, jsonify, send_file
from datetime import datetime
import os
import math

from app_pkg.models import (
    db, Admin, Customer, Vendor, Rider, Order, OTPLog, Payment, 
    VendorDocument, VendorQuotationSubmission, RiderDocument, Notification,
    VendorOrderAssignment, OrderStatusHistory, DeliveryLog
)
from app_pkg.auth import login_required, admin_required
from app_pkg.file_upload import get_file_path_from_db
from app_pkg.logger_config import app_logger
from app_pkg.error_handler import get_error_message

# Helper functions (moved from app/utils/helpers.py)
def haversine_distance(lat1, lon1, lat2, lon2):
    """
    Calculate the great circle distance between two points 
    on the earth (specified in decimal degrees)
    Returns distance in kilometers
    """
    # Convert decimal degrees to radians
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    
    # Haversine formula
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    # Radius of earth in kilometers
    r = 6371
    
    return c * r


def find_nearest_riders(vendor_lat, vendor_lon, max_distance_km=10, limit=5):
    """
    Find nearest available riders within max_distance_km radius
    Returns list of (rider, distance) tuples sorted by distance
    """
    # Get all online and verified riders
    riders = Rider.query.filter(
        Rider.is_online == True,
        Rider.verification_status == 'approved',
        Rider.latitude.isnot(None),
        Rider.longitude.isnot(None)
    ).all()
    
    rider_distances = []
    
    for rider in riders:
        distance = haversine_distance(
            vendor_lat, vendor_lon,
            rider.latitude, rider.longitude
        )
        
        # Only include riders within max distance
        if distance <= max_distance_km:
            rider_distances.append((rider, distance))
    
    # Sort by distance (nearest first)
    rider_distances.sort(key=lambda x: x[1])
    
    # Return top N nearest riders
    return rider_distances[:limit]


def assign_nearest_rider_to_order(order_id, vendor_id, max_search_radius_km=10):
    """
    Assign the nearest available rider to an order for pickup from vendor
    
    Args:
        order_id: ID of the order to be delivered
        vendor_id: ID of the vendor where pickup should happen
        max_search_radius_km: Maximum search radius for riders (default 10km)
    
    Returns:
        dict with assignment result
    """
    try:
        # Get vendor location
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return {
                'success': False,
                'error': 'Vendor not found'
            }
        
        if not vendor.latitude or not vendor.longitude:
            return {
                'success': False,
                'error': 'Vendor location not set. Please update vendor profile with GPS coordinates.'
            }
        
        # Get order details
        order = Order.query.get(order_id)
        if not order:
            return {
                'success': False,
                'error': 'Order not found'
            }
        
        # Find nearest available riders
        nearest_riders = find_nearest_riders(
            vendor.latitude,
            vendor.longitude,
            max_distance_km=max_search_radius_km,
            limit=5
        )
        
        if not nearest_riders:
            return {
                'success': False,
                'error': f'No available riders found within {max_search_radius_km}km radius',
                'suggestion': 'Try increasing search radius or wait for riders to come online'
            }
        
        # Assign to the nearest rider
        rider, distance = nearest_riders[0]
        
        # Check if delivery log already exists
        existing_log = DeliveryLog.query.filter_by(order_id=order_id).first()
        
        if existing_log:
            # Update existing delivery log
            existing_log.assigned_rider_id = rider.id
            existing_log.vendor_address = f"{vendor.address}, {vendor.city}, {vendor.state} - {vendor.pincode}"
            existing_log.vendor_contact = vendor.phone
            existing_log.customer_address = f"{order.address_line1}, {order.city}, {order.state} - {order.pincode}"
            existing_log.status = 'assigned'
            existing_log.assigned_at = datetime.utcnow()
            
            db.session.commit()
            
            return {
                'success': True,
                'message': 'Delivery assignment updated',
                'rider': {
                    'id': rider.id,
                    'name': rider.name,
                    'phone': rider.phone,
                    'vehicle_type': rider.vehicle_type,
                    'distance_km': round(distance, 2)
                },
                'vendor': {
                    'name': vendor.business_name,
                    'address': vendor.address,
                    'city': vendor.city
                },
                'alternatives': [
                    {
                        'rider_id': r.id,
                        'name': r.name,
                        'distance_km': round(d, 2)
                    }
                    for r, d in nearest_riders[1:4]  # Show next 3 alternatives
                ]
            }
        else:
            # Create new delivery log
            delivery_log = DeliveryLog(
                order_id=order_id,
                assigned_rider_id=rider.id,
                vendor_address=f"{vendor.address}, {vendor.city}, {vendor.state} - {vendor.pincode}",
                vendor_contact=vendor.phone,
                customer_address=f"{order.address_line1}, {order.city}, {order.state} - {order.pincode}",
                status='assigned',
                assigned_at=datetime.utcnow()
            )
            
            db.session.add(delivery_log)
            db.session.commit()
            
            return {
                'success': True,
                'message': 'Rider assigned successfully',
                'delivery_log_id': delivery_log.id,
                'rider': {
                    'id': rider.id,
                    'name': rider.name,
                    'phone': rider.phone,
                    'vehicle_type': rider.vehicle_type,
                    'distance_km': round(distance, 2)
                },
                'vendor': {
                    'name': vendor.business_name,
                    'address': vendor.address,
                    'city': vendor.city
                },
                'alternatives': [
                    {
                        'rider_id': r.id,
                        'name': r.name,
                        'distance_km': round(d, 2)
                    }
                    for r, d in nearest_riders[1:4]  # Show next 3 alternatives
                ]
            }
            
    except Exception as e:
        db.session.rollback()
        app_logger.exception("assign_nearest_rider_to_order error")
        return {
            'success': False,
            'error': get_error_message(e, "Failed to find nearby riders. Please try again.")
        }


def get_rider_delivery_stats(rider_id):
    """Get delivery statistics for a rider"""
    logs = DeliveryLog.query.filter_by(assigned_rider_id=rider_id).all()
    
    total_deliveries = len(logs)
    completed = sum(1 for log in logs if log.status == 'delivered')
    in_progress = sum(1 for log in logs if log.status in ['assigned', 'reached_vendor', 'picked_up', 'out_for_delivery'])
    failed = sum(1 for log in logs if log.status in ['failed', 'returned'])
    
    return {
        'total_deliveries': total_deliveries,
        'completed': completed,
        'in_progress': in_progress,
        'failed': failed,
        'success_rate': round((completed / total_deliveries * 100), 2) if total_deliveries > 0 else 0
    }

# Create blueprint
bp = Blueprint('admin', __name__, url_prefix='/api/admin')


@bp.route('/dashboard/stats', methods=['GET'])
@admin_required
def get_dashboard_stats():
    """
    GET /api/admin/dashboard/stats
    Get dashboard statistics
    """
    try:
        stats = {
            "total_customers": Customer.query.count(),
            "total_vendors": Vendor.query.count(),
            "total_riders": Rider.query.count(),
            "total_orders": Order.query.count(),
            "pending_orders": Order.query.filter_by(status='pending').count(),
            "completed_orders": Order.query.filter_by(status='completed').count()
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        app_logger.exception(f"Get dashboard stats error: {e}")
        return jsonify({"error": "Failed to retrieve statistics"}), 500


@bp.route('/customers', methods=['GET'])
@admin_required
def get_customers():
    """
    GET /api/admin/customers
    Get all customers
    """
    try:
        customers = Customer.query.all()
        
        customers_data = [{
            "id": c.id,
            "username": c.username,
            "email": c.email,
            "phone": c.phone,
            "created_at": c.created_at.isoformat() if c.created_at else None
        } for c in customers]
        
        return jsonify({
            "customers": customers_data,
            "count": len(customers_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get customers error: {e}")
        return jsonify({"error": "Failed to retrieve customers"}), 500


@bp.route('/vendors', methods=['GET'])
@admin_required
def get_vendors():
    """
    GET /api/admin/vendors
    Get all vendors
    """
    try:
        # Optional status filter
        status = request.args.get('status')
        
        query = Vendor.query
        if status:
            query = query.filter_by(verification_status=status)
        
        vendors = query.all()
        
        vendors_data = [{
            "id": v.id,
            "username": v.username,
            "email": v.email,
            "business_name": v.business_name,
            "verification_status": v.verification_status,
            "created_at": v.created_at.isoformat() if v.created_at else None
        } for v in vendors]
        
        return jsonify({
            "vendors": vendors_data,
            "count": len(vendors_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendors error: {e}")
        return jsonify({"error": "Failed to retrieve vendors"}), 500


@bp.route('/vendors/<int:vendor_id>/verify', methods=['PUT'])
@admin_required
def verify_vendor(vendor_id):
    """
    PUT /api/admin/vendors/<vendor_id>/verify
    Verify or reject a vendor
    """
    try:
        data = request.get_json()
        status = data.get('status')  # 'verified' or 'rejected'
        remarks = data.get('remarks')
        
        if status not in ['verified', 'rejected']:
            return jsonify({"error": "Invalid status"}), 400
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        vendor.verification_status = status
        vendor.admin_remarks = remarks
        vendor.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            "message": f"Vendor {status} successfully",
            "vendor_id": vendor_id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Verify vendor error: {e}")
        return jsonify({"error": "Failed to verify vendor"}), 500


@bp.route('/riders', methods=['GET'])
@admin_required
def get_riders():
    """
    GET /api/admin/riders
    Get all riders
    """
    try:
        # Optional status filter
        status = request.args.get('status')
        
        query = Rider.query
        if status:
            query = query.filter_by(verification_status=status)
        
        riders = query.all()
        
        riders_data = [{
            "id": r.id,
            "name": r.name,
            "email": r.email,
            "phone": r.phone,
            "verification_status": r.verification_status,
            "vehicle_type": r.vehicle_type,
            "created_at": r.created_at.isoformat() if r.created_at else None
        } for r in riders]
        
        return jsonify({
            "riders": riders_data,
            "count": len(riders_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get riders error: {e}")
        return jsonify({"error": "Failed to retrieve riders"}), 500


@bp.route('/riders/<int:rider_id>/verify', methods=['PUT'])
@admin_required
def verify_rider(rider_id):
    """
    PUT /api/admin/riders/<rider_id>/verify
    Verify or reject a rider
    """
    try:
        data = request.get_json()
        status = data.get('status')  # 'verified' or 'rejected'
        remarks = data.get('remarks')
        
        if status not in ['verified', 'rejected']:
            return jsonify({"error": "Invalid status"}), 400
        
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        rider.verification_status = status
        rider.admin_remarks = remarks
        rider.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            "message": f"Rider {status} successfully",
            "rider_id": rider_id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Verify rider error: {e}")
        return jsonify({"error": "Failed to verify rider"}), 500


@bp.route('/otp-logs', methods=['GET'])
@admin_required
def get_otp_logs():
    """
    GET /api/admin/otp-logs
    Get OTP logs
    """
    try:
        # Optional filters
        limit = request.args.get('limit', 100, type=int)
        
        logs = OTPLog.query.order_by(OTPLog.timestamp.desc()).limit(limit).all()
        
        logs_data = [{
            "id": log.id,
            "recipient": log.recipient,
            "event_type": log.event_type,
            "success": log.success,
            "timestamp": log.timestamp.isoformat() if log.timestamp else None
        } for log in logs]
        
        return jsonify({
            "logs": logs_data,
            "count": len(logs_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get OTP logs error: {e}")
        return jsonify({"error": "Failed to retrieve OTP logs"}), 500


@bp.route('/orders', methods=['GET'])
@admin_required
def get_all_orders():
    """
    GET /api/admin/orders
    Get all orders with optional filters
    """
    try:
        status = request.args.get('status')
        query = Order.query
        
        if status:
            query = query.filter_by(status=status)
        
        orders = query.order_by(Order.created_at.desc()).all()
        
        orders_data = [{
            "id": order.id,
            "customer_id": order.customer_id,
            "selected_vendor_id": order.selected_vendor_id,
            "product_type": order.product_type,
            "quantity": order.quantity,
            "status": order.status,
            "created_at": order.created_at.isoformat() if order.created_at else None
        } for order in orders]
        
        return jsonify({
            "orders": orders_data,
            "count": len(orders_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get all orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/orders/<int:order_id>/assign', methods=['PUT'])
@admin_required
def assign_order_to_vendor(order_id):
    """
    PUT /api/admin/orders/<order_id>/assign
    Assign order to vendor
    """
    try:
        data = request.get_json()
        vendor_id = data.get('vendor_id')
        quotation_price = data.get('quotation_price_per_piece')
        sample_cost = data.get('sample_cost', 500.0)
        
        if not vendor_id or not quotation_price:
            return jsonify({"error": "vendor_id and quotation_price_per_piece are required"}), 400
        
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # Assign vendor to order
        order.selected_vendor_id = vendor_id
        order.quotation_price_per_piece = float(quotation_price)
        order.quotation_total_price = float(quotation_price) * order.quantity
        order.sample_cost = float(sample_cost)
        order.status = 'quotation_sent_to_customer'
        
        # Create vendor order assignment record
        assignment = VendorOrderAssignment(
            order_id=order_id,
            vendor_id=vendor_id,
            status='pending',
            assigned_at=datetime.utcnow()
        )
        db.session.add(assignment)
        
        # Create notification for vendor
        notif = Notification(
            user_id=vendor_id,
            user_type='vendor',
            title='New Order Assigned',
            message=f'You have been assigned Order ORD-{order_id}. Please review and accept.',
            type='order'
        )
        db.session.add(notif)
        
        db.session.commit()
        
        return jsonify({
            "message": "Order assigned to vendor successfully",
            "order_id": order_id,
            "vendor_id": vendor_id
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Assign order error: {e}")
        return jsonify({"error": "Failed to assign order"}), 500


@bp.route('/payments', methods=['GET'])
@admin_required
def get_payments():
    """
    GET /api/admin/payments
    Get all payment transactions
    """
    try:
        payments = Payment.query.order_by(Payment.created_at.desc()).all()
        
        result = []
        for p in payments:
            customer = Customer.query.get(p.customer_id)
            order = Order.query.get(p.order_id)
            
            result.append({
                'id': p.id,
                'transaction_id': p.transaction_id,
                'order_id': p.order_id,
                'customer_id': p.customer_id,
                'customer_name': customer.username if customer else "Unknown",
                'customer_email': customer.email if customer else "N/A",
                'order_product': order.product_type if order else "N/A",
                'payment_type': p.payment_type,
                'payment_method': p.payment_method,
                'amount': p.amount,
                'currency': p.currency,
                'status': p.status,
                'created_at': p.created_at.isoformat() if p.created_at else None,
                'processed_at': p.processed_at.isoformat() if p.processed_at else None,
                'payment_details': p.payment_details
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get payments error: {e}")
        return jsonify({"error": "Failed to retrieve payments"}), 500


@bp.route('/vendors/<int:vendor_id>/approve', methods=['POST'])
@admin_required
def approve_vendor(vendor_id):
    """
    POST /api/admin/vendors/<vendor_id>/approve
    Approve vendor verification request
    """
    try:
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # Set default values
        vendor.commission_rate = 15.0
        vendor.payment_cycle = 'monthly'
        vendor.service_zone = 'all'
        vendor.verification_status = 'approved'
        
        # Update all document statuses to approved
        doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
        if doc_row:
            from sqlalchemy.orm.attributes import flag_modified
            for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature']:
                meta_attr = f"{doc_type}_meta"
                if hasattr(doc_row, meta_attr):
                    meta = getattr(doc_row, meta_attr)
                    if meta:
                        meta = dict(meta) if isinstance(meta, dict) else {}
                        meta['status'] = 'approved'
                        setattr(doc_row, meta_attr, meta)
                        flag_modified(doc_row, meta_attr)
        
        # Create notification
        notif = Notification(
            user_id=vendor_id,
            user_type='vendor',
            title='Verification Approved',
            message='Your account verification has been approved. Please submit your quotation to proceed.',
            type='verification'
        )
        db.session.add(notif)
        
        db.session.commit()
        return jsonify({"message": "Vendor approved successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Approve vendor error: {e}")
        return jsonify({"error": "Failed to approve vendor"}), 500


@bp.route('/vendors/<int:vendor_id>/reject', methods=['POST'])
@admin_required
def reject_vendor(vendor_id):
    """
    POST /api/admin/vendors/<vendor_id>/reject
    Reject vendor verification request
    """
    try:
        data = request.get_json()
        reason = data.get('reason', 'Documents rejected')
        rejected_docs = data.get('rejected_documents', {})
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        vendor.verification_status = 'rejected'
        vendor.admin_remarks = reason
        
        # Update document statuses
        doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
        if doc_row:
            from sqlalchemy.orm.attributes import flag_modified
            if rejected_docs:
                for doc_type, doc_reason in rejected_docs.items():
                    meta_attr = f"{doc_type}_meta"
                    if hasattr(doc_row, meta_attr):
                        meta = getattr(doc_row, meta_attr)
                        meta = dict(meta) if meta else {}
                        meta['status'] = 'rejected'
                        meta['remarks'] = doc_reason
                        setattr(doc_row, meta_attr, meta)
                        flag_modified(doc_row, meta_attr)
            else:
                # Reject all documents
                for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature', 'quotation']:
                    meta_attr = f"{doc_type}_meta"
                    if hasattr(doc_row, meta_attr):
                        meta = getattr(doc_row, meta_attr)
                        meta = dict(meta) if meta else {}
                        meta['status'] = 'rejected'
                        meta['remarks'] = reason
                        setattr(doc_row, meta_attr, meta)
                        flag_modified(doc_row, meta_attr)
        
        db.session.commit()
        return jsonify({"message": "Vendor rejected successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Reject vendor error: {e}")
        return jsonify({"error": "Failed to reject vendor"}), 500


@bp.route('/riders/<int:rider_id>/approve', methods=['POST'])
@admin_required
def approve_rider(rider_id):
    """
    POST /api/admin/riders/<rider_id>/approve
    Approve rider verification request
    """
    try:
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        rider.verification_status = 'approved'
        
        # Update all document statuses to approved
        doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
        if doc_row:
            from sqlalchemy.orm.attributes import flag_modified
            for doc_type in ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']:
                meta_attr = f"{doc_type}_meta"
                if hasattr(doc_row, meta_attr):
                    meta = getattr(doc_row, meta_attr)
                    if meta:
                        meta = dict(meta) if isinstance(meta, dict) else {}
                        meta['status'] = 'approved'
                        setattr(doc_row, meta_attr, meta)
                        flag_modified(doc_row, meta_attr)
        
        # Create notification
        notif = Notification(
            user_id=rider_id,
            user_type='rider',
            title='Verification Approved',
            message='Your account verification has been approved. You can now start accepting deliveries.',
            type='verification'
        )
        db.session.add(notif)
        
        db.session.commit()
        return jsonify({"message": "Rider approved successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Approve rider error: {e}")
        return jsonify({"error": "Failed to approve rider"}), 500


@bp.route('/riders/<int:rider_id>/reject', methods=['POST'])
@admin_required
def reject_rider(rider_id):
    """
    POST /api/admin/riders/<rider_id>/reject
    Reject rider verification request
    """
    try:
        data = request.get_json()
        reason = data.get('reason', 'Documents rejected')
        
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        rider.verification_status = 'rejected'
        rider.admin_remarks = reason
        
        db.session.commit()
        return jsonify({"message": "Rider rejected successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Reject rider error: {e}")
        return jsonify({"error": "Failed to reject rider"}), 500


@bp.route('/quotation-submissions', methods=['GET'])
@admin_required
def get_quotation_submissions():
    """
    GET /api/admin/quotation-submissions
    Get all pending quotation submissions
    """
    try:
        submissions = VendorQuotationSubmission.query.filter_by(status='pending').all()
        
        result = []
        for sub in submissions:
            vendor = Vendor.query.get(sub.vendor_id)
            if vendor:
                result.append({
                    "id": sub.id,
                    "vendor_id": sub.vendor_id,
                    "vendor_name": vendor.business_name or vendor.username or "Unknown",
                    "proposed_commission_rate": float(sub.proposed_commission_rate) if sub.proposed_commission_rate else 0,
                    "filename": sub.quotation_filename or "No file",
                    "submitted_at": sub.submitted_at.isoformat() if sub.submitted_at else None,
                    "status": sub.status or "pending"
                })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get quotation submissions error: {e}")
        return jsonify({"error": "Failed to retrieve quotation submissions"}), 500


@bp.route('/quotation-submissions/<int:submission_id>/approve', methods=['POST'])
@admin_required
def approve_quotation_submission(submission_id):
    """
    POST /api/admin/quotation-submissions/<submission_id>/approve
    Approve quotation submission
    """
    try:
        data = request.get_json()
        final_commission_rate = data.get('commission_rate')
        
        if not final_commission_rate:
            return jsonify({"error": "Commission rate is required"}), 400
        
        submission = VendorQuotationSubmission.query.get(submission_id)
        if not submission:
            return jsonify({"error": "Submission not found"}), 404
        
        if submission.status == 'approved':
            return jsonify({"error": "This submission is already approved"}), 400
        
        vendor = Vendor.query.get(submission.vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # Update submission status
        submission.status = 'approved'
        submission.reviewed_at = datetime.utcnow()
        submission.admin_remarks = data.get('remarks', 'Approved')
        
        # Update vendor's commission rate
        vendor.commission_rate = float(final_commission_rate)
        
        db.session.commit()
        
        # Create notification
        notif = Notification(
            user_id=vendor.id,
            user_type='vendor',
            title='Quotation Approved',
            message=f'Your quotation has been approved with a commission rate of {final_commission_rate}%.',
            type='verification'
        )
        db.session.add(notif)
        db.session.commit()
        
        return jsonify({"message": "Quotation approved successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Approve quotation error: {e}")
        return jsonify({"error": "Failed to approve quotation"}), 500


@bp.route('/quotation-submissions/<int:submission_id>/reject', methods=['POST'])
@admin_required
def reject_quotation_submission(submission_id):
    """
    POST /api/admin/quotation-submissions/<submission_id>/reject
    Reject quotation submission
    """
    try:
        data = request.get_json()
        remarks = data.get('remarks', 'Quotation rejected')
        
        submission = VendorQuotationSubmission.query.get(submission_id)
        if not submission:
            return jsonify({"error": "Submission not found"}), 404
        
        submission.status = 'rejected'
        submission.admin_remarks = remarks
        submission.reviewed_at = datetime.utcnow()
        
        # Create notification
        notif = Notification(
            user_id=submission.vendor_id,
            user_type='vendor',
            title='Quotation Rejected',
            message=f'Your quotation was rejected. Reason: {remarks}. Please re-submit.',
            type='verification'
        )
        db.session.add(notif)
        
        db.session.commit()
        return jsonify({"message": "Quotation rejected successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Reject quotation error: {e}")
        return jsonify({"error": "Failed to reject quotation"}), 500


@bp.route('/production-orders', methods=['GET'])
@admin_required
def get_production_orders():
    """
    GET /api/admin/production-orders
    Get all orders currently in production
    """
    try:
        production_statuses = [
            'assigned', 'accepted_by_vendor', 'in_production', 'material_prep',
            'printing', 'printing_completed', 'quality_check', 'packed_ready'
        ]
        
        orders = Order.query.filter(
            Order.status.in_(production_statuses),
            Order.selected_vendor_id.isnot(None)
        ).all()
        
        result = []
        for o in orders:
            vendor = Vendor.query.get(o.selected_vendor_id)
            customer = Customer.query.get(o.customer_id)
            
            # Progress calculation
            status_order = ['assigned', 'accepted_by_vendor', 'material_prep', 'printing', 
                          'printing_completed', 'quality_check', 'packed_ready']
            current_status = o.status
            if current_status == 'in_production':
                current_status = 'material_prep'
            
            try:
                progress = ((status_order.index(current_status) + 1) / len(status_order)) * 100
            except (ValueError, AttributeError):
                progress = 0
            
            result.append({
                "id": f"ORD-{o.id:03d}" if isinstance(o.id, int) else o.id,
                "db_id": o.id,
                "customerName": customer.username if customer else "Unknown",
                "vendorName": vendor.business_name if vendor else "Unknown",
                "productType": o.product_type,
                "quantity": o.quantity,
                "status": o.status,
                "progress": round(progress, 1),
                "deadline": o.delivery_date,
                "created_at": o.created_at.isoformat() if o.created_at else None
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get production orders error: {e}")
        return jsonify({"error": "Failed to retrieve production orders"}), 500


@bp.route('/vendor-requests', methods=['GET'])
@admin_required
def get_vendor_requests():
    """
    GET /api/admin/vendor-requests
    Get all pending vendor verification requests
    """
    try:
        vendors = Vendor.query.filter(
            Vendor.verification_status.in_(['pending', 'under-review'])
        ).all()
        
        result = []
        for v in vendors:
            try:
                doc_row = VendorDocument.query.filter_by(vendor_id=v.id).first()
                documents = {}
                if doc_row:
                    for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature']:
                        if hasattr(doc_row, f"{doc_type}_meta"):
                            meta = getattr(doc_row, f"{doc_type}_meta")
                            if meta:
                                doc_data = {
                                    'status': meta.get('status', 'pending'),
                                    'fileName': meta.get('filename'),
                                    'fileSize': meta.get('size'),
                                    'uploadedDate': meta.get('uploaded_at')
                                }
                                if doc_type == 'pan':
                                    doc_data['pan_number'] = doc_row.pan_number
                                if doc_type == 'aadhar':
                                    doc_data['aadhar_number'] = doc_row.aadhar_number
                                if doc_type == 'gst':
                                    doc_data['gst_number'] = doc_row.gst_number
                                if doc_type == 'bank':
                                    doc_data['bank_account_number'] = doc_row.bank_account_number
                                    doc_data['bank_holder_name'] = doc_row.bank_holder_name
                                    doc_data['bank_branch'] = doc_row.bank_branch
                                    doc_data['ifsc_code'] = doc_row.ifsc_code
                                documents[doc_type] = doc_data
                
                result.append({
                    "id": v.id,
                    "name": v.business_name or v.username or "Unknown",
                    "businessType": v.business_type or "N/A",
                    "submitted": v.created_at.strftime('%Y-%m-%d') if v.created_at else "N/A",
                    "status": v.verification_status or "pending",
                    "documents": documents,
                    "contact": {
                        "email": v.email or "N/A",
                        "phone": v.phone or "N/A"
                    },
                    "address": v.address or "N/A",
                    "adminRemarks": v.admin_remarks or ""
                })
            except Exception:
                pass
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor requests error: {e}")
        return jsonify({"error": "Failed to retrieve vendor requests"}), 500


@bp.route('/rejected-vendors', methods=['GET'])
@admin_required
def get_rejected_vendors():
    """
    GET /api/admin/rejected-vendors
    Get all rejected vendors
    """
    try:
        vendors = Vendor.query.filter_by(verification_status='rejected').all()
        
        result = []
        for v in vendors:
            try:
                doc_row = VendorDocument.query.filter_by(vendor_id=v.id).first()
                documents = {}
                if doc_row:
                    for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature']:
                        if hasattr(doc_row, f"{doc_type}_meta"):
                            meta = getattr(doc_row, f"{doc_type}_meta")
                            if meta:
                                doc_data = {
                                    'status': meta.get('status', 'pending'),
                                    'fileName': meta.get('filename'),
                                    'fileSize': meta.get('size'),
                                    'uploadedDate': meta.get('uploaded_at'),
                                    'adminRemarks': meta.get('remarks')
                                }
                                documents[doc_type] = doc_data
                
                result.append({
                    'id': v.id,
                    'name': v.username or 'Unknown',
                    'businessName': v.business_name,
                    'email': v.email,
                    'phone': v.phone,
                    'status': v.verification_status,
                    'submitted': v.created_at.strftime('%Y-%m-%d') if v.created_at else "N/A",
                    'adminRemarks': v.admin_remarks,
                    'documents': documents
                })
            except Exception as e:
                app_logger.error(f"Error processing vendor {v.id}: {e}")
                continue
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get rejected vendors error: {e}")
        return jsonify({"error": "Failed to retrieve rejected vendors"}), 500


@bp.route('/vendor-requests/<int:vendor_id>/delete', methods=['DELETE'])
@admin_required
def delete_vendor_request(vendor_id):
    """
    DELETE /api/admin/vendor-requests/<vendor_id>/delete
    Delete vendor verification request to allow re-submission
    """
    try:
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        vendor.verification_status = 'not-submitted'
        vendor.admin_remarks = None
        
        doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
        if doc_row:
            db.session.delete(doc_row)
        
        db.session.commit()
        return jsonify({"message": "Vendor request deleted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Delete vendor request error: {e}")
        return jsonify({"error": "Failed to delete vendor request"}), 500


@bp.route('/vendor-requests/<int:vendor_id>/document/<doc_type>/status', methods=['POST'])
@admin_required
def update_vendor_document_status(vendor_id, doc_type):
    """
    POST /api/admin/vendor-requests/<vendor_id>/document/<doc_type>/status
    Update status of a specific vendor document
    """
    try:
        data = request.get_json()
        status = data.get('status')
        reason = data.get('reason')
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
        if not doc_row:
            return jsonify({"error": "Documents not initialized"}), 404
        
        if not hasattr(doc_row, f"{doc_type}_meta"):
            return jsonify({"error": "Invalid document type"}), 400
        
        meta = getattr(doc_row, f"{doc_type}_meta") or {}
        meta = dict(meta) if isinstance(meta, dict) else {}
        
        meta['status'] = status
        if status == 'rejected':
            if reason:
                meta['remarks'] = reason
            vendor.verification_status = 'rejected'
            if not vendor.admin_remarks:
                vendor.admin_remarks = "Please review rejected documents."
        elif status == 'approved':
            meta['remarks'] = None
        
        setattr(doc_row, f"{doc_type}_meta", meta)
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(doc_row, f"{doc_type}_meta")
        
        db.session.commit()
        return jsonify({"message": "Document status updated"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update vendor document status error: {e}")
        return jsonify({"error": "Failed to update document status"}), 500


@bp.route('/verified-vendors', methods=['GET'])
@admin_required
def get_verified_vendors():
    """
    GET /api/admin/verified-vendors
    Get all verified vendors
    """
    try:
        vendors = Vendor.query.filter(
            Vendor.verification_status.in_(['approved', 'active'])
        ).all()
        
        result = []
        for v in vendors:
            result.append({
                "id": v.id,
                "name": v.business_name or v.username or "Unknown",
                "businessType": v.business_type or "N/A",
                "email": v.email or "N/A",
                "phone": v.phone or "N/A",
                "address": v.address or "N/A",
                "status": v.verification_status or "unknown",
                "commissionRate": float(v.commission_rate) if v.commission_rate is not None else 0,
                "paymentCycle": v.payment_cycle or "monthly",
                "serviceZone": v.service_zone or "N/A",
                "joinedDate": v.created_at.strftime('%Y-%m-%d') if v.created_at else "N/A"
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get verified vendors error: {e}")
        return jsonify({"error": "Failed to retrieve verified vendors"}), 500


@bp.route('/rider-requests', methods=['GET'])
@admin_required
def get_rider_requests():
    """
    GET /api/admin/rider-requests
    Get all pending rider verification requests
    """
    try:
        riders = Rider.query.filter(
            Rider.verification_status.in_(['pending', 'under-review'])
        ).all()
        
        result = []
        for r in riders:
            try:
                doc_row = RiderDocument.query.filter_by(rider_id=r.id).first()
                documents = {}
                if doc_row:
                    for doc_type in ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']:
                        if hasattr(doc_row, f"{doc_type}_meta"):
                            meta = getattr(doc_row, f"{doc_type}_meta")
                            if meta:
                                doc_data = {
                                    'status': meta.get('status', 'pending'),
                                    'fileName': meta.get('filename'),
                                    'fileSize': meta.get('size'),
                                    'uploadedDate': meta.get('uploaded_at')
                                }
                                if doc_type == 'aadhar':
                                    doc_data['aadhar_number'] = doc_row.aadhar_number
                                if doc_type == 'pan':
                                    doc_data['pan_number'] = doc_row.pan_number
                                if doc_type == 'dl':
                                    doc_data['dl_number'] = doc_row.dl_number
                                    doc_data['dl_name'] = doc_row.dl_name
                                    doc_data['dl_validity'] = doc_row.dl_validity
                                if doc_type == 'vehicle_rc':
                                    doc_data['vehicle_rc_number'] = doc_row.vehicle_rc_number
                                if doc_type == 'insurance':
                                    doc_data['insurance_policy_number'] = doc_row.insurance_policy_number
                                if doc_type == 'bank':
                                    doc_data['bank_account_number'] = doc_row.bank_account_number
                                    doc_data['bank_holder_name'] = doc_row.bank_holder_name
                                    doc_data['bank_branch'] = doc_row.bank_branch
                                    doc_data['ifsc_code'] = doc_row.ifsc_code
                                documents[doc_type] = doc_data
                
                result.append({
                    "id": r.id,
                    "name": r.name or "Unknown",
                    "email": r.email or "N/A",
                    "phone": r.phone or "N/A",
                    "vehicleType": r.vehicle_type or "N/A",
                    "vehicleNumber": r.vehicle_number or "N/A",
                    "serviceZone": r.service_zone or "N/A",
                    "submitted": r.created_at.strftime('%Y-%m-%d') if r.created_at else "N/A",
                    "status": r.verification_status or "pending",
                    "documents": documents,
                    "adminRemarks": r.admin_remarks or ""
                })
            except Exception as e:
                app_logger.error(f"Error processing rider {r.id}: {e}")
                continue
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get rider requests error: {e}")
        return jsonify({"error": "Failed to retrieve rider requests"}), 500


@bp.route('/rejected-riders', methods=['GET'])
@admin_required
def get_rejected_riders():
    """
    GET /api/admin/rejected-riders
    Get all rejected riders
    """
    try:
        riders = Rider.query.filter_by(verification_status='rejected').all()
        
        result = []
        for r in riders:
            try:
                doc_row = RiderDocument.query.filter_by(rider_id=r.id).first()
                documents = {}
                if doc_row:
                    for doc_type in ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']:
                        if hasattr(doc_row, f"{doc_type}_meta"):
                            meta = getattr(doc_row, f"{doc_type}_meta")
                            if meta:
                                doc_data = {
                                    'status': meta.get('status', 'pending'),
                                    'fileName': meta.get('filename'),
                                    'fileSize': meta.get('size'),
                                    'uploadedDate': meta.get('uploaded_at'),
                                    'adminRemarks': meta.get('remarks')
                                }
                                documents[doc_type] = doc_data
                
                result.append({
                    'id': r.id,
                    'name': r.name or 'Unknown',
                    'email': r.email,
                    'phone': r.phone,
                    'status': r.verification_status,
                    'submitted': r.created_at.strftime('%Y-%m-%d') if r.created_at else "N/A",
                    'adminRemarks': r.admin_remarks,
                    'documents': documents
                })
            except Exception as e:
                app_logger.error(f"Error processing rider {r.id}: {e}")
                continue
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get rejected riders error: {e}")
        return jsonify({"error": "Failed to retrieve rejected riders"}), 500


@bp.route('/rider-requests/<int:rider_id>/document/<doc_type>/status', methods=['POST'])
@admin_required
def update_rider_document_status(rider_id, doc_type):
    """
    POST /api/admin/rider-requests/<rider_id>/document/<doc_type>/status
    Update status of a specific rider document
    """
    try:
        data = request.get_json()
        status = data.get('status')
        reason = data.get('reason')
        
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
        if not doc_row:
            return jsonify({"error": "Documents not initialized"}), 404
        
        if not hasattr(doc_row, f"{doc_type}_meta"):
            return jsonify({"error": "Invalid document type"}), 400
        
        meta = getattr(doc_row, f"{doc_type}_meta") or {}
        meta = dict(meta) if isinstance(meta, dict) else {}
        
        meta['status'] = status
        if status == 'rejected':
            if reason:
                meta['remarks'] = reason
            rider.verification_status = 'rejected'
            if not rider.admin_remarks:
                rider.admin_remarks = "Please review rejected documents."
        elif status == 'approved':
            meta['remarks'] = None
        
        setattr(doc_row, f"{doc_type}_meta", meta)
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(doc_row, f"{doc_type}_meta")
        
        db.session.commit()
        return jsonify({"message": "Document status updated"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update rider document status error: {e}")
        return jsonify({"error": "Failed to update document status"}), 500


@bp.route('/verified-riders', methods=['GET'])
@admin_required
def get_verified_riders():
    """
    GET /api/admin/verified-riders
    Get all verified riders
    """
    try:
        riders = Rider.query.filter(
            Rider.verification_status.in_(['active', 'approved'])
        ).all()
        
        result = []
        for r in riders:
            result.append({
                "id": r.id,
                "name": r.name or "Unknown",
                "email": r.email or "N/A",
                "phone": r.phone or "N/A",
                "vehicleType": r.vehicle_type or "N/A",
                "vehicleNumber": r.vehicle_number or "N/A",
                "serviceZone": r.service_zone or "N/A",
                "status": r.verification_status or "unknown",
                "isOnline": r.is_online or False,
                "totalDeliveries": r.total_deliveries or 0,
                "successfulDeliveries": r.successful_deliveries or 0,
                "joinedDate": r.created_at.strftime('%Y-%m-%d') if r.created_at else "N/A"
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get verified riders error: {e}")
        return jsonify({"error": "Failed to retrieve verified riders"}), 500


@bp.route('/order-stats', methods=['GET'])
@admin_required
def get_order_stats():
    """
    GET /api/admin/order-stats
    Get order statistics for admin dashboard
    """
    try:
        new_orders_count = Order.query.filter(
            Order.status.in_([
                'pending_admin_review',
                'quotation_sent_to_customer',
                'sample_payment_received'
            ])
        ).count()
        
        production_count = Order.query.filter(
            Order.status.in_([
                'sample_requested',
                'awaiting_advance_payment',
                'in_production',
                'assigned',
                'vendor_assigned',
                'accepted_by_vendor'
            ])
        ).count()
        
        dispatch_count = Order.query.filter(
            Order.status.in_([
                'awaiting_dispatch',
                'ready_for_dispatch',
                'awaiting_delivery',
                'reached_vendor',
                'picked_up',
                'out_for_delivery',
                'packed_ready',
                'dispatched'
            ])
        ).count()
        
        completed_count = Order.query.filter(
            Order.status.in_([
                'completed',
                'completed_with_penalty',
                'delivered'
            ])
        ).count()
        
        return jsonify({
            "newOrders": new_orders_count,
            "inProduction": production_count,
            "readyDispatch": dispatch_count,
            "completed": completed_count
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get order stats error: {e}")
        return jsonify({"error": "Failed to retrieve order stats"}), 500


@bp.route('/notifications', methods=['GET'])
@admin_required
def get_notifications():
    """
    GET /api/admin/notifications
    Get admin notifications
    """
    try:
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        query = Notification.query.filter_by(user_type='admin')
        
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
        app_logger.exception(f"Get admin notifications error: {e}")
        return jsonify({"error": "Failed to retrieve notifications"}), 500


@bp.route('/notifications/<int:notif_id>/read', methods=['POST'])
@admin_required
def mark_notification_read(notif_id):
    """
    POST /api/admin/notifications/<notif_id>/read
    Mark notification as read
    """
    try:
        notif = Notification.query.get(notif_id)
        if not notif:
            return jsonify({"error": "Notification not found"}), 404
        
        notif.is_read = True
        db.session.commit()
        
        return jsonify({"message": "Notification marked as read"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Mark notification read error: {e}")
        return jsonify({"error": "Failed to mark notification as read"}), 500


@bp.route('/profile', methods=['GET'])
@admin_required
def get_admin_profile():
    """
    GET /api/admin/profile
    Get admin profile information
    """
    try:
        admin = Admin.query.get(request.user_id)
        if not admin:
            return jsonify({"error": "Admin not found"}), 404
        
        admin_data = {
            "id": admin.id,
            "username": admin.username,
            "created_at": admin.created_at.isoformat() if admin.created_at else None
        }
        
        return jsonify(admin_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get admin profile error: {e}")
        return jsonify({"error": "Failed to retrieve profile"}), 500


@bp.route('/profile', methods=['PUT'])
@admin_required
def update_admin_profile():
    """
    PUT /api/admin/profile
    Update admin profile information
    """
    try:
        data = request.get_json()
        admin = Admin.query.get(request.user_id)
        
        if not admin:
            return jsonify({"error": "Admin not found"}), 404
        
        # Update allowed fields
        allowed_fields = ['username']
        for field in allowed_fields:
            if field in data:
                setattr(admin, field, data[field])
        
        db.session.commit()
        
        return jsonify({"message": "Profile updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update admin profile error: {e}")
        return jsonify({"error": "Failed to update profile"}), 500


@bp.route('/change-password', methods=['PUT'])
@admin_required
def change_password():
    """
    PUT /api/admin/change-password
    Change admin password
    """
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({"error": "Current password and new password are required"}), 400
        
        admin = Admin.query.get(request.user_id)
        if not admin:
            return jsonify({"error": "Admin not found"}), 404
        
        from werkzeug.security import check_password_hash, generate_password_hash
        if not check_password_hash(admin.password_hash, current_password):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        admin.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({"message": "Password changed successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Change password error: {e}")
        return jsonify({"error": "Failed to change password"}), 500


@bp.route('/product-catalog', methods=['GET'])
@admin_required
def get_product_catalog():
    """
    GET /api/admin/product-catalog
    Get all products in catalog
    """
    try:
        from app.models import ProductCatalog
        products = ProductCatalog.query.all()
        
        result = []
        for p in products:
            result.append({
                'id': p.id,
                'product_type': p.product_type,
                'category': p.category,
                'neck_type': p.neck_type,
                'fabric': p.fabric,
                'size': p.size,
                'average_price': float(p.average_price) if p.average_price else 0,
                'vendor_count': p.vendor_count or 0,
                'notes': p.notes,
                'updated_at': p.updated_at.isoformat() if p.updated_at else None
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get product catalog error: {e}")
        return jsonify({"error": "Failed to retrieve product catalog"}), 500


@bp.route('/quotations/stats', methods=['GET'])
@admin_required
def get_quotation_stats():
    """
    GET /api/admin/quotations/stats
    Get quotation statistics
    """
    try:
        from app.models import VendorQuotation
        total_quotations = VendorQuotation.query.count()
        vendors_with_quotations = db.session.query(VendorQuotation.vendor_id).distinct().count()
        pending_submissions = VendorQuotationSubmission.query.filter_by(status='pending').count()
        approved_submissions = VendorQuotationSubmission.query.filter_by(status='approved').count()
        
        return jsonify({
            'total_quotations': total_quotations,
            'total_vendors_with_quotations': vendors_with_quotations,
            'pending_submissions': pending_submissions,
            'approved_submissions': approved_submissions
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get quotation stats error: {e}")
        return jsonify({"error": "Failed to retrieve quotation stats"}), 500


@bp.route('/average-prices', methods=['GET'])
@admin_required
def get_average_prices():
    """
    GET /api/admin/average-prices
    Get average prices for products
    """
    try:
        from app.models import ProductCatalog, VendorQuotation
        products = ProductCatalog.query.filter(ProductCatalog.vendor_count > 0).all()
        
        result = []
        for p in products:
            quotations = VendorQuotation.query.filter_by(product_id=p.id, status='approved').all()
            min_price = min([float(q.base_cost) for q in quotations], default=float(p.average_price)) if quotations else float(p.average_price)
            max_price = max([float(q.base_cost) for q in quotations], default=float(p.average_price)) if quotations else float(p.average_price)
            
            result.append({
                'id': p.id,
                'product_type': p.product_type,
                'category': p.category,
                'neck_type': p.neck_type,
                'fabric': p.fabric,
                'size': p.size,
                'average_price': float(p.average_price) if p.average_price else 0,
                'min_price': min_price,
                'max_price': max_price,
                'vendor_count': p.vendor_count or 0,
                'updated_at': p.updated_at.isoformat() if p.updated_at else None
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get average prices error: {e}")
        return jsonify({"error": "Failed to retrieve average prices"}), 500


@bp.route('/vendor-quotations/<int:vendor_id>', methods=['GET'])
@admin_required
def get_vendor_quotations(vendor_id):
    """
    GET /api/admin/vendor-quotations/<vendor_id>
    Get all quotations for a vendor
    """
    try:
        from app.models import VendorQuotation, ProductCatalog
        quotations = VendorQuotation.query.filter_by(vendor_id=vendor_id).all()
        
        result = []
        for q in quotations:
            product = ProductCatalog.query.get(q.product_id)
            result.append({
                'id': q.id,
                'vendor_id': q.vendor_id,
                'product_id': q.product_id,
                'product_type': product.product_type if product else 'Unknown',
                'category': product.category if product else 'Unknown',
                'neck_type': product.neck_type if product else 'Unknown',
                'fabric': product.fabric if product else 'Unknown',
                'size': product.size if product else 'Unknown',
                'base_cost': float(q.base_cost) if q.base_cost else 0,
                'status': q.status,
                'created_at': q.created_at.isoformat() if q.created_at else None,
                'updated_at': q.updated_at.isoformat() if q.updated_at else None
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor quotations error: {e}")
        return jsonify({"error": "Failed to retrieve vendor quotations"}), 500


@bp.route('/assign-rider', methods=['POST'])
@admin_required
def assign_rider_proximity():
    """
    POST /api/admin/assign-rider
    Assign nearest available rider to an order based on vendor location
    Uses proximity-based matching algorithm
    """
    try:
        data = request.get_json()
        order_id = data.get('order_id')
        vendor_id = data.get('vendor_id')
        max_radius_km = data.get('max_radius_km', 10)  # Default 10km radius
        
        if not order_id or not vendor_id:
            return jsonify({
                "error": "order_id and vendor_id are required"
            }), 400
        
        # Call the proximity assignment function
        result = assign_nearest_rider_to_order(
            order_id=order_id,
            vendor_id=vendor_id,
            max_search_radius_km=max_radius_km
        )
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        app_logger.exception(f"Assign rider error: {e}")
        return jsonify({"error": "Failed to assign rider"}), 500


@bp.route('/find-nearby-riders', methods=['POST'])
@admin_required
def find_nearby_riders():
    """
    POST /api/admin/find-nearby-riders
    Find all available riders near a vendor location
    Returns sorted list by distance for manual selection
    """
    try:
        data = request.get_json()
        vendor_id = data.get('vendor_id')
        max_radius_km = data.get('max_radius_km', 10)
        limit = data.get('limit', 10)
        
        if not vendor_id:
            return jsonify({"error": "vendor_id is required"}), 400
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        if not vendor.latitude or not vendor.longitude:
            return jsonify({
                "error": "Vendor location not set",
                "message": "Please update vendor profile with GPS coordinates"
            }), 400
        
        # Find nearby riders
        nearby_riders = find_nearest_riders(
            vendor.latitude,
            vendor.longitude,
            max_distance_km=max_radius_km,
            limit=limit
        )
        
        if not nearby_riders:
            return jsonify({
                "message": f"No riders found within {max_radius_km}km",
                "riders": [],
                "vendor": {
                    "id": vendor.id,
                    "name": vendor.business_name,
                    "latitude": vendor.latitude,
                    "longitude": vendor.longitude
                }
            }), 200
        
        # Format response
        riders_list = []
        for rider, distance in nearby_riders:
            stats = get_rider_delivery_stats(rider.id)
            riders_list.append({
                "rider_id": rider.id,
                "name": rider.name,
                "phone": rider.phone,
                "vehicle_type": rider.vehicle_type,
                "distance_km": round(distance, 2),
                "is_online": rider.is_online,
                "stats": stats,
                "current_location": {
                    "latitude": rider.latitude,
                    "longitude": rider.longitude
                }
            })
        
        return jsonify({
            "message": f"Found {len(riders_list)} riders within {max_radius_km}km",
            "riders": riders_list,
            "vendor": {
                "id": vendor.id,
                "name": vendor.business_name,
                "address": vendor.address,
                "city": vendor.city,
                "latitude": vendor.latitude,
                "longitude": vendor.longitude
            }
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Find nearby riders error: {e}")
        return jsonify({"error": "Failed to find nearby riders"}), 500
