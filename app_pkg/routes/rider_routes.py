"""
Rider Routes Blueprint
Handles rider-specific endpoints for deliveries, earnings, and profile management
"""
from flask import Blueprint, request, jsonify, send_file, current_app
from datetime import datetime, timedelta
import os

from app_pkg.models import (
    db, Rider, RiderDocument, DeliveryLog, DeliveryPartner, Order,
    Notification, OrderStatusHistory, OTPLog, Customer
)
from app_pkg.auth import login_required, role_required
from app_pkg.file_upload import validate_and_save_file, delete_file, get_file_path_from_db
from app_pkg.logger_config import app_logger
from app_pkg.activity_logger import log_activity_from_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Create blueprint
bp = Blueprint('rider', __name__, url_prefix='/api/rider')

# Custom key function for rate limiting by rider ID
def get_rider_id_for_rate_limit():
    """Get rider ID from request for rate limiting"""
    try:
        if hasattr(request, 'user_id') and request.user_id:
            return f"rider:{request.user_id}"
    except Exception:
        pass
    return get_remote_address()


@bp.route('/profile', methods=['GET'])
@login_required
@role_required(['rider'])
def get_rider_profile():
    """
    GET /api/rider/profile
    Get rider profile information
    """
    try:
        rider = Rider.query.get(request.user_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        rider_data = {
            "id": rider.id,
            "name": rider.name,
            "email": rider.email,
            "phone": rider.phone,
            "verification_status": rider.verification_status,
            "vehicle_type": rider.vehicle_type,
            "vehicle_number": rider.vehicle_number,
            "service_zone": rider.service_zone,
            "created_at": rider.created_at.isoformat() if rider.created_at else None
        }
        
        return jsonify(rider_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get rider profile error: {e}")
        return jsonify({"error": "Failed to retrieve profile"}), 500


@bp.route('/profile', methods=['PUT'])
@login_required
@role_required(['rider'])
def update_rider_profile():
    """
    PUT /api/rider/profile
    Update rider profile information
    """
    try:
        data = request.get_json()
        rider = Rider.query.get(request.user_id)
        
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        # Update allowed fields
        allowed_fields = ['phone', 'vehicle_type', 'vehicle_number', 'service_zone']
        for field in allowed_fields:
            if field in data:
                setattr(rider, field, data[field])
        
        rider.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"message": "Profile updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update rider profile error: {e}")
        return jsonify({"error": "Failed to update profile"}), 500


@bp.route('/deliveries/history', methods=['GET'])
@login_required
@role_required(['rider'])
def get_delivery_history():
    """
    GET /api/rider/deliveries/history
    Get delivery history for this rider
    """
    try:
        deliveries = DeliveryLog.query.filter_by(
            assigned_rider_id=request.user_id
        ).order_by(DeliveryLog.created_at.desc()).all()
        
        deliveries_data = [{
            "id": d.id,
            "order_id": d.order_id,
            "status": d.status,
            "assigned_at": d.assigned_at.isoformat() if d.assigned_at else None,
            "delivered_at": d.delivered_at.isoformat() if d.delivered_at else None
        } for d in deliveries]
        
        return jsonify({
            "deliveries": deliveries_data,
            "count": len(deliveries_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get delivery history error: {e}")
        return jsonify({"error": "Failed to retrieve delivery history"}), 500


@bp.route('/earnings', methods=['GET'])
@login_required
@role_required(['rider'])
def get_earnings():
    """
    GET /api/rider/earnings
    Get earnings statistics for this rider
    """
    try:
        # Calculate earnings from delivery logs
        completed_deliveries = DeliveryLog.query.filter_by(
            assigned_rider_id=request.user_id,
            status='delivered'
        ).all()
        
        total_deliveries = len(completed_deliveries)
        
        # Single source of truth: Calculate earnings from DeliveryLog only
        # This is transactional and cannot diverge from stored values
        total_earnings = sum(d.total_earning or 0 for d in completed_deliveries)
        
        # Calculate paid amount from deliveries with payout_status='paid'
        paid_deliveries = [d for d in completed_deliveries if getattr(d, 'payout_status', None) == 'paid']
        paid_amount = sum(d.total_earning or 0 for d in paid_deliveries)
        
        earnings_data = {
            "total_deliveries": total_deliveries,
            "total_earnings": float(total_earnings),
            "pending_payment": float(total_earnings - paid_amount),
            "paid_amount": float(paid_amount)
        }
        
        return jsonify(earnings_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get earnings error: {e}")
        return jsonify({"error": "Failed to retrieve earnings"}), 500


@bp.route('/verification/upload', methods=['POST'])
@login_required
@role_required(['rider'])
def upload_verification_document():
    """
    POST /api/rider/verification/upload
    Upload rider verification document
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['file']
        doc_type = request.form.get('doc_type')
        
        # Security: Use request.user_id instead of accepting rider_id from client
        # This ensures riders can only upload documents for themselves
        rider_id = request.user_id
        
        if not file or not doc_type:
            return jsonify({"error": "Missing required data"}), 400
        
        valid_types = ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']
        if doc_type not in valid_types:
            return jsonify({"error": "Invalid document type"}), 400
        
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        # Get or create document row
        doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
        if not doc_row:
            doc_row = RiderDocument(rider_id=rider_id)
            db.session.add(doc_row)
        
        # Validate and save file
        file_info, error = validate_and_save_file(
            file=file,
            endpoint='/api/rider/verification/upload',
            subfolder='rider',
            user_id=rider_id,
            doc_type=doc_type,
            scan_virus=False
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        # Delete old file if exists
        old_path = getattr(doc_row, doc_type, None)
        if old_path:
            delete_file(old_path)
        
        # Store file path
        setattr(doc_row, doc_type, file_info['path'])
        
        # Store metadata
        meta = {
            'filename': file_info['filename'],
            'original_filename': file_info['original_filename'],
            'mimetype': file_info['mimetype'],
            'size': file_info['size'],
            'uploaded_at': datetime.utcnow().isoformat(),
            'status': 'uploaded'
        }
        setattr(doc_row, f"{doc_type}_meta", meta)
        
        # Save manual fields if provided
        if doc_type == 'aadhar' and request.form.get('aadhar_number'):
            doc_row.aadhar_number = request.form.get('aadhar_number')
        if doc_type == 'pan' and request.form.get('pan_number'):
            doc_row.pan_number = request.form.get('pan_number')
        if doc_type == 'dl':
            if request.form.get('dl_number'):
                doc_row.dl_number = request.form.get('dl_number')
            if request.form.get('dl_name'):
                doc_row.dl_name = request.form.get('dl_name')
            if request.form.get('dl_validity'):
                doc_row.dl_validity = request.form.get('dl_validity')
        if doc_type == 'vehicle_rc' and request.form.get('vehicle_rc_number'):
            doc_row.vehicle_rc_number = request.form.get('vehicle_rc_number')
        if doc_type == 'insurance' and request.form.get('insurance_policy_number'):
            doc_row.insurance_policy_number = request.form.get('insurance_policy_number')
        if doc_type == 'bank':
            if request.form.get('bank_account_number'):
                doc_row.bank_account_number = request.form.get('bank_account_number')
            if request.form.get('bank_holder_name'):
                doc_row.bank_holder_name = request.form.get('bank_holder_name')
            if request.form.get('bank_branch'):
                doc_row.bank_branch = request.form.get('bank_branch')
            if request.form.get('ifsc_code'):
                doc_row.ifsc_code = request.form.get('ifsc_code')
        
        db.session.commit()
        
        return jsonify({
            "message": "Document uploaded successfully",
            "fileUrl": f"/api/rider/verification/document/{doc_type}"
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Upload rider document error: {e}")
        return jsonify({"error": "Failed to upload document"}), 500


@bp.route('/verification/submit', methods=['POST'])
@login_required
@role_required(['rider'])
def submit_verification():
    """
    POST /api/rider/verification/submit
    Submit rider verification for admin review
    """
    try:
        data = request.get_json()
        
        # Security: Use request.user_id instead of accepting rider_id from client
        # This ensures riders can only submit verification for themselves
        rider_id = request.user_id
        
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        # Update manual fields in RiderDocument
        doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
        if not doc_row:
            doc_row = RiderDocument(rider_id=rider_id)
            db.session.add(doc_row)
        
        if data.get('aadhar_number'):
            doc_row.aadhar_number = data.get('aadhar_number')
        if data.get('pan_number'):
            doc_row.pan_number = data.get('pan_number')
        if data.get('dl_number'):
            doc_row.dl_number = data.get('dl_number')
        if data.get('dl_name'):
            doc_row.dl_name = data.get('dl_name')
        if data.get('dl_validity'):
            doc_row.dl_validity = data.get('dl_validity')
        if data.get('vehicle_rc_number'):
            doc_row.vehicle_rc_number = data.get('vehicle_rc_number')
        if data.get('insurance_policy_number'):
            doc_row.insurance_policy_number = data.get('insurance_policy_number')
        if data.get('bank_account_number'):
            doc_row.bank_account_number = data.get('bank_account_number')
        if data.get('bank_holder_name'):
            doc_row.bank_holder_name = data.get('bank_holder_name')
        if data.get('bank_branch'):
            doc_row.bank_branch = data.get('bank_branch')
        if data.get('ifsc_code'):
            doc_row.ifsc_code = data.get('ifsc_code')
        
        rider.verification_status = 'pending'
        db.session.commit()
        
        return jsonify({"message": "Verification submitted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Submit verification error: {e}")
        return jsonify({"error": "Failed to submit verification"}), 500


@bp.route('/verification/status', methods=['GET'])
@login_required
@role_required(['rider'])
def get_verification_status():
    """
    GET /api/rider/verification/status
    Get rider verification status and documents
    """
    try:
        rider = Rider.query.get(request.user_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        doc_row = RiderDocument.query.filter_by(rider_id=request.user_id).first()
        if not doc_row:
            doc_row = RiderDocument(rider_id=request.user_id)
            db.session.add(doc_row)
            db.session.commit()
        
        documents = {}
        for doc_type in ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']:
            meta = getattr(doc_row, f"{doc_type}_meta")
            doc_data = {}
            
            if meta:
                doc_data = {
                    'status': meta.get('status', 'pending'),
                    'fileName': meta.get('filename'),
                    'fileSize': meta.get('size'),
                    'uploadedDate': meta.get('uploaded_at'),
                    'adminRemarks': meta.get('remarks', '')
                }
            else:
                doc_data = {
                    'status': 'pending',
                    'fileName': None,
                    'fileSize': None,
                    'uploadedDate': None,
                    'adminRemarks': ''
                }
            
            # Add manual fields
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
        
        return jsonify({
            "status": rider.verification_status or "not-submitted",
            "documents": documents,
            "adminRemarks": rider.admin_remarks or ""
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get verification status error: {e}")
        return jsonify({"error": "Failed to retrieve verification status"}), 500


@bp.route('/verification/document/<doc_type>', methods=['GET'])
@login_required
@role_required(['rider'])
def get_verification_document(doc_type):
    """
    GET /api/rider/verification/document/<doc_type>
    Get rider verification document
    """
    try:
        doc_row = RiderDocument.query.filter_by(rider_id=request.user_id).first()
        if not doc_row:
            return jsonify({"error": "No documents found"}), 404
        
        file_path = getattr(doc_row, doc_type)
        if not file_path:
            return jsonify({"error": "Document not found"}), 404
        
        absolute_path = get_file_path_from_db(file_path)
        
        if not absolute_path or not os.path.exists(absolute_path):
            return jsonify({"error": "File not found on disk"}), 404
        
        meta = getattr(doc_row, f"{doc_type}_meta")
        mimetype = meta.get('mimetype', 'application/octet-stream') if meta else 'application/octet-stream'
        filename = meta.get('filename', f'{doc_type}.pdf') if meta else f'{doc_type}.pdf'
        
        return send_file(
            absolute_path,
            mimetype=mimetype,
            as_attachment=False,
            download_name=filename
        )
        
    except Exception as e:
        app_logger.exception(f"Get rider document error: {e}")
        return jsonify({"error": "Failed to retrieve document"}), 500


@bp.route('/update-vehicle', methods=['POST'])
@login_required
@role_required(['rider'])
def update_vehicle():
    """
    POST /api/rider/update-vehicle
    Update rider vehicle details
    """
    try:
        data = request.get_json()
        vehicle_type = data.get('vehicle_type')
        vehicle_number = data.get('vehicle_number')
        service_zone = data.get('service_zone')
        
        rider = Rider.query.get(request.user_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        if vehicle_type:
            rider.vehicle_type = vehicle_type
        if vehicle_number:
            rider.vehicle_number = vehicle_number
        if service_zone:
            rider.service_zone = service_zone
        
        db.session.commit()
        return jsonify({"message": "Vehicle details updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update vehicle error: {e}")
        return jsonify({"error": "Failed to update vehicle details"}), 500


@bp.route('/update-presence', methods=['GET', 'POST'])
@login_required
@role_required(['rider'])
def update_presence():
    """
    GET/POST /api/rider/update-presence
    Update rider online status and GPS coordinates
    """
    if request.method == 'GET':
        rider = Rider.query.get(request.user_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        return jsonify({
            "is_online": rider.is_online,
            "latitude": rider.latitude,
            "longitude": rider.longitude
        }), 200
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        is_online = data.get('is_online')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        rider = Rider.query.get(request.user_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        if is_online is not None:
            rider.is_online = bool(is_online)
            if rider.is_online:
                rider.last_online_at = datetime.utcnow()
        
        if latitude is not None and longitude is not None:
            rider.latitude = float(latitude)
            rider.longitude = float(longitude)
            # Note: Reverse geocoding would require Mappls API integration
        
        db.session.commit()
        return jsonify({
            "message": "Rider presence updated",
            "is_online": rider.is_online,
            "current_address": rider.current_address
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update presence error: {e}")
        return jsonify({"error": "Failed to update presence"}), 500


@bp.route('/status', methods=['GET'])
@login_required
@role_required(['rider'])
def get_status():
    """
    GET /api/rider/status
    Get rider status with real-time stats
    """
    try:
        rider = Rider.query.get(request.user_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        # Calculate real-time stats
        try:
            total_assigned = DeliveryLog.query.filter_by(assigned_rider_id=request.user_id).count()
            
            pending_pickup = DeliveryLog.query.filter(
                (DeliveryLog.assigned_rider_id == request.user_id),
                (DeliveryLog.status.in_(['assigned', 'reached_vendor']))
            ).count()
            
            out_for_delivery = DeliveryLog.query.filter(
                (DeliveryLog.assigned_rider_id == request.user_id),
                (DeliveryLog.status.in_(['picked_up', 'out_for_delivery']))
            ).count()
            
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            completed_today_query = DeliveryLog.query.filter(
                (DeliveryLog.assigned_rider_id == request.user_id),
                (DeliveryLog.status == 'delivered'),
                (DeliveryLog.delivered_at >= today_start)
            )
            completed_today = completed_today_query.count()
            earnings_today = sum(d.total_earning or 0 for d in completed_today_query.all())
            
            week_start = today_start - timedelta(days=7)
            month_start = today_start - timedelta(days=30)
            
            earnings_week = sum(d.total_earning or 0 for d in DeliveryLog.query.filter(
                (DeliveryLog.assigned_rider_id == request.user_id),
                (DeliveryLog.status == 'delivered'),
                (DeliveryLog.delivered_at >= week_start)
            ).all())
            
            earnings_month = sum(d.total_earning or 0 for d in DeliveryLog.query.filter(
                (DeliveryLog.assigned_rider_id == request.user_id),
                (DeliveryLog.status == 'delivered'),
                (DeliveryLog.delivered_at >= month_start)
            ).all())
            
            pending_payout = sum(d.total_earning or 0 for d in DeliveryLog.query.filter(
                (DeliveryLog.assigned_rider_id == request.user_id),
                (DeliveryLog.payout_status == 'pending')
            ).all())
        except Exception:
            total_assigned = pending_pickup = out_for_delivery = completed_today = 0
            earnings_today = earnings_week = earnings_month = pending_payout = 0
        
        return jsonify({
            "id": rider.id,
            "name": rider.name,
            "is_online": rider.is_online,
            "verification_status": rider.verification_status,
            "stats": {
                "total_assigned": total_assigned,
                "pending_pickup": pending_pickup,
                "out_for_delivery": out_for_delivery,
                "completed_today": completed_today,
                "earnings_today": round(earnings_today, 2),
                "earnings_week": round(earnings_week, 2),
                "earnings_month": round(earnings_month, 2),
                "pending_payout": round(pending_payout, 2)
            }
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get rider status error: {e}")
        return jsonify({"error": "Failed to retrieve rider status"}), 500


@bp.route('/deliveries/assigned', methods=['GET'])
@login_required
@role_required(['rider'])
def get_assigned_deliveries():
    """
    GET /api/rider/deliveries/assigned
    Get all assigned deliveries with full details (excludes delivered/completed)
    """
    try:
        # Consistency: Always filter by assigned_rider_id first (security)
        # Then exclude completed deliveries to show only active assignments
        deliveries = DeliveryLog.query.filter(
            DeliveryLog.assigned_rider_id == request.user_id,
            DeliveryLog.status != 'delivered'
        ).all()
        
        result = []
        for d in deliveries:
            order = Order.query.get(d.order_id)
            result.append({
                "id": d.id,
                "order_id": d.order_id,
                "status": d.status,
                "pickup": {
                    "address": d.vendor_address,
                    "contact": d.vendor_contact
                },
                "delivery": {
                    "address": d.customer_address,
                    "contact": d.customer_contact
                },
                "deadline": order.delivery_date.isoformat() if order and order.delivery_date else None,
                "is_urgent": d.is_urgent or False,
                "product_details": {
                    "type": order.category if order else "Items",
                    "quantity": order.quantity if order else 1
                }
            })
        
        return jsonify({"deliveries": result}), 200
        
    except Exception as e:
        app_logger.exception(f"Get assigned deliveries error: {e}")
        return jsonify({"error": "Failed to retrieve deliveries"}), 500


@bp.route('/deliveries/<int:delivery_id>/status', methods=['PUT'])
@login_required
@role_required(['rider'])
def update_delivery_status(delivery_id):
    """
    PUT /api/rider/deliveries/<delivery_id>/status
    Update delivery status with location tracking
    """
    try:
        data = request.get_json()
        status = data.get('status')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        delivery = DeliveryLog.query.get(delivery_id)
        if not delivery:
            return jsonify({"error": "Delivery not found"}), 404
        
        if delivery.assigned_rider_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        # Validate rider can only set specific statuses
        allowed_rider_statuses = ['reached_vendor', 'picked_up', 'out_for_delivery', 'delivered']
        if status not in allowed_rider_statuses:
            return jsonify({"error": f"Invalid status. Riders can only set: {', '.join(allowed_rider_statuses)}"}), 400
        
        # Get order to validate current state
        order = Order.query.get(delivery.order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        # Validate status transition - prevent skipping workflow states
        # Riders can only progress through delivery stages in sequence
        # CRITICAL: Rider can only set 'reached_vendor' when order is 'ready_for_pickup'
        # This ensures vendor has finished packing before rider arrives
        current_order_status = order.status
        valid_transitions = {
            'reached_vendor': ['ready_for_pickup'],  # Only allow when vendor has marked ready
            'picked_up': ['reached_vendor'],
            'out_for_delivery': ['picked_up'],
            'delivered': ['out_for_delivery']
        }
        
        if status in valid_transitions:
            if current_order_status not in valid_transitions[status]:
                return jsonify({
                    "error": f"Cannot set status to '{status}'. Order must be in one of: {', '.join(valid_transitions[status])}. Current status: {current_order_status}"
                }), 400
        
        delivery.status = status
        
        # Record timestamp and GPS location based on status
        if status == 'reached_vendor':
            delivery.reached_vendor_at = datetime.utcnow()
            if latitude and longitude:
                delivery.current_latitude = latitude
                delivery.current_longitude = longitude
                delivery.last_location_update = datetime.utcnow()
        elif status == 'picked_up':
            delivery.picked_up_at = datetime.utcnow()
        elif status == 'out_for_delivery':
            delivery.out_for_delivery_at = datetime.utcnow()
        elif status == 'delivered':
            delivery.delivered_at = datetime.utcnow()
        
        # Update order status and create history
        status_labels = {
            'reached_vendor': 'Rider Reached Vendor',
            'picked_up': 'Order Picked Up',
            'out_for_delivery': 'Out for Delivery',
            'delivered': 'Order Delivered'
        }
        
        order.status = status
        history = OrderStatusHistory(
            order_id=order.id,
            status=status,
            status_label=status_labels[status],
            changed_by_type='rider',
            changed_by_id=request.user_id,
            notes=data.get('notes', '')
        )
        db.session.add(history)
        
        db.session.commit()
        
        # Log activity
        status_label = status_labels.get(status, status.replace('_', ' ').title())
        log_activity_from_request(
            action=f"Updated delivery status for Order #{order.id} to {status_label}",
            action_type="delivery_update",
            entity_type="order",
            entity_id=order.id,
            details=data.get('notes', '')
        )
        
        return jsonify({"message": f"Delivery status updated to {status}"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update delivery status error: {e}")
        return jsonify({"error": "Failed to update delivery status"}), 500


@bp.route('/deliveries/<int:delivery_id>/pickup-proof', methods=['POST'])
@login_required
@role_required(['rider'])
def upload_pickup_proof(delivery_id):
    """
    POST /api/rider/deliveries/<delivery_id>/pickup-proof
    Upload pickup proof image
    """
    try:
        delivery = DeliveryLog.query.get(delivery_id)
        if not delivery:
            return jsonify({"error": "Delivery not found"}), 404
        
        if delivery.assigned_rider_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        file = request.files.get('proof_image')
        notes = request.form.get('notes', '')
        
        if file:
            file_info, error = validate_and_save_file(
                file=file,
                endpoint='/api/rider/deliveries/pickup-proof',
                subfolder='rider',
                user_id=request.user_id,
                doc_type='pickup_proof',
                scan_virus=False
            )
            if error:
                return jsonify({"error": error}), 400
            
            if delivery.pickup_proof:
                delete_file(delivery.pickup_proof)
            
            delivery.pickup_proof = file_info['path']
            delivery.pickup_proof_filename = file_info['filename']
        
        delivery.notes = notes
        delivery.status = 'picked_up'
        delivery.picked_up_at = datetime.utcnow()
        
        order = Order.query.get(delivery.order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        # Validate status transition - can only set picked_up from reached_vendor
        current_order_status = order.status
        valid_pickup_states = ['reached_vendor']
        if current_order_status not in valid_pickup_states:
            return jsonify({
                "error": f"Cannot mark as picked up. Order must be in 'reached_vendor' status. Current status: {current_order_status}"
            }), 400
        
        order.status = 'picked_up'
        history = OrderStatusHistory(
            order_id=order.id,
            status='picked_up',
            status_label='Order Picked Up',
            changed_by_type='rider',
            changed_by_id=request.user_id,
            notes=f'Pickup proof uploaded. Notes: {notes}'
        )
        db.session.add(history)
        
        db.session.commit()
        return jsonify({"message": "Pickup proof uploaded and marked as picked up"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Upload pickup proof error: {e}")
        return jsonify({"error": "Failed to upload pickup proof"}), 500


@bp.route('/deliveries/<int:delivery_id>/delivery-proof', methods=['POST'])
@login_required
@role_required(['rider'])
def upload_delivery_proof(delivery_id):
    """
    POST /api/rider/deliveries/<delivery_id>/delivery-proof
    Upload delivery proof and complete delivery
    """
    try:
        delivery = DeliveryLog.query.get(delivery_id)
        if not delivery:
            return jsonify({"error": "Delivery not found"}), 404
        
        if delivery.assigned_rider_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        file = request.files.get('proof_image')
        otp = request.form.get('otp', '')
        notes = request.form.get('notes', '')
        
        # CRITICAL: Verify OTP before allowing delivery completion
        # This prevents fraud - rider cannot complete delivery without customer OTP
        if not otp:
            return jsonify({"error": "OTP is required for delivery completion"}), 400
        
        # Get order and customer to verify OTP
        order = Order.query.get(delivery.order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        customer = Customer.query.get(order.customer_id)
        if not customer:
            return jsonify({"error": "Customer not found"}), 404
        
        # Verify OTP from OTPLog - check recent OTPs for customer's phone/email
        # CRITICAL: This prevents fraud - rider cannot complete delivery without valid customer OTP
        recent_otp = OTPLog.query.filter(
            OTPLog.recipient.in_([customer.phone, customer.email]),
            OTPLog.otp_code == otp,
            OTPLog.status == 'sent',
            OTPLog.expires_at >= datetime.utcnow()
        ).order_by(OTPLog.created_at.desc()).first()
        
        if not recent_otp:
            return jsonify({"error": "Invalid or expired OTP. Please verify with customer."}), 400
        
        # Mark OTP as used to prevent reuse
        recent_otp.status = 'verified'
        
        if file:
            file_info, error = validate_and_save_file(
                file=file,
                endpoint='/api/rider/deliveries/delivery-proof',
                subfolder='rider',
                user_id=request.user_id,
                doc_type='delivery_proof',
                scan_virus=False
            )
            if error:
                return jsonify({"error": error}), 400
            
            if delivery.delivery_proof:
                delete_file(delivery.delivery_proof)
            
            delivery.delivery_proof = file_info['path']
            delivery.delivery_proof_filename = file_info['filename']
        
        delivery.status = 'delivered'
        delivery.delivered_at = datetime.utcnow()
        delivery.delivery_time = datetime.utcnow()
        delivery.notes = (delivery.notes or "") + f" | Delivery notes: {notes}"
        delivery.delivery_otp = otp
        delivery.otp_verified = True  # Mark OTP as verified
        
        # Calculate earnings
        delivery.base_payout = 40.0
        delivery.total_earning = 50.0
        delivery.payout_status = 'pending'
        
        # Order already fetched above for OTP verification
        
        # Validate status transition - can only set delivered from out_for_delivery
        current_order_status = order.status
        valid_delivery_states = ['out_for_delivery']
        if current_order_status not in valid_delivery_states:
            return jsonify({
                "error": f"Cannot mark as delivered. Order must be in 'out_for_delivery' status. Current status: {current_order_status}"
            }), 400
        
        order.status = 'delivered'
        history = OrderStatusHistory(
            order_id=order.id,
            status='delivered',
            status_label='Order Delivered',
            changed_by_type='rider',
            changed_by_id=request.user_id
        )
        db.session.add(history)
        
        db.session.commit()
        
        # Log activity
        log_activity_from_request(
            action=f"Completed delivery for Order #{order.id} with OTP verification",
            action_type="delivery_update",
            entity_type="order",
            entity_id=order.id,
            details=f"Delivery proof uploaded, OTP verified, Earnings: ₹50.0"
        )
        
        return jsonify({
            "message": "Delivery completed successfully",
            "earnings": {"total": 50.0}
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Upload delivery proof error: {e}")
        return jsonify({"error": "Failed to upload delivery proof"}), 500


@bp.route('/deliveries/<int:delivery_id>/location', methods=['PUT'])
@login_required
@role_required(['rider'])
def update_live_location(delivery_id):
    """
    PUT /api/rider/deliveries/<delivery_id>/location
    Update live location during delivery
    Rate limited to prevent spam and DB overload (1 update per 5 seconds per rider)
    """
    # Rate limit: 1 update per 5 seconds per rider
    # This prevents spam attacks while allowing reasonable tracking frequency
    # Use in-memory tracking for simplicity (can be upgraded to Redis in production)
    if not hasattr(update_live_location, '_last_update'):
        update_live_location._last_update = {}
    
    rider_id = request.user_id
    current_time = datetime.utcnow().timestamp()
    last_update = update_live_location._last_update.get(rider_id, 0)
    
    if current_time - last_update < 5:  # 5 seconds
        return jsonify({
            "error": "Rate limit exceeded. Please wait before updating location again.",
            "retry_after": max(1, int(5 - (current_time - last_update)))
        }), 429
    
    # Update last update time
    update_live_location._last_update[rider_id] = current_time
    
    try:
        data = request.get_json()
        lat = data.get('latitude')
        lon = data.get('longitude')
        
        delivery = DeliveryLog.query.get(delivery_id)
        if not delivery:
            return jsonify({"error": "Delivery not found"}), 404
        
        if delivery.assigned_rider_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        delivery.current_latitude = lat
        delivery.current_longitude = lon
        delivery.last_location_update = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"message": "Location updated"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update location error: {e}")
        return jsonify({"error": "Failed to update location"}), 500


@bp.route('/deliveries/<int:delivery_id>/details', methods=['GET'])
@login_required
@role_required(['rider', 'admin', 'vendor', 'customer'])
def get_delivery_details(delivery_id):
    """
    GET /api/rider/deliveries/<delivery_id>/details
    Get full delivery details for a specific delivery
    """
    try:
        # Security: Use request.user_id instead of accepting rider_id from client
        # This ensures riders can only access their own deliveries
        delivery = DeliveryLog.query.filter_by(
            id=delivery_id,
            assigned_rider_id=request.user_id
        ).first()
        
        if not delivery:
            return jsonify({"error": "Delivery not found"}), 404
        
        # Get order details
        order = Order.query.get(delivery.order_id)
        
        return jsonify({
            "id": delivery.id,
            "order_id": delivery.order_id,
            "status": delivery.status,
            "is_urgent": delivery.is_urgent or False,
            "pickup": {
                "address": delivery.vendor_address,
                "contact": delivery.vendor_contact
            },
            "delivery": {
                "address": delivery.customer_address,
                "contact": delivery.customer_contact
            },
            "product_details": {
                "type": order.category if order else "Items",
                "quantity": order.quantity if order else 1,
                "fabric": order.fabric if order else None,
                "color": order.color if order else None
            },
            "assigned_at": delivery.assigned_at.isoformat() if delivery.assigned_at else None,
            "reached_vendor_at": delivery.reached_vendor_at.isoformat() if delivery.reached_vendor_at else None,
            "picked_up_at": delivery.picked_up_at.isoformat() if delivery.picked_up_at else None,
            "out_for_delivery_at": delivery.out_for_delivery_at.isoformat() if delivery.out_for_delivery_at else None,
            "delivered_at": delivery.delivered_at.isoformat() if delivery.delivered_at else None,
            "pickup_notes": delivery.pickup_notes,
            "delivery_notes": delivery.delivery_notes,
            "delivery_otp": delivery.delivery_otp
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get delivery details error: {e}")
        return jsonify({"error": "Failed to retrieve delivery details"}), 500


@bp.route('/notifications', methods=['GET'])
@login_required
@role_required(['rider'])
def get_notifications():
    """
    GET /api/rider/notifications
    Get rider notifications
    """
    try:
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'
        
        query = Notification.query.filter_by(user_id=request.user_id, user_type='rider')
        
        if unread_only:
            query = query.filter_by(is_read=False)
        
        notifs = query.order_by(Notification.created_at.desc()).all()
        
        return jsonify([{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'type': n.type,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat() if n.created_at else None
        } for n in notifs]), 200
        
    except Exception as e:
        app_logger.exception(f"Get rider notifications error: {e}")
        return jsonify({"error": "Failed to retrieve notifications"}), 500


@bp.route('/notifications/<int:notif_id>/read', methods=['POST'])
@login_required
@role_required(['rider'])
def mark_notification_read(notif_id):
    """
    POST /api/rider/notifications/<notif_id>/read
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


@bp.route('/change-password', methods=['PUT'])
@login_required
@role_required(['rider'])
def change_password():
    """
    PUT /api/rider/change-password
    Change rider password
    """
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({"error": "Current password and new password are required"}), 400
        
        rider = Rider.query.get(request.user_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        from werkzeug.security import check_password_hash, generate_password_hash
        if not check_password_hash(rider.password_hash, current_password):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        rider.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({"message": "Password changed successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Change password error: {e}")
        return jsonify({"error": "Failed to change password"}), 500
