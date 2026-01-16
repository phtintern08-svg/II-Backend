"""
Vendor Routes Blueprint
Handles vendor-specific endpoints for quotations, orders, and profile management
"""
from flask import Blueprint, request, jsonify, send_file
from datetime import datetime
import os

from app_pkg.models import (
    db, Vendor, VendorQuotation, VendorDocument, VendorOrderAssignment, Order,
    VendorQuotationSubmission, Notification, OrderStatusHistory, Customer
)
from app_pkg.auth import login_required, role_required
from app_pkg.file_upload import validate_and_save_file, delete_file, get_file_path_from_db
from app_pkg.logger_config import app_logger

# Create blueprint
bp = Blueprint('vendor', __name__, url_prefix='/vendor')


@bp.route('/profile', methods=['GET'])
@role_required(['vendor'])
def get_vendor_profile():
    """
    GET /api/vendor/profile
    Get vendor profile information
    """
    try:
        vendor = Vendor.query.get(request.user_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        vendor_data = {
            "id": vendor.id,
            "username": vendor.username,
            "email": vendor.email,
            "phone": vendor.phone,
            "business_name": vendor.business_name,
            "business_type": vendor.business_type,
            "address": vendor.address,
            "verification_status": vendor.verification_status,
            "commission_rate": float(vendor.commission_rate) if vendor.commission_rate else 0,
            "service_zone": vendor.service_zone,
            "created_at": vendor.created_at.isoformat() if vendor.created_at else None
        }
        
        return jsonify(vendor_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor profile error: {e}")
        return jsonify({"error": "Failed to retrieve profile"}), 500


@bp.route('/profile', methods=['PUT'])
@role_required(['vendor'])
def update_vendor_profile():
    """
    PUT /api/vendor/profile
    Update vendor profile information
    """
    try:
        data = request.get_json()
        vendor = Vendor.query.get(request.user_id)
        
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # Update allowed fields
        allowed_fields = ['business_name', 'phone', 'address', 'service_zone']
        for field in allowed_fields:
            if field in data:
                setattr(vendor, field, data[field])
        
        vendor.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({"message": "Profile updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update vendor profile error: {e}")
        return jsonify({"error": "Failed to update profile"}), 500


@bp.route('/quotations', methods=['GET'])
@role_required(['vendor'])
def get_vendor_quotations():
    """
    GET /api/vendor/quotations
    Get all quotations submitted by this vendor
    """
    try:
        quotations = VendorQuotation.query.filter_by(vendor_id=request.user_id).all()
        
        quotations_data = [{
            "id": q.id,
            "order_id": q.order_id,
            "quoted_price": float(q.quoted_price) if q.quoted_price else 0,
            "status": q.status,
            "submitted_at": q.submitted_at.isoformat() if q.submitted_at else None
        } for q in quotations]
        
        return jsonify({
            "quotations": quotations_data,
            "count": len(quotations_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor quotations error: {e}")
        return jsonify({"error": "Failed to retrieve quotations"}), 500


@bp.route('/quotations', methods=['POST'])
@role_required(['vendor'])
def submit_quotation():
    """
    POST /api/vendor/quotations
    Submit a new quotation for an order
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['order_id', 'quoted_price']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Business logic validation
        order = Order.query.get(data['order_id'])
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        # Check if vendor is eligible (verification status)
        vendor = Vendor.query.get(request.user_id)
        if not vendor or vendor.verification_status not in ['approved', 'active']:
            return jsonify({"error": "Vendor must be verified to submit quotations"}), 403
        
        # Check if quotation already exists
        existing = VendorQuotation.query.filter_by(
            vendor_id=request.user_id,
            order_id=data['order_id']
        ).first()
        
        if existing:
            # Update existing quotation
            existing.quoted_price = data['quoted_price']
            existing.status = 'pending'
            existing.submitted_at = datetime.utcnow()
            new_quotation = existing
        else:
            # Create new quotation
            new_quotation = VendorQuotation(
                vendor_id=request.user_id,
                order_id=data['order_id'],
                quoted_price=data['quoted_price'],
                status='pending',
                submitted_at=datetime.utcnow()
            )
            db.session.add(new_quotation)
        
        db.session.add(new_quotation)
        db.session.commit()
        
        return jsonify({
            "message": "Quotation submitted successfully",
            "quotation_id": new_quotation.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Submit quotation error: {e}")
        return jsonify({"error": "Failed to submit quotation"}), 500


@bp.route('/orders', methods=['GET'])
@role_required(['vendor'])
def get_vendor_orders():
    """
    GET /api/vendor/orders
    Get all orders assigned to this vendor
    """
    try:
        # Get orders assigned to this vendor
        vendor_orders = Order.query.filter_by(selected_vendor_id=request.user_id).all()
        
        # Also get from VendorOrderAssignment for additional metadata
        assignments = VendorOrderAssignment.query.filter_by(vendor_id=request.user_id).all()
        assignment_map = {a.order_id: a for a in assignments}
        
        orders_data = []
        for order in vendor_orders:
            assignment = assignment_map.get(order.id)
            orders_data.append({
                "id": order.id,
                "customer_id": order.customer_id,
                "product_type": order.product_type,
                "quantity": order.quantity,
                "status": order.status,
                "assigned_at": assignment.assigned_at.isoformat() if assignment and assignment.assigned_at else None,
                "created_at": order.created_at.isoformat() if order.created_at else None
            })
        
        return jsonify({
            "orders": orders_data,
            "count": len(orders_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/verification/upload', methods=['POST'])
@role_required(['vendor'])
def upload_verification_document():
    """
    POST /api/vendor/verification/upload
    Upload vendor verification document
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['file']
        # SECURITY: Always use vendor_id from JWT, never from request body
        vendor_id = request.user_id
        doc_type = request.form.get('doc_type')
        
        if not file or not doc_type:
            return jsonify({"error": "Missing required data"}), 400
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # Validate and save file
        file_info, error = validate_and_save_file(
            file=file,
            endpoint='/api/vendor/verification/upload',
            subfolder='vendor',
            user_id=int(vendor_id),
            doc_type=doc_type,
            scan_virus=False
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        # Get or create document row
        doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
        if not doc_row:
            doc_row = VendorDocument(vendor_id=vendor_id)
            db.session.add(doc_row)
        
        # Store file path
        if hasattr(doc_row, doc_type):
            old_path = getattr(doc_row, doc_type, None)
            if old_path:
                delete_file(old_path)
            
            setattr(doc_row, doc_type, file_info['path'])
            
            # Update metadata
            meta = {
                'filename': file_info['filename'],
                'original_filename': file_info['original_filename'],
                'mimetype': file_info['mimetype'],
                'size': file_info['size'],
                'status': 'uploaded',
                'uploaded_at': datetime.utcnow().isoformat()
            }
            setattr(doc_row, f"{doc_type}_meta", meta)
            
            # Save manual fields if provided
            if doc_type == 'pan' and request.form.get('pan_number'):
                doc_row.pan_number = request.form.get('pan_number')
            if doc_type == 'aadhar' and request.form.get('aadhar_number'):
                doc_row.aadhar_number = request.form.get('aadhar_number')
            if doc_type == 'gst' and request.form.get('gst_number'):
                doc_row.gst_number = request.form.get('gst_number')
            if doc_type == 'bank':
                if request.form.get('bank_account_number'):
                    doc_row.bank_account_number = request.form.get('bank_account_number')
                if request.form.get('bank_holder_name'):
                    doc_row.bank_holder_name = request.form.get('bank_holder_name')
                if request.form.get('bank_branch'):
                    doc_row.bank_branch = request.form.get('bank_branch')
                if request.form.get('ifsc_code'):
                    doc_row.ifsc_code = request.form.get('ifsc_code')
            
            doc_row.updated_at = datetime.utcnow()
            db.session.commit()
            
            return jsonify({
                "message": "File uploaded successfully",
                "fileName": file_info['filename']
            }), 200
        else:
            return jsonify({"error": "Invalid document type"}), 400
            
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Upload vendor document error: {e}")
        return jsonify({"error": "Failed to upload document"}), 500


@bp.route('/verification/submit', methods=['POST'])
@role_required(['vendor'])
def submit_verification():
    """
    POST /api/vendor/verification/submit
    Submit vendor verification for admin review
    """
    try:
        data = request.get_json()
        # SECURITY: Always use vendor_id from JWT, never from request body
        vendor_id = request.user_id
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # Update manual fields in VendorDocument
        doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
        if not doc_row:
            doc_row = VendorDocument(vendor_id=vendor_id)
            db.session.add(doc_row)
        
        if data.get('pan_number'):
            doc_row.pan_number = data.get('pan_number')
        if data.get('aadhar_number'):
            doc_row.aadhar_number = data.get('aadhar_number')
        if data.get('gst_number'):
            doc_row.gst_number = data.get('gst_number')
        if data.get('bank_account_number'):
            doc_row.bank_account_number = data.get('bank_account_number')
        if data.get('bank_holder_name'):
            doc_row.bank_holder_name = data.get('bank_holder_name')
        if data.get('bank_branch'):
            doc_row.bank_branch = data.get('bank_branch')
        if data.get('ifsc_code'):
            doc_row.ifsc_code = data.get('ifsc_code')
        
        vendor.verification_status = 'pending'
        db.session.commit()
        
        return jsonify({"message": "Verification submitted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Submit verification error: {e}")
        return jsonify({"error": "Failed to submit verification"}), 500


@bp.route('/verification/status', methods=['GET'])
@role_required(['vendor'])
def get_verification_status():
    """
    GET /api/vendor/verification/status
    Get vendor verification status and documents
    """
    try:
        vendor = Vendor.query.get(request.user_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        doc_row = VendorDocument.query.filter_by(vendor_id=request.user_id).first()
        
        documents = {}
        if doc_row:
            from sqlalchemy.orm.attributes import flag_modified
            for doc_type in ['pan', 'aadhar', 'gst', 'business', 'bank', 'workshop', 'signature']:
                if hasattr(doc_row, f"{doc_type}_meta"):
                    meta = getattr(doc_row, f"{doc_type}_meta")
                    doc_data = {
                        'status': 'pending',
                        'fileName': '',
                        'uploadedDate': '',
                        'adminRemarks': ''
                    }
                    
                    if meta:
                        doc_data = {
                            'status': meta.get('status', 'pending'),
                            'fileName': meta.get('filename'),
                            'fileSize': meta.get('size'),
                            'uploadedDate': meta.get('uploaded_at'),
                            'adminRemarks': meta.get('remarks', '')
                        }
                    
                    # Add manual fields
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
        
        return jsonify({
            "status": vendor.verification_status or "not-submitted",
            "documents": documents,
            "admin_remarks": vendor.admin_remarks or ""
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get verification status error: {e}")
        return jsonify({"error": "Failed to retrieve verification status"}), 500


@bp.route('/verification/document/<doc_type>', methods=['GET'])
@role_required(['vendor'])
def get_verification_document(doc_type):
    """
    GET /api/vendor/verification/document/<doc_type>
    Get vendor verification document
    """
    try:
        doc_row = VendorDocument.query.filter_by(vendor_id=request.user_id).first()
        
        if not doc_row or not hasattr(doc_row, doc_type):
            return jsonify({"error": "Document not found"}), 404
        
        file_path = getattr(doc_row, doc_type)
        meta = getattr(doc_row, f"{doc_type}_meta")
        
        if not file_path or not meta:
            return jsonify({"error": "Document content missing"}), 404
        
        absolute_path = get_file_path_from_db(file_path)
        
        if not absolute_path or not os.path.exists(absolute_path):
            return jsonify({"error": "File not found on disk"}), 404
        
        return send_file(
            absolute_path,
            mimetype=meta.get('mimetype', 'application/octet-stream'),
            as_attachment=False,
            download_name=meta.get('filename', f'{doc_type}.pdf')
        )
        
    except Exception as e:
        app_logger.exception(f"Get vendor document error: {e}")
        return jsonify({"error": "Failed to retrieve document"}), 500


@bp.route('/quotation/submit', methods=['POST'])
@role_required(['vendor'])
def submit_quotation_file():
    """
    POST /api/vendor/quotation/submit
    Submit quotation file after approval
    """
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['file']
        # SECURITY: Always use vendor_id from JWT, never from request body
        vendor_id = request.user_id
        commission_rate = request.form.get('commission_rate')
        
        if not file or not commission_rate:
            return jsonify({"error": "Missing required data"}), 400
        
        if float(commission_rate) < 15:
            return jsonify({"error": "Commission rate must be at least 15%"}), 400
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        if vendor.verification_status != 'approved':
            return jsonify({"error": "Vendor must be approved first"}), 403
        
        # Validate and save file
        file_info, error = validate_and_save_file(
            file=file,
            endpoint='/api/vendor/quotation/submit',
            subfolder='vendor',
            user_id=int(vendor_id),
            doc_type='quotation',
            scan_virus=False
        )
        
        if error:
            return jsonify({"error": error}), 400
        
        # Check if submission already exists
        existing = VendorQuotationSubmission.query.filter_by(vendor_id=vendor_id).first()
        if existing:
            if existing.quotation_file:
                delete_file(existing.quotation_file)
            existing.quotation_file = file_info['path']
            existing.quotation_filename = file_info['filename']
            existing.quotation_mimetype = file_info['mimetype']
            existing.proposed_commission_rate = float(commission_rate)
            existing.status = 'pending'
            existing.submitted_at = datetime.utcnow()
        else:
            submission = VendorQuotationSubmission(
                vendor_id=vendor_id,
                quotation_file=file_info['path'],
                quotation_filename=file_info['filename'],
                quotation_mimetype=file_info['mimetype'],
                proposed_commission_rate=float(commission_rate)
            )
            db.session.add(submission)
        
        db.session.commit()
        return jsonify({"message": "Quotation submitted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Submit quotation error: {e}")
        return jsonify({"error": "Failed to submit quotation"}), 500


@bp.route('/quotation/status', methods=['GET'])
@role_required(['vendor'])
def get_quotation_status():
    """
    GET /api/vendor/quotation/status
    Get quotation submission status
    """
    try:
        submission = VendorQuotationSubmission.query.filter_by(vendor_id=request.user_id).first()
        
        if not submission:
            return jsonify({
                "submitted": False,
                "status": None
            }), 200
        
        return jsonify({
            "submitted": True,
            "status": submission.status,
            "proposed_commission_rate": float(submission.proposed_commission_rate) if submission.proposed_commission_rate else 0,
            "filename": submission.quotation_filename,
            "submitted_at": submission.submitted_at.isoformat() if submission.submitted_at else None,
            "admin_remarks": submission.admin_remarks
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get quotation status error: {e}")
        return jsonify({"error": "Failed to retrieve quotation status"}), 500


@bp.route('/orders', methods=['GET'])
@role_required(['vendor'])
def get_vendor_orders_filtered():
    """
    GET /api/vendor/orders
    Get vendor orders with status filter
    """
    try:
        status = request.args.get('status')
        
        query = Order.query.filter_by(selected_vendor_id=request.user_id)
        
        if status == 'new':
            query = query.filter_by(status='assigned')
        elif status == 'in_production':
            production_statuses = [
                'accepted_by_vendor', 'in_production', 'material_prep',
                'printing', 'printing_completed', 'quality_check'
            ]
            query = query.filter(Order.status.in_(production_statuses))
        elif status:
            query = query.filter_by(status=status)
        
        orders = query.all()
        
        result = []
        for o in orders:
            customer = Customer.query.get(o.customer_id)
            
            # Map status to stage for in_production
            current_stage = None
            if o.status == 'accepted_by_vendor':
                current_stage = 'accepted'
            elif o.status == 'material_prep':
                current_stage = 'material'
            elif o.status == 'printing':
                current_stage = 'printing'
            elif o.status == 'printing_completed':
                current_stage = 'completed'
            elif o.status == 'quality_check':
                current_stage = 'quality'
            elif o.status == 'packed_ready':
                current_stage = 'packed'
            
            order_data = {
                "id": f"ORD-{o.id:03d}" if isinstance(o.id, int) else o.id,
                "db_id": o.id,
                "customerName": customer.username if customer else "Unknown",
                "productType": o.product_type,
                "quantity": o.quantity,
                "status": o.status,
                "deadline": o.delivery_date,
                "created_at": o.created_at.isoformat() if o.created_at else None
            }
            
            if current_stage:
                order_data["currentStage"] = current_stage
                order_data["notes"] = o.feedback_comment or ""
            
            result.append(order_data)
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/dashboard/stats', methods=['GET'])
@role_required(['vendor'])
def get_dashboard_stats():
    """
    GET /api/vendor/dashboard/stats
    Get vendor dashboard statistics
    """
    try:
        vendor_id = request.user_id
        
        new_orders = Order.query.filter_by(selected_vendor_id=vendor_id, status='assigned').count()
        
        production_statuses = ['accepted_by_vendor', 'material_prep', 'printing', 'printing_completed', 'quality_check']
        in_production = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(production_statuses)
        ).count()
        
        ready_dispatch = Order.query.filter_by(selected_vendor_id=vendor_id, status='packed_ready').count()
        
        completed = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.like('completed%')
        ).count()
        
        return jsonify({
            "newOrders": new_orders,
            "inProduction": in_production,
            "readyForDispatch": ready_dispatch,
            "completed": completed
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor dashboard stats error: {e}")
        return jsonify({"error": "Failed to retrieve dashboard stats"}), 500


@bp.route('/notifications', methods=['GET'])
@role_required(['vendor'])
def get_notifications():
    """
    GET /api/vendor/notifications
    Get vendor notifications
    """
    try:
        notifs = Notification.query.filter_by(
            user_id=request.user_id,
            user_type='vendor'
        ).order_by(Notification.created_at.desc()).all()
        
        return jsonify([{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'type': n.type,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat() if n.created_at else None
        } for n in notifs]), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor notifications error: {e}")
        return jsonify({"error": "Failed to retrieve notifications"}), 500


@bp.route('/notifications/<int:notif_id>/read', methods=['POST'])
@role_required(['vendor'])
def mark_notification_read(notif_id):
    """
    POST /api/vendor/notifications/<notif_id>/read
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
        
        return jsonify({"message": "Marked as read"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Mark notification read error: {e}")
        return jsonify({"error": "Failed to mark notification as read"}), 500


@bp.route('/change-password', methods=['PUT'])
@role_required(['vendor'])
def change_password():
    """
    PUT /api/vendor/change-password
    Change vendor password
    """
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({"error": "Current password and new password are required"}), 400
        
        vendor = Vendor.query.get(request.user_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # Verify current password
        from werkzeug.security import check_password_hash
        if not check_password_hash(vendor.password_hash, current_password):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        # Update password
        from werkzeug.security import generate_password_hash
        vendor.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        return jsonify({"message": "Password changed successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Change password error: {e}")
        return jsonify({"error": "Failed to change password"}), 500


@bp.route('/orders/<int:order_id>/production-stage', methods=['PUT'])
@role_required(['vendor'])
def update_production_stage(order_id):
    """
    PUT /api/vendor/orders/<order_id>/production-stage
    Update production stage of an order
    """
    try:
        data = request.get_json()
        stage_id = data.get('stage_id')  # 'accepted', 'material', 'printing', etc.
        notes = data.get('notes', '')
        
        if not stage_id:
            return jsonify({"error": "stage_id is required"}), 400
        
        # Handle ORD- prefix if present
        actual_order_id = order_id
        if isinstance(order_id, str) and order_id.startswith('ORD-'):
            actual_order_id = int(order_id.replace('ORD-', ''))
        
        order = Order.query.get(actual_order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        if order.selected_vendor_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        # Map frontend stage_id to DB status
        status_map = {
            'accepted': 'accepted_by_vendor',
            'material': 'material_prep',
            'printing': 'printing',
            'completed': 'printing_completed',
            'quality': 'quality_check',
            'packed': 'packed_ready',
            'dispatched': 'dispatched',
            'delivered': 'delivered'
        }
        
        # Human-readable labels for notifications
        stage_labels = {
            'accepted': 'Order Accepted',
            'material': 'Material Preparation',
            'printing': 'Printing In Progress',
            'completed': 'Printing Completed',
            'quality': 'Quality Check',
            'packed': 'Packed & Ready for Dispatch',
            'dispatched': 'Order Dispatched',
            'delivered': 'Order Delivered'
        }
        
        new_status = status_map.get(stage_id, 'in_production')
        stage_label = stage_labels.get(stage_id, 'In Production')
        order.status = new_status
        
        # Record status history
        status_record = OrderStatusHistory(
            order_id=order.id,
            status=new_status,
            status_label=stage_label,
            changed_by_type='vendor',
            changed_by_id=request.user_id,
            notes=notes
        )
        db.session.add(status_record)
        
        # Notify Admin
        admin_notif = Notification(
            user_id=1,
            user_type='admin',
            title=f'Production Update: ORD-{order.id}',
            message=f'Order ORD-{order.id} has progressed to "{stage_label}". Vendor ID: {request.user_id}.',
            type='order'
        )
        db.session.add(admin_notif)
        
        # Notify Customer
        customer_notif = Notification(
            user_id=order.customer_id,
            user_type='customer',
            title=f'Your Order Update',
            message=f'Great news! Your order ORD-{order.id} is now in "{stage_label}" stage.',
            type='order'
        )
        db.session.add(customer_notif)
        
        db.session.commit()
        
        return jsonify({
            "message": "Production stage updated successfully",
            "new_status": new_status
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update production stage error: {e}")
        return jsonify({"error": "Failed to update production stage"}), 500


@bp.route('/orders/<int:order_id>/move-to-production', methods=['POST'])
@role_required(['vendor'])
def move_to_production(order_id):
    """
    POST /api/vendor/orders/<order_id>/move-to-production
    Move order directly to production
    """
    try:
        data = request.get_json()
        # SECURITY: Always use vendor_id from JWT, never from request body
        vendor_id = request.user_id
        
        # Handle ORD- prefix if present
        actual_order_id = order_id
        if isinstance(order_id, str) and order_id.startswith('ORD-'):
            actual_order_id = int(order_id.replace('ORD-', ''))
        
        order = Order.query.get(actual_order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        if order.selected_vendor_id != int(vendor_id):
            return jsonify({"error": "This order is not assigned to you"}), 403
        
        order.status = 'in_production'
        
        # Update formal assignment record
        assignment = VendorOrderAssignment.query.filter_by(
            order_id=actual_order_id,
            vendor_id=int(vendor_id)
        ).first()
        if assignment:
            assignment.status = 'accepted'
            assignment.responded_at = datetime.utcnow()
        
        # Record status history
        status_record = OrderStatusHistory(
            order_id=actual_order_id,
            status='in_production',
            status_label='In Production',
            changed_by_type='vendor',
            changed_by_id=int(vendor_id),
            notes='Vendor moved order directly to production'
        )
        db.session.add(status_record)
        
        db.session.commit()
        
        return jsonify({"message": "Order moved to production successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Move to production error: {e}")
        return jsonify({"error": "Failed to move order to production"}), 500


@bp.route('/orders/<int:order_id>/reject', methods=['POST'])
@role_required(['vendor'])
def reject_order(order_id):
    """
    POST /api/vendor/orders/<order_id>/reject
    Reject an assigned order
    """
    try:
        data = request.get_json()
        reason = data.get('reason', 'No reason provided')
        
        # Handle ORD- prefix if present
        actual_order_id = order_id
        if isinstance(order_id, str) and order_id.startswith('ORD-'):
            actual_order_id = int(order_id.replace('ORD-', ''))
        
        order = Order.query.get(actual_order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        if order.selected_vendor_id != request.user_id:
            return jsonify({"error": "This order is not assigned to you"}), 403
        
        order.status = 'rejected_by_vendor'
        order.selected_vendor_id = None
        
        # Update formal assignment record
        assignment = VendorOrderAssignment.query.filter_by(
            order_id=actual_order_id,
            vendor_id=request.user_id
        ).first()
        if assignment:
            assignment.status = 'rejected'
            assignment.rejection_reason = reason
            assignment.responded_at = datetime.utcnow()
        
        # Notify Admin
        admin_notif = Notification(
            user_id=1,
            user_type='admin',
            title='Order Rejected by Vendor',
            message=f'Vendor has rejected order #{actual_order_id}. Reason: {reason}',
            type='order'
        )
        db.session.add(admin_notif)
        
        db.session.commit()
        
        return jsonify({"message": "Order rejected successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Reject order error: {e}")
        return jsonify({"error": "Failed to reject order"}), 500


@bp.route('/update-location', methods=['POST'])
@role_required(['vendor'])
def update_location():
    """
    POST /api/vendor/update-location
    Update vendor GPS coordinates
    """
    try:
        data = request.get_json()
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        vendor = Vendor.query.get(request.user_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        if latitude is not None and longitude is not None:
            vendor.latitude = float(latitude)
            vendor.longitude = float(longitude)
        
        db.session.commit()
        return jsonify({"message": "Vendor location updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update location error: {e}")
        return jsonify({"error": "Failed to update location"}), 500


@bp.route('/update-location-details', methods=['POST'])
@role_required(['vendor'])
def update_location_details():
    """
    POST /api/vendor/update-location-details
    Update vendor shop location details
    """
    try:
        data = request.get_json()
        
        vendor = Vendor.query.get(request.user_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        if 'address' in data:
            vendor.address = data.get('address')
        if 'city' in data:
            vendor.city = data.get('city')
        if 'state' in data:
            vendor.state = data.get('state')
        if 'pincode' in data:
            vendor.pincode = data.get('pincode')
        if 'latitude' in data and data['latitude'] is not None:
            vendor.latitude = float(data['latitude'])
        if 'longitude' in data and data['longitude'] is not None:
            vendor.longitude = float(data['longitude'])
        
        db.session.commit()
        return jsonify({"message": "Shop location details updated successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update location details error: {e}")
        return jsonify({"error": "Failed to update location details"}), 500


@bp.route('/order-stats', methods=['GET'])
@role_required(['vendor'])
def get_order_stats():
    """
    GET /api/vendor/order-stats
    Get order statistics for vendor dashboard
    """
    try:
        vendor_id = request.user_id
        
        new_orders_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['assigned'])
        ).count()
        
        in_production_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['accepted_by_vendor', 'in_production', 'material_prep', 'printing', 'printing_completed', 'quality_check'])
        ).count()
        
        ready_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['ready_for_dispatch', 'packed_ready', 'ready_for_pickup'])
        ).count()
        
        completed_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['completed', 'completed_with_penalty', 'delivered'])
        ).count()
        
        return jsonify({
            "newOrders": new_orders_count,
            "inProduction": in_production_count,
            "readyForDispatch": ready_count,
            "completed": completed_count
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor order stats error: {e}")
        return jsonify({"error": "Failed to retrieve order stats"}), 500


@bp.route('/track-delivery/<int:delivery_id>', methods=['GET'])
@role_required(['vendor', 'admin', 'customer'])
def track_delivery(delivery_id):
    """
    GET /api/vendor/track-delivery/<delivery_id>
    Allow vendor to track assigned rider's live location during pickup
    """
    try:
        delivery = DeliveryLog.query.get(delivery_id)
        if not delivery:
            return jsonify({"error": "Delivery not found"}), 404
        
        # Get order and rider details
        order = Order.query.get(delivery.order_id)
        rider = Rider.query.get(delivery.assigned_rider_id)
        
        # Get vendor details (assuming vendor_id can be derived from order)
        vendor_id = order.selected_vendor_id if order else None
        vendor = Vendor.query.get(vendor_id) if vendor_id else None
        
        return jsonify({
            "delivery_id": delivery.id,
            "order_id": delivery.order_id,
            "status": delivery.status,
            "rider": {
                "id": rider.id if rider else None,
                "name": rider.name if rider else None,
                "phone": rider.phone if rider else None,
                "vehicle_type": rider.vehicle_type if rider else None
            },
            "rider_location": {
                "latitude": delivery.current_latitude,
                "longitude": delivery.current_longitude,
                "last_update": delivery.last_location_update.isoformat() if delivery.last_location_update else None
            } if delivery.current_latitude and delivery.current_longitude else None,
            "vendor_location": {
                "latitude": vendor.latitude if vendor else None,
                "longitude": vendor.longitude if vendor else None,
                "address": vendor.address if vendor else None
            },
            "product": {
                "type": order.category if order else None,
                "quantity": order.quantity if order else None
            },
            "assigned_at": delivery.assigned_at.isoformat() if delivery.assigned_at else None,
            "reached_vendor_at": delivery.reached_vendor_at.isoformat() if delivery.reached_vendor_at else None
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Track delivery error: {e}")
        return jsonify({"error": "Failed to track delivery"}), 500


@bp.route('/new-orders', methods=['GET'])
@role_required(['vendor'])
def get_new_orders():
    """
    GET /api/vendor/new-orders
    Get new orders assigned to vendor
    """
    try:
        orders = Order.query.filter_by(
            selected_vendor_id=request.user_id,
            status='assigned'
        ).all()
        
        result = []
        for o in orders:
            customer = Customer.query.get(o.customer_id)
            result.append({
                "id": f"ORD-{o.id:03d}" if isinstance(o.id, int) else o.id,
                "db_id": o.id,
                "customerName": customer.username if customer else "Unknown",
                "productType": o.product_type,
                "color": o.color,
                "size": o.sample_size or "N/A",
                "quantity": o.quantity,
                "customization": {
                    "printType": o.print_type,
                    "neckType": o.neck_type,
                    "fabric": o.fabric
                },
                "deadline": o.delivery_date,
                "assignedDate": o.created_at.isoformat() if o.created_at else None,
                "address": f"{o.address_line1}, {o.city}, {o.pincode}"
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get new orders error: {e}")
        return jsonify({"error": "Failed to retrieve new orders"}), 500
