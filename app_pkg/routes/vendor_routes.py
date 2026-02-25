"""
Vendor Routes Blueprint
Handles vendor-specific endpoints for quotations, orders, and profile management
"""
from flask import Blueprint, request, jsonify, send_file, current_app
from datetime import datetime
import os
import json
from sqlalchemy import text

from app_pkg.models import (
    db, Vendor, VendorQuotation, VendorDocument, VendorOrderAssignment, Order,
    VendorQuotationSubmission, Notification, OrderStatusHistory, Customer,
    DeliveryLog, Rider, VendorCapacity, ProductCatalog, MarketplaceProduct, CartProduct  # CartProduct for vendor-created products
)
from app_pkg.auth import login_required, role_required
from app_pkg.file_upload import validate_and_save_file, delete_file, get_file_path_from_db
from app_pkg.logger_config import app_logger
from app_pkg.activity_logger import log_activity_from_request
from app_pkg.schemas import vendor_orders_schema  # 🔥 Filtered schema for vendors (sample fields only)

# Create blueprint
bp = Blueprint('vendor', __name__, url_prefix='/api/vendor')


@bp.route('/profile', methods=['GET'])
@login_required
@role_required(['vendor'])
def get_vendor_profile():
    """
    GET /api/vendor/profile
    Get vendor profile information
    """
    try:
        # ✅ CRITICAL: Verify request.user_id is set by @login_required decorator
        user_id = getattr(request, 'user_id', None)
        role = getattr(request, 'role', None)
        
        if not user_id:
            app_logger.error("CRITICAL: request.user_id is None! Token authentication failed.")
            return jsonify({"error": "Authentication failed", "code": "USER_ID_NOT_SET"}), 401
        
        app_logger.info(f"TOKEN OK → user_id={user_id}, role={role}")
        
        vendor = Vendor.query.get(user_id)
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
            "bio": vendor.bio,
            "avatar_url": vendor.avatar_url,
            "verification_status": vendor.verification_status,
            "commission_rate": float(vendor.commission_rate) if vendor.commission_rate else 0,
            "service_zone": vendor.service_zone,
            "city": vendor.city,
            "state": vendor.state,
            "pincode": vendor.pincode,
            "latitude": float(vendor.latitude) if vendor.latitude else None,
            "longitude": float(vendor.longitude) if vendor.longitude else None,
            "current_address": vendor.current_address,
            "created_at": vendor.created_at.isoformat() if vendor.created_at else None
        }
        
        return jsonify(vendor_data), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor profile error: {e}")
        return jsonify({"error": "Failed to retrieve profile"}), 500


@bp.route('/profile', methods=['PUT'])
@login_required
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
        
        # Update allowed fields - expanded to match frontend expectations
        allowed_fields = [
            'business_name',
            'phone',
            'address',
            'service_zone',
            'business_type',
            'bio',
            'city',
            'state',
            'pincode',
            'latitude',
            'longitude',
            'current_address'
        ]
        for field in allowed_fields:
            if field in data:
                # Handle latitude/longitude conversion
                if field in ['latitude', 'longitude'] and data[field] is not None:
                    try:
                        setattr(vendor, field, float(data[field]))
                    except (ValueError, TypeError):
                        app_logger.warning(f"Invalid {field} value: {data[field]}")
                else:
                    setattr(vendor, field, data[field])
        
        db.session.commit()
        
        # Return updated profile data to frontend for sync
        vendor_data = {
            "id": vendor.id,
            "username": vendor.username,
            "email": vendor.email,
            "phone": vendor.phone,
            "business_name": vendor.business_name,
            "business_type": vendor.business_type,
            "address": vendor.address,
            "bio": vendor.bio,
            "avatar_url": vendor.avatar_url,
            "city": vendor.city,
            "state": vendor.state,
            "pincode": vendor.pincode,
            "latitude": float(vendor.latitude) if vendor.latitude else None,
            "longitude": float(vendor.longitude) if vendor.longitude else None,
            "service_zone": vendor.service_zone
        }
        
        return jsonify({
            "message": "Profile updated successfully",
            "profile": vendor_data
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update vendor profile error: {e}")
        return jsonify({"error": "Failed to update profile"}), 500


@bp.route('/quotations', methods=['GET'])
@login_required
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
@login_required
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
        
        # Log activity
        log_activity_from_request(
            action=f"Submitted quotation for Order #{data['order_id']} (Price: ₹{data['quoted_price']})",
            action_type="quotation_submission",
            entity_type="order",
            entity_id=data['order_id'],
            details=f"Quoted price: ₹{data['quoted_price']}"
        )
        
        return jsonify({
            "message": "Quotation submitted successfully",
            "quotation_id": new_quotation.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Submit quotation error: {e}")
        return jsonify({"error": "Failed to submit quotation"}), 500


@bp.route('/orders/all', methods=['GET'])
@login_required
@role_required(['vendor'])
def get_vendor_orders():
    """
    GET /api/vendor/orders/all
    Get all orders assigned to this vendor (SAMPLE FIELDS ONLY - no bulk details)
    🔥 SECURITY: Vendors should NOT see quantity, bulk pricing, or financial details
    """
    try:
        # Get orders assigned to this vendor
        vendor_orders = Order.query.filter_by(selected_vendor_id=request.user_id).all()
        
        # 🔥 SECURITY: Use filtered schema - only sample fields, no bulk details
        orders_data = vendor_orders_schema.dump(vendor_orders)
        
        return jsonify({
            "orders": orders_data,
            "count": len(orders_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/verification/upload', methods=['POST'])
@login_required
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
        
        # Debug logging
        file.seek(0)
        file_data = file.read()
        file.seek(0)  # Reset for validation
        file_size = len(file_data)
        file_ext = os.path.splitext(file.filename)[1].lower() if file.filename else ''
        
        app_logger.info(f"Upload attempt: vendor_id={vendor_id}, doc_type={doc_type}, filename={file.filename}, "
                    f"content_type={file.content_type}, size={file_size}, ext={file_ext}")
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404

        # SECURITY: Enforce upload rules - block non-compliant requests (Postman/DOM bypass)
        v_status = vendor.verification_status or 'not-submitted'
        if v_status in ('pending', 'approved'):
            return jsonify({"error": "Documents cannot be modified during or after approval"}), 403
        if v_status == 'rejected':
            doc_row_check = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
            doc_meta = None
            if doc_row_check and hasattr(doc_row_check, f"{doc_type}_meta"):
                doc_meta = getattr(doc_row_check, f"{doc_type}_meta") or {}
            doc_status = (doc_meta or {}).get('status', 'pending')
            if doc_status != 'rejected':
                return jsonify({"error": "Only rejected documents can be re-uploaded"}), 403
        
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
            app_logger.warning(f"Upload validation failed: vendor_id={vendor_id}, doc_type={doc_type}, "
                            f"filename={file.filename}, error={error}")
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
            
            # Get existing metadata to preserve rejected status if resubmitting
            existing_meta = getattr(doc_row, f"{doc_type}_meta") or {}
            existing_meta = dict(existing_meta) if isinstance(existing_meta, dict) else {}
            was_rejected = existing_meta.get('status') == 'rejected'
            
            # Update metadata
            meta = {
                'filename': file_info['filename'],
                'original_filename': file_info['original_filename'],
                'mimetype': file_info['mimetype'],
                'size': file_info['size'],
                'status': 'rejected' if was_rejected else 'uploaded',  # Keep rejected status if resubmitting rejected doc
                'uploaded_at': datetime.utcnow().isoformat(),
                'resubmitted': was_rejected  # Flag to indicate this is a resubmission
            }
            # Preserve admin remarks if resubmitting
            if was_rejected and existing_meta.get('remarks'):
                meta['remarks'] = existing_meta.get('remarks')
                meta['previous_rejection_reason'] = existing_meta.get('remarks')
            
            setattr(doc_row, f"{doc_type}_meta", meta)
            
            # Save manual fields if provided
            if doc_type == 'pan' and request.form.get('pan_number'):
                doc_row.pan_number = request.form.get('pan_number')
            if doc_type == 'aadhar' and request.form.get('aadhar_number'):
                doc_row.aadhar_number = request.form.get('aadhar_number')
            if doc_type == 'gst' and request.form.get('gst_number'):
                doc_row.gst_number = request.form.get('gst_number')
            if doc_type == 'business' and request.form.get('business_registration_number'):
                doc_row.business_registration_number = request.form.get('business_registration_number')
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
@login_required
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
        if data.get('business_registration_number'):
            doc_row.business_registration_number = data.get('business_registration_number')
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
        app_logger.info(f"Vendor {vendor_id} verification_status updated to {vendor.verification_status}")

        return jsonify({"message": "Verification submitted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Submit verification error: {e}")
        return jsonify({"error": "Failed to submit verification"}), 500


@bp.route('/verification/status', methods=['GET'])
@login_required
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
        db.session.refresh(vendor)

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
                    
                    # Add manual fields (CRITICAL: Frontend expects these after page refresh)
                    # These fields are used to populate hidden inputs and validate submission
                    if doc_type == 'pan':
                        doc_data['pan_number'] = doc_row.pan_number
                    if doc_type == 'aadhar':
                        doc_data['aadhar_number'] = doc_row.aadhar_number
                    if doc_type == 'gst':
                        doc_data['gst_number'] = doc_row.gst_number
                    if doc_type == 'business':
                        doc_data['business_registration_number'] = doc_row.business_registration_number
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
@login_required
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
@login_required
@role_required(['vendor'])
def submit_quotation_file():
    """
    POST /api/vendor/quotation/submit
    Submit quotation file after approval
    """
    try:
        # Debug logging
        app_logger.info(f"Quotation submit request - vendor_id={request.user_id}, files={list(request.files.keys())}, form_keys={list(request.form.keys())}")
        
        if 'file' not in request.files:
            app_logger.warning(f"Quotation submit failed: No file part in request")
            return jsonify({"error": "No file part"}), 400
        
        file = request.files['file']
        # SECURITY: Always use vendor_id from JWT, never from request body
        vendor_id = request.user_id
        commission_rate = request.form.get('commission_rate')
        
        # Debug logging - read file to get actual size
        if file:
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)  # Reset for validation
        else:
            file_size = 0
        
        app_logger.info(f"Quotation submit - file={file.filename if file else None}, commission_rate={commission_rate}, file_size={file_size}")
        
        if not file or file.filename == '':
            app_logger.warning(f"Quotation submit failed: File is empty or missing")
            return jsonify({"error": "File is required"}), 400
        
        if not commission_rate:
            app_logger.warning(f"Quotation submit failed: Commission rate missing")
            return jsonify({"error": "Commission rate is required"}), 400
        
        try:
            commission_float = float(commission_rate)
        except (ValueError, TypeError):
            app_logger.warning(f"Quotation submit failed: Invalid commission rate format: {commission_rate}")
            return jsonify({"error": "Commission rate must be a valid number"}), 400
        
        if commission_float < 15:
            app_logger.warning(f"Quotation submit failed: Commission rate too low: {commission_float}")
            return jsonify({"error": "Commission rate must be at least 15%"}), 400
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            app_logger.warning(f"Quotation submit failed: Vendor not found: {vendor_id}")
            return jsonify({"error": "Vendor not found"}), 404
        
        if vendor.verification_status != 'approved':
            app_logger.warning(f"Quotation submit failed: Vendor not approved: status={vendor.verification_status}")
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
            app_logger.warning(f"Quotation submit failed: File validation error: {error}")
            return jsonify({"error": error}), 400
        
        # Check if submission already exists
        # Safety check: ensure file_info['path'] is a string, not bytes
        assert isinstance(file_info['path'], str), f"quotation_file must be a string path, got {type(file_info['path'])}"
        
        existing = VendorQuotationSubmission.query.filter_by(vendor_id=vendor_id).first()
        if existing:
            if existing.quotation_file:
                delete_file(existing.quotation_file)
            existing.quotation_file = file_info['path']
            existing.quotation_filename = file_info['filename']
            existing.quotation_mimetype = file_info['mimetype']
            existing.proposed_commission_rate = commission_float
            existing.status = 'pending'
            existing.submitted_at = datetime.utcnow()
        else:
            submission = VendorQuotationSubmission(
                vendor_id=vendor_id,
                quotation_file=file_info['path'],
                quotation_filename=file_info['filename'],
                quotation_mimetype=file_info['mimetype'],
                proposed_commission_rate=commission_float
            )
            db.session.add(submission)
        
        db.session.commit()
        return jsonify({"message": "Quotation submitted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Submit quotation error: {e}")
        return jsonify({"error": "Failed to submit quotation"}), 500


@bp.route('/quotation/status', methods=['GET'])
@login_required
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


# ============================================================================
# Production Capacity (Made-to-Order)
# Products auto-populated from APPROVED vendor_quotations.
# Vendor Price = READ-ONLY (from vendor_quotations). Vendor edits ONLY capacity.
# ============================================================================

@bp.route('/capacity', methods=['GET'])
@login_required
@role_required(['vendor'])
def get_vendor_capacity():
    """
    GET /api/vendor/capacity

    Capacity page SOURCE OF TRUTH = vendor_quotations (approved only).
    Query: FROM vendor_quotations → LEFT JOIN product_catalog → LEFT JOIN vendor_capacity.
    NEVER start from product_catalog or vendor_capacity.

    Vendor Price = read-only (from vendor_quotations.base_cost).
    Capacity fields = editable (from vendor_capacity).
    """
    try:
        vendor_id = request.user_id
        vendor_db = current_app.config.get('DB_NAME_VENDOR', 'impromptuindian_vendor')
        admin_db = current_app.config.get('DB_NAME_ADMIN', 'impromptuindian_admin')
        if not all(c.isalnum() or c == '_' for c in vendor_db):
            vendor_db = 'impromptuindian_vendor'
        if not all(c.isalnum() or c == '_' for c in admin_db):
            admin_db = 'impromptuindian_admin'

        product_type_filter = request.args.get('product_type', '').strip().lower()
        category_filter = request.args.get('category', '').strip().lower()
        size_filter = request.args.get('size', '').strip().upper()

        sql = text(f"""
            SELECT
                vq.product_id AS product_catalog_id,
                COALESCE(pc.product_type, CONCAT('Product #', vq.product_id)) AS product_type,
                COALESCE(pc.category, '-') AS category,
                COALESCE(pc.neck_type, '-') AS neck_type,
                COALESCE(pc.fabric, '-') AS fabric,
                COALESCE(pc.size, '-') AS size,
                vq.base_cost AS quoted_price,
                COALESCE(vc.daily_capacity, 0) AS daily_capacity,
                COALESCE(vc.max_bulk_capacity, 0) AS max_bulk_capacity,
                COALESCE(vc.lead_time_days, 3) AS lead_time_days
            FROM {vendor_db}.vendor_quotations vq
            LEFT JOIN {admin_db}.product_catalog pc ON pc.id = vq.product_id
            LEFT JOIN {vendor_db}.vendor_capacity vc
                ON vc.product_catalog_id = vq.product_id
                AND vc.vendor_id = vq.vendor_id
                AND vc.is_active = 1
            WHERE vq.vendor_id = :vendor_id
            AND LOWER(TRIM(COALESCE(vq.status, ''))) = 'approved'
            ORDER BY vq.product_id
        """)

        rows = db.session.execute(sql, {"vendor_id": vendor_id}).fetchall()

        result = []
        for row in rows:
            pt = (row.product_type or '').strip().lower()
            cat = (row.category or '').strip().lower()
            sz = (row.size or '-').strip().upper()
            if product_type_filter and pt != product_type_filter:
                continue
            if category_filter and cat != category_filter:
                continue
            if size_filter and sz != size_filter:
                continue

            result.append({
                "product_catalog_id": row.product_catalog_id,
                "product_type": row.product_type or f"Product #{row.product_catalog_id}",
                "category": row.category or "-",
                "neck_type": row.neck_type or "-",
                "fabric": row.fabric or "-",
                "size": row.size or "-",
                "quoted_price": float(row.quoted_price) if row.quoted_price is not None else 0,
                "daily_capacity": int(row.daily_capacity or 0),
                "max_bulk_capacity": int(row.max_bulk_capacity or 0),
                "lead_time_days": int(row.lead_time_days or 3),
            })

        product_types = sorted(set(r["product_type"] for r in result if r["product_type"] and not r["product_type"].startswith("Product #")))
        categories = sorted(set(r["category"] for r in result if r["category"] and r["category"] != "-"))
        sizes = sorted(set(r["size"] for r in result if r["size"] and r["size"] != "-"))

        return jsonify({
            "rows": result,
            "count": len(result),
            "filters": {
                "product_types": product_types,
                "categories": categories,
                "sizes": sizes
            },
            "message": "No approved quotations. Submit quotation and wait for admin approval." if not result else None
        }), 200

    except Exception as e:
        app_logger.exception(f"Get vendor capacity error: {e}")
        return jsonify({"error": "Failed to retrieve capacity"}), 500


@bp.route('/capacity', methods=['POST', 'PUT'])
@login_required
@role_required(['vendor'])
def upsert_vendor_capacity():
    """
    POST/PUT /api/vendor/capacity
    Create or update production capacity ONLY.
    Body: { product_catalog_id, daily_capacity, max_bulk_capacity?, lead_time_days? }
    Price is NEVER accepted - vendor can only edit capacity. Price comes from vendor_quotations (admin-controlled).
    """
    try:
        vendor_id = request.user_id
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404

        if vendor.verification_status not in ['approved', 'active']:
            return jsonify({
                "error": "Capacity can be submitted only after verification approval",
                "verification_status": vendor.verification_status
            }), 403

        data = request.get_json()
        items = data if isinstance(data, list) else [data]

        updated = []
        for item in items:
            product_catalog_id = item.get('product_catalog_id')
            daily_capacity = item.get('daily_capacity', 0)
            max_bulk_capacity = item.get('max_bulk_capacity', 0)
            lead_time_days = item.get('lead_time_days', 3)

            if not product_catalog_id:
                continue

            pcid = int(product_catalog_id)

            # SECURITY: Vendor can only set capacity for products they have APPROVED quotation for
            vq = VendorQuotation.query.filter_by(
                vendor_id=vendor_id,
                product_id=pcid,
                status='approved'
            ).first()
            if not vq:
                app_logger.warning(f"Vendor {vendor_id} attempted capacity for product {pcid} without approved quotation")
                continue  # Silently skip - no approved quote for this product

            existing = VendorCapacity.query.filter_by(
                vendor_id=vendor_id,
                product_catalog_id=pcid
            ).first()

            if existing:
                existing.daily_capacity = int(daily_capacity)
                existing.max_bulk_capacity = int(max_bulk_capacity)
                existing.lead_time_days = int(lead_time_days)
                existing.is_active = True
                existing.updated_at = datetime.utcnow()
                updated.append(existing)
            else:
                new_cap = VendorCapacity(
                    vendor_id=vendor_id,
                    product_catalog_id=pcid,
                    daily_capacity=int(daily_capacity),
                    max_bulk_capacity=int(max_bulk_capacity),
                    lead_time_days=int(lead_time_days)
                )
                db.session.add(new_cap)
                updated.append(new_cap)

        db.session.commit()
        return jsonify({
            "message": "Capacity updated successfully",
            "count": len(updated)
        }), 200

    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Upsert vendor capacity error: {e}")
        return jsonify({"error": "Failed to update capacity"}), 500


@bp.route('/capacity/<int:product_catalog_id>', methods=['DELETE'])
@login_required
@role_required(['vendor'])
def delete_vendor_capacity(product_catalog_id):
    """
    DELETE /api/vendor/capacity/<product_catalog_id>
    Soft-deactivate (set capacity to 0) - vendor keeps quotation, just clears capacity.
    """
    try:
        cap = VendorCapacity.query.filter_by(
            vendor_id=request.user_id,
            product_catalog_id=product_catalog_id
        ).first()

        if not cap:
            return jsonify({"error": "Capacity entry not found"}), 404

        cap.daily_capacity = 0
        cap.max_bulk_capacity = 0
        cap.is_active = False
        cap.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"message": "Capacity cleared"}), 200

    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Delete vendor capacity error: {e}")
        return jsonify({"error": "Failed to clear capacity"}), 500


@bp.route('/cart-products', methods=['GET'])
@login_required
@role_required(['vendor'])
def get_cart_products():
    """
    GET /api/vendor/cart-products
    Get all cart products for the logged-in vendor
    """
    try:
        vendor_id = request.user_id
        
        products = CartProduct.query.filter_by(vendor_id=vendor_id).order_by(
            CartProduct.created_at.desc()
        ).all()
        
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
            
            products_list.append({
                "id": p.id,
                "product_type": p.product_type,
                "product_name": p.product_name,
                "description": p.description,
                "cost_price": float(p.cost_price) if p.cost_price else 0,
                "sizes": sizes,
                "images": images,
                "status": p.status,
                "admin_remarks": p.admin_remarks,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "updated_at": p.updated_at.isoformat() if p.updated_at else None
            })
        
        return jsonify({
            "products": products_list,
            "count": len(products_list)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get cart products error: {e}")
        return jsonify({"error": "Failed to retrieve products"}), 500


@bp.route('/cart-products', methods=['POST'])
@login_required
@role_required(['vendor'])
def create_cart_product():
    """
    POST /api/vendor/cart-products
    Create a new cart product with image uploads
    """
    try:
        vendor_id = request.user_id
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404

        # Validate required form fields
        product_type = request.form.get('product_type', '').strip()
        product_name = request.form.get('product_name', '').strip()
        description = request.form.get('description', '').strip()
        cost_price = request.form.get('cost_price', '').strip()
        sizes_json = request.form.get('sizes', '[]')

        if not product_type or not product_name or not cost_price:
            return jsonify({"error": "product_type, product_name, and cost_price are required"}), 400

        # Validate cost price
        try:
            cost = float(cost_price)
            if cost <= 0:
                return jsonify({"error": "cost_price must be greater than 0"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "invalid cost_price format"}), 400

        # Parse sizes
        try:
            sizes = json.loads(sizes_json) if sizes_json else []
            if not isinstance(sizes, list) or len(sizes) == 0:
                return jsonify({"error": "At least one size is required"}), 400
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid sizes format"}), 400

        # Handle image uploads
        image_files = request.files.getlist('images')
        if not image_files or len(image_files) == 0:
            return jsonify({"error": "At least one image is required"}), 400

        image_paths = []
        for img_file in image_files:
            if img_file and img_file.filename:
                # Validate and save image
                file_info, error = validate_and_save_file(
                    img_file,
                    '/api/vendor/cart-products',
                    'vendor_products',
                    vendor_id,
                    'product_image',
                    scan_virus=False
                )
                if error:
                    return jsonify({"error": f"Image upload failed: {error}"}), 400
                if file_info and file_info.get('path'):
                    image_paths.append(file_info['path'])

        if len(image_paths) == 0:
            return jsonify({"error": "Failed to upload images"}), 400

        # Create cart product
        product = CartProduct(
            vendor_id=vendor_id,
            product_type=product_type,
            product_name=product_name,
            description=description,
            cost_price=cost,
            sizes=sizes,
            images=image_paths,
            status='pending'
        )
        
        db.session.add(product)
        db.session.commit()
        
        app_logger.info(f"Vendor #{vendor_id} created cart product #{product.id}: {product.product_name}")
        
        return jsonify({
            "message": "Product submitted for admin approval",
            "product": {
                "id": product.id,
                "product_name": product.product_name,
                "status": product.status,
                "created_at": product.created_at.isoformat() if product.created_at else None
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Create cart product error: {e}")
        return jsonify({"error": "Failed to create product"}), 500


@bp.route('/orders', methods=['GET'])
@login_required
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
            # 🔥 FIX: 'new' orders are those assigned to vendor but not yet in production
            # Only include pre-production statuses - once order moves to production, it should appear in "In Production" page
            query = query.filter(
                Order.status.in_([
                    'quotation_sent_to_customer',
                    'sample_requested',
                    'awaiting_advance_payment'
                ])
            )
        elif status == 'in_production':
            production_statuses = [
                'in_production', 'material_prep',
                'printing', 'printing_completed', 'quality_check'
            ]
            query = query.filter(Order.status.in_(production_statuses))
        elif status == 'completed':
            # 🔥 FIX: Return both dispatched and delivered orders for completed page
            query = query.filter(Order.status.in_(['dispatched', 'delivered', 'completed', 'completed_with_penalty']))
        elif status:
            query = query.filter_by(status=status)
        
        orders = query.order_by(Order.created_at.desc()).all()
        
        # 🔥 SECURITY: Use filtered schema - vendors should NOT see quantity or bulk details
        # Get base filtered data (sample fields only)
        filtered_orders = vendor_orders_schema.dump(orders)
        
        # Map to frontend format while maintaining security (no quantity field)
        result = []
        for idx, o in enumerate(orders):
            customer = Customer.query.get(o.customer_id)
            filtered_data = filtered_orders[idx]
            
            # Map status to stage for in_production
            current_stage = None
            if o.status == 'in_production':
                current_stage = 'in_production'  # 🔥 FIX: Match frontend stage ID
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
            
            # Determine order type: "sample" or "bulk"
            is_bulk = filtered_data.get("is_bulk_order", False)
            order_type = "bulk" if is_bulk else "sample"
            
            # For sample orders, quantity is always 1. For bulk orders, use the quantity from DB
            order_quantity = filtered_data.get("quantity", 1) if is_bulk else 1
            
            # 🔥 SECURITY: Build response with orderType and quantity
            order_data = {
                "id": f"ORD-{o.id:03d}" if isinstance(o.id, int) else o.id,
                "db_id": filtered_data.get("id"),
                "orderType": order_type,  # "sample" or "bulk"
                "quantity": order_quantity,  # 1 for sample, actual quantity for bulk
                "customerName": customer.username if customer else "Unknown",
                "productType": filtered_data.get("product_type"),  # From filtered schema
                "color": filtered_data.get("color"),
                "size": filtered_data.get("sample_size"),  # Only sample size, not bulk sizes
                "deadline": filtered_data.get("delivery_date"),  # ISO format from schema
                "assignedDate": filtered_data.get("created_at"),  # ISO format from schema
                "status": filtered_data.get("status"),
                "customization": {  # Frontend expects customization object
                    "fabric": filtered_data.get("fabric"),
                    "printType": filtered_data.get("print_type"),
                    "neckType": filtered_data.get("neck_type")
                },
                "specialInstructions": filtered_data.get("feedback_comment"),
                "address": f"{filtered_data.get('address_line1') or ''}, {filtered_data.get('city') or ''}, {filtered_data.get('pincode') or ''}".strip(', ') if filtered_data.get('address_line1') else None
            }
            
            if current_stage:
                order_data["currentStage"] = current_stage
                order_data["notes"] = filtered_data.get("feedback_comment") or ""
            
            result.append(order_data)
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/dashboard/stats', methods=['GET'])
@login_required
@role_required(['vendor'])
def get_dashboard_stats():
    """
    GET /api/vendor/dashboard/stats
    Get vendor dashboard statistics
    """
    try:
        vendor_id = request.user_id
        
        # 🔥 FIX: New orders are pre-production only - once order moves to production, it should appear in "In Production"
        new_orders = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_([
                'quotation_sent_to_customer',
                'sample_requested',
                'awaiting_advance_payment'
            ])
        ).count()
        
        # 🔥 FIX: In-production orders include in_production stage and all active production stages
        production_statuses = [
            'in_production',
            'material_prep',
            'printing',
            'printing_completed',
            'quality_check'
        ]
        in_production = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(production_statuses)
        ).count()
        
        # 🔥 FIX: Standardize to only packed_ready
        ready_dispatch = Order.query.filter_by(selected_vendor_id=vendor_id, status='packed_ready').count()
        
        # 🔥 FIX: Include dispatched orders in completed count (treat dispatched as completed)
        completed = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['completed', 'completed_with_penalty', 'delivered', 'dispatched'])
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
@login_required
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
@login_required
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
@login_required
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
@login_required
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
        # 🔥 REMOVED: 'accepted' stage - vendors must compulsorily produce, no acceptance stage
        status_map = {
            'in_production': 'in_production',  # 🔥 FIX: Explicitly map first stage
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
            'in_production': 'In Production',  # 🔥 FIX: Explicitly map first stage label
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
        # 🔥 FIX: Use dynamic admin ID instead of hardcoded 1 (prevents money misrouting)
        from app_pkg.routes.orders_routes import get_admin_id
        admin_id = get_admin_id()
        admin_notif = Notification(
            user_id=admin_id,
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
        
        # Log activity
        log_activity_from_request(
            action=f"Updated production stage for Order #{order.id} to {stage_label}",
            action_type="order_status_change",
            entity_type="order",
            entity_id=order.id,
            details=notes if notes else None
        )
        
        return jsonify({
            "message": "Production stage updated successfully",
            "new_status": new_status
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update production stage error: {e}")
        return jsonify({"error": "Failed to update production stage"}), 500


@bp.route('/orders/<int:order_id>/move-to-production', methods=['POST'])
@login_required
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
            assignment.status = 'started'  # Changed from 'accepted' - vendor must compulsorily produce
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


# 🔥 REMOVED: Reject endpoint - vendors must compulsorily produce, no rejection allowed


@bp.route('/update-location', methods=['POST'])
@login_required
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
@login_required
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
@login_required
@role_required(['vendor'])
def get_order_stats():
    """
    GET /api/vendor/order-stats
    Get order statistics for vendor dashboard
    """
    try:
        vendor_id = request.user_id
        
        # 🔥 FIX: New orders are pre-production only - once order moves to production, it should appear in "In Production"
        new_orders_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_([
                'quotation_sent_to_customer',
                'sample_requested',
                'awaiting_advance_payment'
            ])
        ).count()
        
        # 🔥 FIX: In-production orders include in_production stage and all active production stages
        in_production_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_([
                'in_production',
                'material_prep',
                'printing',
                'printing_completed',
                'quality_check'
            ])
        ).count()
        
        # 🔥 FIX: Standardize to only packed_ready (remove unused statuses)
        ready_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status == 'packed_ready'
        ).count()
        
        # 🔥 FIX: Include dispatched orders in completed count (treat dispatched as completed)
        completed_count = Order.query.filter(
            Order.selected_vendor_id == vendor_id,
            Order.status.in_(['completed', 'completed_with_penalty', 'delivered', 'dispatched'])
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
@login_required
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
        
        # 🔥 SECURITY: Check user role - vendors should NOT see quantity
        user_role = getattr(request, 'role', None)
        show_quantity = user_role != 'vendor'  # Only admin and customer see quantity
        
        response_data = {
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
                "type": order.category if order else None
            },
            "assigned_at": delivery.assigned_at.isoformat() if delivery.assigned_at else None,
            "reached_vendor_at": delivery.reached_vendor_at.isoformat() if delivery.reached_vendor_at else None
        }
        
        # Only include quantity for admin and customer, not vendor
        if show_quantity and order:
            response_data["product"]["quantity"] = order.quantity
        
        return jsonify(response_data), 200
        
    except Exception as e:
        app_logger.exception(f"Track delivery error: {e}")
        return jsonify({"error": "Failed to track delivery"}), 500


@bp.route('/new-orders', methods=['GET'])
@login_required
@role_required(['vendor'])
def get_new_orders():
    """
    GET /api/vendor/new-orders
    Get new orders assigned to vendor
    🔥 Vendor should see orders after admin assignment, including before advance payment
    """
    try:
        # 🔥 FIX: Vendor should see orders after admin assignment, but not yet in production
        # Only include pre-production statuses - once order moves to production, it should appear in "In Production" page
        orders = Order.query.filter(
            Order.selected_vendor_id == request.user_id,
            Order.status.in_([
                'quotation_sent_to_customer',
                'sample_requested',
                'awaiting_advance_payment'
            ])
        ).order_by(Order.created_at.desc()).all()
        
        # 🔥 SECURITY: Use filtered schema - vendors should NOT see quantity or bulk details
        filtered_orders = vendor_orders_schema.dump(orders)
        
        result = []
        for idx, o in enumerate(orders):
            customer = Customer.query.get(o.customer_id)
            filtered_data = filtered_orders[idx]
            
            result.append({
                "id": f"ORD-{o.id:03d}" if isinstance(o.id, int) else o.id,
                "db_id": filtered_data.get("id"),
                "customerName": customer.username if customer else "Unknown",
                "productType": filtered_data.get("product_type"),  # From filtered schema
                "color": filtered_data.get("color"),
                "size": filtered_data.get("sample_size"),  # Only sample size, not bulk
                # 🔥 REMOVED: "quantity": o.quantity,  # Vendors should NOT see bulk quantity
                "customization": {  # Frontend expects customization object
                    "printType": filtered_data.get("print_type"),
                    "neckType": filtered_data.get("neck_type"),
                    "fabric": filtered_data.get("fabric")
                },
                "deadline": filtered_data.get("delivery_date"),  # ISO format from schema
                "assignedDate": filtered_data.get("created_at"),  # ISO format from schema
                "specialInstructions": filtered_data.get("feedback_comment"),
                "address": f"{filtered_data.get('address_line1') or ''}, {filtered_data.get('city') or ''}, {filtered_data.get('pincode') or ''}".strip(', ') if filtered_data.get('address_line1') else None
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get new orders error: {e}")
        return jsonify({"error": "Failed to retrieve new orders"}), 500


# ============================================================================
# Marketplace Products (Vendor → Admin Approval → Customer Display)
# ============================================================================

@bp.route('/products', methods=['POST'])
@login_required
@role_required(['vendor'])
def add_marketplace_product():
    """
    POST /api/vendor/products
    Vendor adds a new product (status = PENDING)
    """
    try:
        vendor_id = request.user_id
        data = request.get_json()
        
        # Validate required fields
        if not data.get('product_name') or not data.get('price'):
            return jsonify({"error": "product_name and price are required"}), 400
        
        # Validate price is positive
        try:
            price = float(data['price'])
            if price <= 0:
                return jsonify({"error": "price must be greater than 0"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "invalid price format"}), 400
        
        # Create new product
        product = MarketplaceProduct(
            vendor_id=vendor_id,
            product_name=data['product_name'],
            description=data.get('description', ''),
            price=price,
            sizes=data.get('sizes', []),  # JSON array
            colors=data.get('colors', []),  # JSON array
            image_url=data.get('image_url', ''),
            status='PENDING'
        )
        
        db.session.add(product)
        db.session.commit()
        
        app_logger.info(f"Vendor #{vendor_id} added product #{product.id}: {product.product_name}")
        
        return jsonify({
            "message": "Product added successfully",
            "product": {
                "id": product.id,
                "product_name": product.product_name,
                "status": product.status,
                "created_at": product.created_at.isoformat() if product.created_at else None
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Add marketplace product error: {e}")
        return jsonify({"error": "Failed to add product"}), 500


@bp.route('/products', methods=['GET'])
@login_required
@role_required(['vendor'])
def get_vendor_products():
    """
    GET /api/vendor/products
    Get all products for the logged-in vendor (with status)
    """
    try:
        vendor_id = request.user_id
        
        products = MarketplaceProduct.query.filter_by(vendor_id=vendor_id).order_by(
            MarketplaceProduct.created_at.desc()
        ).all()
        
        products_list = []
        for p in products:
            # Status badge mapping
            status_badge = {
                'PENDING': '🟡 Pending',
                'APPROVED': '🟢 Approved',
                'REJECTED': '🔴 Rejected'
            }.get(p.status, p.status)
            
            products_list.append({
                "id": p.id,
                "product_name": p.product_name,
                "description": p.description,
                "price": float(p.price) if p.price else 0,
                "sizes": p.sizes if p.sizes else [],
                "colors": p.colors if p.colors else [],
                "image_url": p.image_url,
                "status": p.status,
                "status_badge": status_badge,
                "admin_comment": p.admin_comment,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "updated_at": p.updated_at.isoformat() if p.updated_at else None
            })
        
        return jsonify({
            "products": products_list,
            "count": len(products_list)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get vendor products error: {e}")
        return jsonify({"error": "Failed to retrieve products"}), 500


@bp.route('/products/<int:product_id>', methods=['PUT'])
@login_required
@role_required(['vendor'])
def update_vendor_product(product_id):
    """
    PUT /api/vendor/products/<product_id>
    Vendor updates a product.
    If product is APPROVED, status resets to PENDING (requires re-approval).
    """
    try:
        vendor_id = request.user_id
        data = request.get_json()
        
        product = MarketplaceProduct.query.filter_by(id=product_id, vendor_id=vendor_id).first()
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        # 🔥 PRODUCTION RULE: If product is APPROVED, reset to PENDING on edit
        was_approved = product.status == 'APPROVED'
        
        # Update fields
        if 'product_name' in data:
            product.product_name = data['product_name']
        if 'description' in data:
            product.description = data['description']
        if 'price' in data:
            try:
                price = float(data['price'])
                if price <= 0:
                    return jsonify({"error": "price must be greater than 0"}), 400
                product.price = price
            except (ValueError, TypeError):
                return jsonify({"error": "invalid price format"}), 400
        if 'sizes' in data:
            product.sizes = data['sizes']
        if 'colors' in data:
            product.colors = data['colors']
        if 'image_url' in data:
            product.image_url = data['image_url']
        
        # Reset status to PENDING if it was APPROVED
        if was_approved:
            product.status = 'PENDING'
            product.admin_comment = None  # Clear previous admin comment
        
        db.session.commit()
        
        app_logger.info(f"Vendor #{vendor_id} updated product #{product_id}. Status reset to PENDING: {was_approved}")
        
        return jsonify({
            "message": "Product updated successfully",
            "product": {
                "id": product.id,
                "product_name": product.product_name,
                "status": product.status,
                "requires_reapproval": was_approved
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update vendor product error: {e}")
        return jsonify({"error": "Failed to update product"}), 500
