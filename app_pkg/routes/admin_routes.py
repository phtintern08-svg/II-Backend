"""
Admin Routes Blueprint
Handles admin-specific endpoints for managing users, orders, and system settings
"""
from flask import Blueprint, request, jsonify, send_file, current_app
from datetime import datetime, timedelta
import os
import math
import csv
import time
import re
from sqlalchemy import text, func

from app_pkg.models import (
    db, Admin, Customer, Vendor, Rider, Order, OTPLog, Payment, 
    VendorDocument, VendorQuotationSubmission, RiderDocument, Notification,
    VendorOrderAssignment, OrderStatusHistory, DeliveryLog, ProductCatalog,
    DeliveryPartner, SupportUser, SupportTicket, SupportTicketCategory,
    SupportPriorityRule, SupportEscalationRule, SupportAutoAssignment, ActivityLog, 
    VendorQuotation, VendorCapacity, VendorStock, MarketplaceProduct, CartProduct
)
from app_pkg.auth import login_required, admin_required
from app_pkg.file_upload import get_file_path_from_db
from app_pkg.logger_config import app_logger
from app_pkg.error_handler import get_error_message
from app_pkg.activity_logger import log_activity_from_request

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
    # Get all online, verified, and ACTIVE riders (location updated in last 15 sec)
    active_threshold = datetime.utcnow() - timedelta(seconds=15)
    riders = Rider.query.filter(
        Rider.is_online == True,
        Rider.verification_status == 'approved',
        Rider.latitude.isnot(None),
        Rider.longitude.isnot(None),
        (Rider.last_location_update.is_(None)) | (Rider.last_location_update >= active_threshold)
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
    
ub    # Sort by distance (nearest first), then by accuracy (more accurate preferred)
    def sort_key(item):
        rider, dist = item
        acc = rider.location_accuracy if rider.location_accuracy is not None else 9999
        return (dist, acc)
    rider_distances.sort(key=sort_key)
    
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
            
            # 🔥 FIX: Auto-carry delivery deadline from order.delivery_date
            if order.delivery_date:
                from datetime import time
                delivery_deadline = datetime.combine(order.delivery_date, time(23, 59, 59))
                existing_log.delivery_deadline = delivery_deadline
            
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
            # 🔥 FIX: Auto-carry delivery deadline from order.delivery_date
            delivery_deadline = None
            if order.delivery_date:
                from datetime import time
                delivery_deadline = datetime.combine(order.delivery_date, time(23, 59, 59))
            
            # Create new delivery log
            delivery_log = DeliveryLog(
                order_id=order_id,
                assigned_rider_id=rider.id,
                vendor_address=f"{vendor.address}, {vendor.city}, {vendor.state} - {vendor.pincode}",
                vendor_contact=vendor.phone,
                customer_address=f"{order.address_line1}, {order.city}, {order.state} - {order.pincode}",
                status='assigned',
                assigned_at=datetime.utcnow(),
                delivery_deadline=delivery_deadline
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
    # 🔥 DIAGNOSTIC: Log BEFORE any processing to verify decorator executed
    import os
    process_id = os.getpid()
    app_logger.info(
        f"🔵 Dashboard stats route EXECUTED - Process: {process_id}, "
        f"user_id: {getattr(request, 'user_id', 'NOT SET')}, "
        f"role: {getattr(request, 'role', 'NOT SET')}, "
        f"current_user exists: {hasattr(request, 'current_user')}"
    )
    
    # 🔥 DEFENSIVE: Verify authentication attributes are set (should never fail if decorator worked)
    if not hasattr(request, 'user_id') or not request.user_id:
        app_logger.error(
            f"❌ CRITICAL: Dashboard stats route reached but user_id not set! "
            f"Process: {process_id}, "
            f"Has current_user: {hasattr(request, 'current_user')}, "
            f"Has role: {hasattr(request, 'role')}"
        )
        return jsonify({
            "error": "Authentication error - user context missing",
            "code": "AUTH_CONTEXT_MISSING"
        }), 401
    
    if not hasattr(request, 'role') or request.role != 'admin':
        app_logger.error(
            f"❌ CRITICAL: Dashboard stats route reached but role invalid! "
            f"Process: {process_id}, "
            f"Role: {getattr(request, 'role', 'NOT SET')}"
        )
        return jsonify({
            "error": "Insufficient permissions",
            "code": "INSUFFICIENT_PERMISSIONS"
        }), 403
    
    try:
        # Time-based calculations
        today = datetime.utcnow().date()
        week_start = today - timedelta(days=today.weekday())  # Start of current week (Monday)
        month_start = today.replace(day=1)  # Start of current month
        
        # Orders created today
        today_orders = db.session.query(func.count(Order.id)).filter(
            func.date(Order.created_at) == today
        ).scalar() or 0
        
        # Orders created this week
        week_orders = db.session.query(func.count(Order.id)).filter(
            Order.created_at >= datetime.combine(week_start, datetime.min.time())
        ).scalar() or 0
        
        # Orders created this month
        month_orders = db.session.query(func.count(Order.id)).filter(
            Order.created_at >= datetime.combine(month_start, datetime.min.time())
        ).scalar() or 0
        
        # Status-based counts (using same categorization as order-stats endpoint)
        # Pending orders (new orders awaiting assignment)
        pending_orders = Order.query.filter(
            Order.status.in_([
                'pending_admin_review',
                'quotation_sent_to_customer',
                'sample_payment_received'
            ])
        ).count()
        
        # In production orders
        in_production = Order.query.filter(
            Order.status.in_([
                'sample_requested',
                'awaiting_advance_payment',
                'in_production',
                'assigned',
                'vendor_assigned'
            ])
        ).count()
        
        # Ready for dispatch orders
        ready_dispatch = Order.query.filter(
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
        
        # Completed orders
        completed_orders = Order.query.filter(
            Order.status.in_([
                'completed',
                'completed_with_penalty',
                'delivered'
            ])
        ).count()
        
        # Cancelled/rejected orders
        cancelled_orders = Order.query.filter(
            Order.status.in_([
                'quotation_rejected_by_customer',
                'sample_rejected'
            ])
        ).count()
        
        # Additional stats for vendors and riders
        total_customers = Customer.query.count()
        total_vendors = Vendor.query.count()
        total_riders = Rider.query.count()
        total_orders = Order.query.count()
        
        stats = {
            # Time-based order counts
            "today_orders": today_orders,
            "week_orders": week_orders,
            "month_orders": month_orders,
            
            # Status-based order counts
            "pending_orders": pending_orders,
            "in_production": in_production,
            "ready_dispatch": ready_dispatch,
            "completed_orders": completed_orders,
            "cancelled_orders": cancelled_orders,
            
            # Additional stats
            "total_customers": total_customers,
            "total_vendors": total_vendors,
            "total_riders": total_riders,
            "total_orders": total_orders
        }
        
        app_logger.debug(f"✅ Dashboard stats computed successfully - Process: {process_id}")
        return jsonify(stats), 200
        
    except Exception as e:
        app_logger.exception(
            f"❌ Dashboard stats error - Process: {process_id}, Error: {e}"
        )
        return jsonify({"error": "Failed to retrieve statistics"}), 500


@bp.route('/system-stats', methods=['GET'])
@admin_required
def get_system_stats():
    """
    GET /api/admin/system-stats
    Get process-level system statistics (CPU, RAM, Disk I/O) for the backend application
    """
    try:
        # Try to import psutil, fallback gracefully if not installed
        try:
            import psutil
        except ImportError:
            app_logger.warning("psutil not installed - system stats unavailable")
            return jsonify({
                "error": "System monitoring not available - psutil package required",
                "code": "PSUTIL_NOT_INSTALLED"
            }), 503
        
        # Get current process
        current_process = psutil.Process(os.getpid())
        
        # Check if we're running under Passenger/Gunicorn (multiple workers)
        # Passenger typically has a parent process with children
        parent = current_process.parent()
        processes = []
        
        # Try to detect if we're in a multi-worker setup
        try:
            # Check if parent is a worker manager (gunicorn, passenger, etc.)
            parent_name = parent.name().lower() if parent else ''
            is_multi_worker = any(name in parent_name for name in ['gunicorn', 'passenger', 'uwsgi', 'supervisord'])
            
            if is_multi_worker:
                # Get all child processes (workers)
                try:
                    children = parent.children(recursive=True)
                    processes = children + [parent]
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Fallback to current process only
                    processes = [current_process]
            else:
                # Single process setup
                processes = [current_process]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Fallback to current process only
            processes = [current_process]
        
        # Aggregate metrics across all processes
        total_cpu = 0.0
        total_ram_mb = 0.0
        total_ram_percent = 0.0
        total_read_bytes = 0
        total_write_bytes = 0
        total_threads = 0
        oldest_create_time = time.time()
        
        for proc in processes:
            try:
                # CPU (non-blocking)
                total_cpu += proc.cpu_percent(interval=0.0)
                
                # RAM
                mem_info = proc.memory_info()
                total_ram_mb += mem_info.rss / 1024 / 1024
                total_ram_percent += proc.memory_percent()
                
                # Disk I/O
                try:
                    io = proc.io_counters()
                    total_read_bytes += io.read_bytes
                    total_write_bytes += io.write_bytes
                except (psutil.AccessDenied, AttributeError):
                    # Some systems don't allow I/O stats
                    pass
                
                # Threads
                total_threads += proc.num_threads()
                
                # Track oldest process (for uptime)
                try:
                    create_time = proc.create_time()
                    if create_time < oldest_create_time:
                        oldest_create_time = create_time
                except (psutil.AccessDenied, AttributeError):
                    pass
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                app_logger.warning(f"Could not access process {proc.pid}: {e}")
                continue
        
        # Calculate uptime
        uptime_seconds = time.time() - oldest_create_time
        uptime_hours = uptime_seconds / 3600
        
        # Get system CPU count
        cpu_cores = psutil.cpu_count()
        
        # Build response
        stats = {
            "cpu": {
                "percent": round(total_cpu, 2),
                "cores": cpu_cores
            },
            "ram": {
                "percent": round(total_ram_percent, 2),
                "used_mb": round(total_ram_mb, 2)
            },
            "io": {
                "read_mb": round(total_read_bytes / 1024 / 1024, 2),
                "written_mb": round(total_write_bytes / 1024 / 1024, 2),
                "total_mb": round((total_read_bytes + total_write_bytes) / 1024 / 1024, 2)
            },
            "process": {
                "threads": total_threads,
                "uptime_hours": round(uptime_hours, 2),
                "pid": current_process.pid,
                "worker_count": len(processes)
            }
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        app_logger.exception(f"Get system stats error: {e}")
        return jsonify({"error": "Failed to retrieve system statistics"}), 500


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
    
    Query Parameters:
    - status (optional): Filter by verification status
      Frontend values: 'verified', 'rejected', 'pending'
      Maps to DB values: 'approved', 'rejected', 'pending' (or other pending statuses)
    """
    try:
        # Optional status filter
        status = request.args.get('status')
        
        query = Vendor.query
        if status:
            # 🔥 FIX: Map frontend status terminology to database values
            # Frontend uses "verified" but database stores "approved"
            status_mapping = {
                'verified': 'approved',  # Frontend "verified" → DB "approved"
                'rejected': 'rejected',  # Direct mapping
                'pending': 'pending',   # Direct mapping (or could be 'not-submitted')
            }
            
            # Map frontend status to database status
            db_status = status_mapping.get(status.lower(), status)
            
            # If status is 'pending', also check for other pending-related statuses
            if status.lower() == 'pending':
                query = query.filter(
                    Vendor.verification_status.in_(['pending', 'not-submitted', 'under-review'])
                )
            else:
                query = query.filter_by(verification_status=db_status)
        
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
    Verify or reject a vendor.
    🔥 DB uses 'approved', not 'verified'. Accept both from frontend, store 'approved'.
    """
    try:
        data = request.get_json()
        status = (data.get('status') or '').strip().lower()
        remarks = data.get('remarks')

        if status not in ['verified', 'approved', 'rejected']:
            return jsonify({"error": "Invalid status. Use 'approved' or 'rejected'"}), 400

        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404

        # 🔥 ALWAYS store 'approved' - never 'verified'. System expects 'approved'.
        db_status = 'approved' if status in ('verified', 'approved') else 'rejected'
        vendor.verification_status = db_status
        vendor.admin_remarks = remarks
        vendor.updated_at = datetime.utcnow()

        db.session.commit()

        return jsonify({
            "message": f"Vendor {db_status} successfully",
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
    Verify or reject a rider.
    🔥 DB uses 'approved', not 'verified'. Accept both from frontend, store 'approved'.
    """
    try:
        data = request.get_json()
        status = (data.get('status') or '').strip().lower()
        remarks = data.get('remarks')

        if status not in ['verified', 'approved', 'rejected']:
            return jsonify({"error": "Invalid status. Use 'approved' or 'rejected'"}), 400

        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404

        # 🔥 ALWAYS store 'approved' - never 'verified'. System expects 'approved'.
        db_status = 'approved' if status in ('verified', 'approved') else 'rejected'
        rider.verification_status = db_status
        rider.admin_remarks = remarks
        rider.updated_at = datetime.utcnow()

        db.session.commit()

        return jsonify({
            "message": f"Rider {db_status} successfully",
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
        
        logs = OTPLog.query.order_by(OTPLog.created_at.desc()).limit(limit).all()
        
        logs_data = [{
            "id": log.id,
            "recipient": log.recipient,
            "otp_code": log.otp_code,
            "type": log.type,
            "status": log.status,
            "created_at": log.created_at.isoformat() if log.created_at else None
        } for log in logs]
        
        return jsonify({
            "logs": logs_data,
            "count": len(logs_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get OTP logs error: {e}")
        return jsonify({"error": "Failed to retrieve OTP logs"}), 500


@bp.route('/activity-logs', methods=['GET'])
@admin_required
def get_activity_logs():
    """
    GET /api/admin/activity-logs
    Get activity logs showing who did what across all user types
    Returns logs from ActivityLog table which stores all user actions
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        
        # Get activity logs from ActivityLog table
        activity_logs = ActivityLog.query.order_by(
            ActivityLog.timestamp.desc()
        ).limit(limit).all()
        
        activities = []
        for log in activity_logs:
            activities.append({
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "user_name": log.user_name,
                "user_type": log.user_type,
                "action": log.action,
                "action_type": log.action_type,
                "entity_type": log.entity_type,
                "entity_id": log.entity_id,
                "details": log.details
            })
        
        return jsonify({
            "activities": activities,
            "count": len(activities)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get activity logs error: {e}")
        return jsonify({"error": "Failed to retrieve activity logs"}), 500


@bp.route('/orders', methods=['GET'])
@admin_required
def get_all_orders():
    """
    GET /api/admin/orders
    Get all orders with optional filters
    🔥 ADMIN: Returns FULL order data including bulk details, quantities, and financials
    Includes marketplace product and vendor information for cart orders
    """
    try:
        from app_pkg.schemas import orders_schema
        
        status = request.args.get('status')
        query = Order.query
        
        if status:
            query = query.filter_by(status=status)
        
        orders = query.order_by(Order.created_at.desc()).all()
        
        # 🔥 ADMIN: Use full schema - admins see everything (sample + bulk)
        orders_data = orders_schema.dump(orders)
        
        # Enrich orders with marketplace product and vendor information
        for idx, order in enumerate(orders):
            if order.marketplace_product_id:
                try:
                    # Get marketplace product
                    product = MarketplaceProduct.query.get(order.marketplace_product_id)
                    if product:
                        orders_data[idx]['product_name'] = product.product_name
                        orders_data[idx]['product_image'] = product.image_url
                        orders_data[idx]['vendor_id'] = product.vendor_id
                        
                        # Get vendor information
                        vendor = Vendor.query.get(product.vendor_id)
                        if vendor:
                            orders_data[idx]['vendor_name'] = vendor.business_name
                        else:
                            orders_data[idx]['vendor_name'] = f"Vendor #{product.vendor_id}"
                    else:
                        orders_data[idx]['product_name'] = None
                        orders_data[idx]['product_image'] = None
                        orders_data[idx]['vendor_id'] = None
                        orders_data[idx]['vendor_name'] = None
                except Exception as e:
                    app_logger.warning(f"Failed to fetch product/vendor info for order {order.id}: {e}")
                    orders_data[idx]['product_name'] = None
                    orders_data[idx]['product_image'] = None
                    orders_data[idx]['vendor_id'] = None
                    orders_data[idx]['vendor_name'] = None
        
        return jsonify({
            "orders": orders_data,
            "count": len(orders_data)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get all orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/orders/<int:order_id>/eligible-vendors', methods=['GET'])
@admin_required
def get_eligible_vendors_for_order(order_id):
    """
    GET /api/admin/orders/<order_id>/eligible-vendors
    Returns eligible vendors for order assignment.
    
    Two order types:
    1. Marketplace Orders (marketplace_product_id exists):
       - Returns the vendor who posted the product
       - Bypasses recommendation engine
       - Auto-assigned vendor
    
    2. RFQ/Catalog Orders (no marketplace_product_id):
       - Uses recommendation engine
       - Hard Filters: approved quotation, capacity, stock, verification
       - Ranking: stock, distance, capacity, lead time
    """
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404

        # 🔥 DEBUG: Log order details to diagnose marketplace_product_id
        app_logger.info(f"Order {order_id} details: marketplace_product_id={order.marketplace_product_id}, selected_vendor_id={order.selected_vendor_id}, product_type={order.product_type}, status={order.status}")

        # 🔥 VENDOR PRODUCT ORDER: Check if vendor is already auto-assigned (CartProduct or MarketplaceProduct)
        # If vendor is auto-assigned, return that vendor as eligible
        if order.selected_vendor_id:
            try:
                vendor = Vendor.query.get(order.selected_vendor_id)
                if vendor:
                    app_logger.info(f"Order {order_id} has auto-assigned vendor {order.selected_vendor_id} ({vendor.business_name})")
                    vendor_data = {
                        "vendor_id": vendor.id,
                        "vendor_name": vendor.business_name,
                        "score": 1.0,
                        "distance_km": None,
                        "stock_available": order.quantity,
                        "capacity_available": order.quantity,
                        "lead_time_days": 2,
                        "base_cost_per_piece": order.price_per_piece_offered or 0,
                        "city": vendor.city or "",
                        "state": vendor.state or "",
                        "auto_assigned": True,
                        "is_marketplace": True,  # Treat auto-assigned orders as marketplace-like
                    }
                    
                    return jsonify({
                        "eligible_vendors": [vendor_data],
                        "order_quantity": order.quantity,
                        "product_catalog_ids": [],
                        "message": f"Vendor '{vendor.business_name}' is auto-assigned to this order.",
                        "is_marketplace": True
                    }), 200
            except Exception as e:
                app_logger.warning(f"Error fetching auto-assigned vendor {order.selected_vendor_id}: {e}")

        # 🔥 MARKETPLACE ORDER: Return vendor who posted the product
        # Check if order has marketplace_product_id set
        if hasattr(order, 'marketplace_product_id') and order.marketplace_product_id:
            app_logger.info(f"Order {order_id} is marketplace order with product_id: {order.marketplace_product_id}")
            try:
                product = MarketplaceProduct.query.get(order.marketplace_product_id)
                if not product:
                    app_logger.warning(f"Marketplace product {order.marketplace_product_id} not found for order {order_id}")
                    return jsonify({
                        "eligible_vendors": [],
                        "message": f"Marketplace product {order.marketplace_product_id} not found.",
                        "auto_assigned": False,
                        "is_marketplace": True
                    }), 200
                
                app_logger.info(f"Found marketplace product: {product.product_name}, vendor_id: {product.vendor_id}")
                
                vendor = Vendor.query.get(product.vendor_id)
                if not vendor:
                    app_logger.warning(f"Vendor {product.vendor_id} not found for marketplace product {order.marketplace_product_id}")
                    return jsonify({
                        "eligible_vendors": [],
                        "message": f"Vendor {product.vendor_id} not found for marketplace product.",
                        "auto_assigned": False,
                        "is_marketplace": True
                    }), 200
                
                # Return the vendor who posted the product
                vendor_data = {
                    "vendor_id": vendor.id,
                    "vendor_name": vendor.business_name,
                    "score": 1.0,  # Perfect match - vendor owns the product
                    "distance_km": None,  # Not applicable for marketplace
                    "stock_available": order.quantity,  # Use order quantity as available
                    "capacity_available": order.quantity,
                    "lead_time_days": 2,  # Default lead time for marketplace products
                    "base_cost_per_piece": float(product.price) if product.price else order.price_per_piece_offered or 0,
                    "city": vendor.city or "",
                    "state": vendor.state or "",
                    "auto_assigned": True,
                    "is_marketplace": True,
                    "product_name": product.product_name,
                    "product_image": product.image_url
                }
                
                app_logger.info(f"Marketplace order {order_id}: Returning vendor {vendor.id} ({vendor.business_name}) who posted product {order.marketplace_product_id}")
                
                return jsonify({
                    "eligible_vendors": [vendor_data],
                    "order_quantity": order.quantity,
                    "product_catalog_ids": [],
                    "message": f"Marketplace product order. Vendor '{vendor.business_name}' posted this product.",
                    "is_marketplace": True
                }), 200
                
            except Exception as e:
                app_logger.exception(f"Error fetching marketplace product vendor for order {order_id}: {e}")
                import traceback
                app_logger.error(f"Traceback: {traceback.format_exc()}")
                return jsonify({
                    "eligible_vendors": [],
                    "message": f"Error fetching marketplace product vendor: {str(e)}",
                    "auto_assigned": False,
                    "is_marketplace": True
                }), 200

        # 🔥 RFQ/CATALOG ORDER: Use recommendation engine
        from app_pkg.services.vendor_recommendation_engine import get_recommended_vendors

        total_qty = order.get_effective_quantity()
        product_catalog_ids = _resolve_order_to_product_catalog_ids(order)
        if not product_catalog_ids:
            return jsonify({
                "eligible_vendors": [],
                "message": "Could not resolve order to product catalog.",
                "order_product": f"{order.product_type or ''} / {order.category or ''} / {order.neck_type or ''} / {order.fabric or ''}",
                "is_marketplace": False
            }), 200

        import app_pkg.models as models
        # Recommendation engine does hard filtering + ranking
        candidates = get_recommended_vendors(order, product_catalog_ids, total_qty, db, models)
        
        return jsonify({
            "eligible_vendors": candidates,
            "order_quantity": total_qty,
            "product_catalog_ids": product_catalog_ids,
            "message": f"Found {len(candidates)} eligible vendor(s) based on requirements, capacity, and stock.",
            "is_marketplace": False
        }), 200
    except Exception as e:
        app_logger.exception(f"Get eligible vendors error: {e}")
        return jsonify({"error": "Failed to get eligible vendors"}), 500


@bp.route('/orders/<int:order_id>/recommended-vendors', methods=['GET'])
@admin_required
def get_recommended_vendors_for_order(order_id):
    """
    GET /api/admin/orders/<order_id>/recommended-vendors
    Returns vendors ranked by: requirement match, stock, distance, capacity, lead time.
    Backend-controlled, deterministic, transparent (score breakdown).
    """
    try:
        from app_pkg.services.vendor_recommendation_engine import get_recommended_vendors

        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404

        total_qty = order.get_effective_quantity()
        product_catalog_ids = _resolve_order_to_product_catalog_ids(order)
        if not product_catalog_ids:
            return jsonify({
                "recommended_vendors": [],
                "message": "Could not resolve order to product catalog.",
                "order_product": f"{order.product_type or ''} / {order.category or ''} / {order.neck_type or ''} / {order.fabric or ''}"
            }), 200

        import app_pkg.models as models
        candidates = get_recommended_vendors(order, product_catalog_ids, total_qty, db, models)
        return jsonify({
            "recommended_vendors": candidates,
            "order_quantity": total_qty,
            "product_catalog_ids": product_catalog_ids
        }), 200
    except Exception as e:
        app_logger.exception(f"Get recommended vendors error: {e}")
        return jsonify({"error": "Failed to get recommended vendors"}), 500


def _resolve_order_to_product_items(order):
    """Resolve order to list of (product_catalog_id, quantity) for stock deduction."""
    def _normalize(value):
        """Normalize string: strip, lowercase, handle None"""
        if not value:
            return ''
        return str(value).strip().lower()
    
    def _resolve(product_type, category, neck_type, fabric, size, try_without_fabric=False):
        """Resolve product catalog entry with fallback to no fabric."""
        pt_norm = _normalize(product_type)
        cat_norm = _normalize(category)
        nt_norm = _normalize(neck_type) if neck_type and neck_type.lower() != 'none' else None
        fb_norm = _normalize(fabric) if fabric and not try_without_fabric else None
        size_norm = str(size).strip().upper() if size else None
        
        q = ProductCatalog.query.filter(
            func.lower(ProductCatalog.product_type) == pt_norm,
            func.lower(ProductCatalog.category) == cat_norm,
        )
        
        if size_norm:
            q = q.filter(func.upper(ProductCatalog.size) == size_norm)
        if nt_norm:
            q = q.filter(func.lower(ProductCatalog.neck_type) == nt_norm)
        if fb_norm and not try_without_fabric:
            q = q.filter(func.lower(ProductCatalog.fabric) == fb_norm)
        
        p = q.first()
        return p.id if p else None

    pt = (order.product_type or '').strip()
    cat = (order.category or '').strip()
    nt = (order.neck_type or '').strip()
    fb = (order.fabric or '').strip()
    items = []
    
    if order.is_bulk_order and order.size_distribution:
        for size, qty in order.size_distribution.items():
            pid = _resolve(pt, cat, nt, fb, size, try_without_fabric=False)
            if not pid and fb:
                pid = _resolve(pt, cat, nt, fb, size, try_without_fabric=True)
            if pid and qty:
                items.append((pid, int(qty)))
    else:
        size = order.sample_size or (order.size_distribution and next(iter(order.size_distribution.keys()), None)) or 'M'
        pid = _resolve(pt, cat, nt, fb, size, try_without_fabric=False)
        if not pid and fb:
            pid = _resolve(pt, cat, nt, fb, size, try_without_fabric=True)
        if pid:
            items.append((pid, order.get_effective_quantity()))
    return items


def _resolve_order_to_product_catalog_ids(order):
    """
    Resolve order product fields to product_catalog ids.
    Uses case-insensitive matching and handles fabric mismatches gracefully.
    """
    def _normalize(value):
        """Normalize string: strip, lowercase, handle None"""
        if not value:
            return ''
        return str(value).strip().lower()
    
    def _resolve(product_type, category, neck_type, fabric, size, try_without_fabric=False):
        """
        Resolve product catalog entry.
        Tries with fabric first, then without fabric if not found.
        """
        # Normalize all inputs
        pt_norm = _normalize(product_type)
        cat_norm = _normalize(category)
        nt_norm = _normalize(neck_type) if neck_type and neck_type.lower() != 'none' else None
        fb_norm = _normalize(fabric) if fabric and not try_without_fabric else None
        size_norm = str(size).strip().upper() if size else None
        
        # Base query: product_type and category (required)
        q = ProductCatalog.query.filter(
            func.lower(ProductCatalog.product_type) == pt_norm,
            func.lower(ProductCatalog.category) == cat_norm,
        )
        
        # Add size filter (required for matching)
        if size_norm:
            q = q.filter(func.upper(ProductCatalog.size) == size_norm)
        
        # Add neck_type filter if provided
        if nt_norm:
            q = q.filter(func.lower(ProductCatalog.neck_type) == nt_norm)
        
        # Add fabric filter only if fabric is provided and we're not trying without it
        if fb_norm and not try_without_fabric:
            q = q.filter(func.lower(ProductCatalog.fabric) == fb_norm)
        
        p = q.first()
        return p.id if p else None
    
    # Normalize order fields
    pt = (order.product_type or '').strip()
    cat = (order.category or '').strip()
    nt = (order.neck_type or '').strip()
    fb = (order.fabric or '').strip()
    
    ids = []
    
    if order.is_bulk_order and order.size_distribution:
        # Bulk order: resolve each size
        for size in order.size_distribution.keys():
            # Try with fabric first
            pid = _resolve(pt, cat, nt, fb, size, try_without_fabric=False)
            # If not found and fabric was provided, try without fabric
            if not pid and fb:
                app_logger.info(f"Product not found with fabric '{fb}', trying without fabric for {pt}/{cat}/{nt}/{size}")
                pid = _resolve(pt, cat, nt, fb, size, try_without_fabric=True)
            
            if pid and pid not in ids:
                ids.append(pid)
            elif not pid:
                app_logger.warning(f"Could not resolve product: {pt}/{cat}/{nt}/{fb}/{size}")
    else:
        # Single size order
        size = order.sample_size or (order.size_distribution and next(iter(order.size_distribution.keys()), None)) or 'M'
        
        # Try with fabric first
        pid = _resolve(pt, cat, nt, fb, size, try_without_fabric=False)
        # If not found and fabric was provided, try without fabric
        if not pid and fb:
            app_logger.info(f"Product not found with fabric '{fb}', trying without fabric for {pt}/{cat}/{nt}/{size}")
            pid = _resolve(pt, cat, nt, fb, size, try_without_fabric=True)
        
        if pid:
            ids.append(pid)
        else:
            app_logger.warning(f"Could not resolve product catalog for order {order.id}: {pt}/{cat}/{nt}/{fb}/{size}")
    
    return ids


@bp.route('/orders/<int:order_id>/suggested-vendors', methods=['GET'])
@admin_required
def get_suggested_vendors_for_order(order_id):
    """
    GET /api/admin/orders/<order_id>/suggested-vendors (LEGACY)
    Uses recommendation engine; returns suggested_vendors for backward compatibility.
    """
    try:
        from app_pkg.services.vendor_recommendation_engine import get_recommended_vendors
        import app_pkg.models as models

        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        total_qty = order.get_effective_quantity()
        product_catalog_ids = _resolve_order_to_product_catalog_ids(order)
        if not product_catalog_ids:
            return jsonify({
                "suggested_vendors": [],
                "message": "Could not resolve order to product catalog.",
                "order_product": f"{order.product_type or ''} / {order.category or ''}"
            }), 200
        rec = get_recommended_vendors(order, product_catalog_ids, total_qty, db, models)
        suggested = [
            {
                "vendor_id": r["vendor_id"],
                "vendor_name": r["vendor_name"],
                "lead_time_days": r["lead_time_days"],
                "base_cost_per_piece": r["base_cost_per_piece"],
                "city": r.get("city"),
                "state": r.get("state"),
                "score": r.get("score"),
                "stock_available": r.get("stock_available"),
                "distance_km": r.get("distance_km"),
            }
            for r in rec
        ]
        return jsonify({
            "suggested_vendors": suggested,
            "order_quantity": total_qty,
            "product_catalog_ids": product_catalog_ids
        }), 200
    except Exception as e:
        app_logger.exception(f"Get suggested vendors error: {e}")
        return jsonify({"error": "Failed to get suggested vendors"}), 500


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
        sample_cost = data.get('sample_cost')  # 🔥 FIX: Remove default - only update if explicitly provided
        
        if not vendor_id:
            return jsonify({"error": "vendor_id is required"}), 400
        
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        # 🔥 CRITICAL: Prevent double assignment (race condition protection)
        # If order already has a vendor assigned, reject new assignment
        if order.selected_vendor_id is not None:
            existing_vendor = Vendor.query.get(order.selected_vendor_id)
            vendor_name = existing_vendor.business_name if existing_vendor else f"Vendor #{order.selected_vendor_id}"
            app_logger.warning(
                f"Assignment blocked: Order {order_id} already assigned to vendor {order.selected_vendor_id}"
            )
            return jsonify({
                "error": f"Order is already assigned to {vendor_name}. "
                        f"Cannot assign to another vendor. Please refresh the page."
            }), 409  # 409 Conflict
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # 🔥 SECURITY: Validate quantity is not None before calculation
        if order.quantity is None or order.quantity <= 0:
            app_logger.error(f"Invalid quantity for order {order_id}: {order.quantity}")
            return jsonify({"error": "Order quantity is invalid. Cannot calculate total price."}), 400
        
        # 🔥 BULK ORDER FIX: Use helper method to get effective quantity
        # This ensures correct quantity is used for bulk orders (bulk_quantity) vs sample orders (quantity)
        total_qty = order.get_effective_quantity()
        
        # 🔥 MARKETPLACE ORDER: Skip eligibility check - vendor owns the product
        if order.marketplace_product_id:
            try:
                product = MarketplaceProduct.query.get(order.marketplace_product_id)
                if product and product.vendor_id == vendor_id:
                    # Vendor owns the product - allow assignment
                    app_logger.info(f"Marketplace order {order_id}: Allowing assignment to product owner vendor {vendor_id}")
                else:
                    # Admin trying to assign different vendor - validate they're eligible
                    app_logger.warning(f"Marketplace order {order_id}: Admin assigning different vendor {vendor_id} (product owner: {product.vendor_id if product else 'unknown'})")
                    # Still validate the new vendor is eligible (admin can reassign if needed)
                    from app_pkg.services.vendor_recommendation_engine import get_recommended_vendors
                    import app_pkg.models as models
                    product_catalog_ids = _resolve_order_to_product_catalog_ids(order)
                    if product_catalog_ids:
                        eligible_vendors = get_recommended_vendors(order, product_catalog_ids, total_qty, db, models)
                        eligible_vendor_ids = [v["vendor_id"] for v in eligible_vendors]
                        if vendor_id not in eligible_vendor_ids:
                            return jsonify({
                                "error": f"Vendor {vendor_id} is not eligible for this order. "
                                        f"Marketplace product is owned by vendor {product.vendor_id if product else 'unknown'}. "
                                        f"Please select the product owner or an eligible vendor."
                            }), 400
            except Exception as e:
                app_logger.warning(f"Error validating marketplace product vendor: {e}")
                # Continue with normal validation as fallback
        
        # 🔥 RFQ/CATALOG ORDER: Validate vendor eligibility using recommendation engine
        if not order.marketplace_product_id:
            # 🔥 CRITICAL SECURITY: Re-validate vendor eligibility before assignment
            # Frontend filtering is not enough - admin could modify request manually
            # Backend must enforce eligibility as source of truth
            from app_pkg.services.vendor_recommendation_engine import get_recommended_vendors
            import app_pkg.models as models
            product_catalog_ids = _resolve_order_to_product_catalog_ids(order)
            if not product_catalog_ids:
                return jsonify({"error": "Could not resolve order to product catalog. Cannot validate eligibility."}), 400
            
            eligible_vendors = get_recommended_vendors(order, product_catalog_ids, total_qty, db, models)
            eligible_vendor_ids = [v["vendor_id"] for v in eligible_vendors]
            
            # 🔥 MANUAL ASSIGNMENT: If no eligible vendors found, allow manual assignment
            # Admin can override and assign any verified vendor when recommendation engine finds none
            if len(eligible_vendor_ids) > 0 and vendor_id not in eligible_vendor_ids:
                app_logger.warning(
                    f"Assignment blocked: Vendor {vendor_id} not eligible for order {order_id}. "
                    f"Eligible vendors: {eligible_vendor_ids}"
                )
                return jsonify({
                    "error": f"Vendor {vendor_id} is not eligible for this order. "
                            f"Vendor must have: approved quotation for all products, sufficient capacity, "
                            f"and be verified. Please select from eligible vendors only."
                }), 400
            elif len(eligible_vendor_ids) == 0:
                # No eligible vendors found - allow manual assignment but log it
                app_logger.info(
                    f"Manual assignment allowed: No eligible vendors found for order {order_id}. "
                    f"Admin manually assigning vendor {vendor_id} ({vendor.business_name})."
                )
        
        # 🔥 CRITICAL: Verify vendor verification status (double-check)
        if vendor.verification_status not in ('approved', 'active'):
            app_logger.warning(f"Assignment blocked: Vendor {vendor_id} verification_status={vendor.verification_status}")
            return jsonify({"error": "Vendor is not verified. Only approved/active vendors can be assigned."}), 400
        
        # Assign vendor to order
        order.selected_vendor_id = vendor_id
        
        # 🔥 FIX: Use quotation_price if provided, otherwise use vendor's base cost or order's existing price
        if quotation_price:
            new_price = float(quotation_price)
            order.quotation_price_per_piece = new_price
            order.quotation_total_price = new_price * total_qty  # Use correct quantity (bulk or sample)
        else:
            # If no quotation price provided, try to get from vendor quotation or use existing price
            # For marketplace orders, price is already set, so keep it
            if order.quotation_price_per_piece:
                # Keep existing price
                order.quotation_total_price = order.quotation_price_per_piece * total_qty
            else:
                # Try to get from vendor quotation
                from app_pkg.models import VendorQuotation
                vq = VendorQuotation.query.filter_by(
                    vendor_id=vendor_id,
                    product_id=order.product_catalog_id,
                    status='approved'
                ).first()
                if vq and vq.base_cost:
                    order.quotation_price_per_piece = float(vq.base_cost)
                    order.quotation_total_price = float(vq.base_cost) * total_qty
                else:
                    # Fallback: use price_per_piece_offered if available
                    if order.price_per_piece_offered:
                        order.quotation_price_per_piece = float(order.price_per_piece_offered)
                        order.quotation_total_price = float(order.price_per_piece_offered) * total_qty
        
        # 🔥 FIX: Only update sample_cost if explicitly provided (should not overwrite existing value)
        # Sample cost is determined at order creation time and should not be changed during vendor assignment
        if sample_cost is not None:
            app_logger.warning(f"Sample cost being updated for order {order_id}: {order.sample_cost} -> {sample_cost}")
            order.sample_cost = float(sample_cost)
        # If not provided, keep existing sample_cost from order creation
        
        # 🔥 LOGGING: Log assignment details for debugging
        app_logger.info(
            f"Assigning vendor: Order={order_id}, "
            f"Vendor={vendor_id}, "
            f"Qty={order.quantity}, "
            f"BulkQty={order.bulk_quantity if order.is_bulk_order else 'N/A'}, "
            f"IsBulk={order.is_bulk_order}, "
            f"EffectiveQty={total_qty}, "
            f"PricePerPiece={order.quotation_price_per_piece}, "
            f"Total={order.quotation_total_price}, "
            f"SampleCost={order.sample_cost}"
        )
        # 🔥 FIX: Set status to 'quotation_sent_to_customer' to match state machine
        # Vendor will see order only after customer pays advance (status becomes 'in_production')
        # This matches the state machine: pending_admin_review → quotation_sent_to_customer
        order.status = 'quotation_sent_to_customer'
        
        # Create vendor order assignment record
        # 🔥 FIX: Since vendor must compulsorily produce, status should be 'assigned' not 'pending'
        assignment = VendorOrderAssignment(
            order_id=order_id,
            vendor_id=vendor_id,
            status='assigned',  # Changed from 'pending' - vendor must compulsorily produce
            assigned_at=datetime.utcnow()
        )
        db.session.add(assignment)
        
        # Create notification for vendor
        notif = Notification(
            user_id=vendor_id,
            user_type='vendor',
            title='New Order Assigned',
            message=f'You have been assigned Order ORD-{order_id}. Please start production when ready.',
            type='order'
        )
        db.session.add(notif)

        # 🔥 CRITICAL CONCURRENCY SAFETY: Deduct vendor_stock with row-level locking
        # Prevents race condition: two admins assigning simultaneously → negative stock
        # 📌 CONCEPTUAL SEPARATION: Stock = ready goods, Capacity = production ability
        # If vendor has stock, deduct it. If no stock row exists, vendor uses capacity (made-to-order)
        product_items = _resolve_order_to_product_items(order)
        for pcid, qty in product_items:
            # Use with_for_update() to lock row during transaction
            stock_row = db.session.query(VendorStock).filter_by(
                vendor_id=vendor_id,
                product_catalog_id=pcid
            ).with_for_update().first()
            
            if stock_row:
                # Vendor has stock - deduct it
                if stock_row.available_quantity < qty:
                    # Rollback transaction if insufficient stock
                    db.session.rollback()
                    app_logger.warning(
                        f"Stock deduction failed: Order {order_id}, Product {pcid}, "
                        f"Required {qty}, Available {stock_row.available_quantity}"
                    )
                    return jsonify({
                        "error": f"Insufficient stock for product. Available: {stock_row.available_quantity}, Required: {qty}"
                    }), 400
                
                # Deduct stock atomically
                stock_row.available_quantity = stock_row.available_quantity - qty
                app_logger.info(
                    f"Stock deducted: Vendor {vendor_id}, Product {pcid}, "
                    f"Quantity {qty}, Remaining {stock_row.available_quantity}"
                )
            else:
                # No stock row exists - vendor will fulfill via capacity (made-to-order)
                # This is expected for capacity-based vendors (production model)
                app_logger.info(
                    f"Order {order_id}, Product {pcid}: No stock row for vendor {vendor_id}. "
                    f"Vendor will fulfill via production capacity (made-to-order model)."
                )

        db.session.commit()
        
        # Log activity
        vendor_name = vendor.business_name or vendor.username or f"Vendor #{vendor_id}"
        log_activity_from_request(
            action=f"Assigned Order #{order_id} to {vendor_name}",
            action_type="admin_action",
            entity_type="order",
            entity_id=order_id,
            details=f"Quotation price: ₹{quotation_price} per piece, Quantity: {total_qty} ({'bulk' if order.is_bulk_order else 'sample'}), Total: ₹{order.quotation_total_price}, Sample cost: ₹{order.sample_cost}"
        )
        
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
    Approve vendor (set verification_status to 'approved' or 'active')
    🔥 GPS VALIDATION: Vendor must have latitude/longitude before approval
    """
    try:
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        # 🔥 GPS VALIDATION: Vendor must have GPS location before approval (required for distance-based ranking)
        if vendor.latitude is None or vendor.longitude is None:
            return jsonify({
                "error": "Vendor GPS location required",
                "message": "Vendor must set their latitude and longitude (GPS location) before approval. This is required for distance-based order assignment."
            }), 400
        
        # Validate coordinates are not 0.0 (invalid)
        try:
            lat = float(vendor.latitude)
            lon = float(vendor.longitude)
            if lat == 0.0 and lon == 0.0:
                return jsonify({
                    "error": "Invalid GPS location",
                    "message": "Vendor GPS coordinates cannot be (0,0). Please set a valid location."
                }), 400
        except (ValueError, TypeError):
            return jsonify({
                "error": "Invalid GPS location format",
                "message": "Vendor GPS coordinates must be valid numbers."
            }), 400
        
        # Set default values
        vendor.commission_rate = 15.0
        vendor.payment_cycle = 'monthly'
        vendor.service_zone = 'all'
        vendor.verification_status = 'approved'
        
        # Update all document statuses to approved
        doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
        if doc_row:
            from sqlalchemy.orm.attributes import flag_modified
            for doc_type in ['pan', 'aadhar', 'bank', 'workshop', 'signature', 'business_document']:
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
            message='Your account verification has been approved. Submit your quotation, then set Production Capacity (daily capacity + lead time) to receive order assignments.',
            type='verification'
        )
        db.session.add(notif)
        
        db.session.commit()
        
        # Log activity
        vendor_name = vendor.business_name or vendor.username or f"Vendor #{vendor_id}"
        log_activity_from_request(
            action=f"Approved vendor verification: {vendor_name}",
            action_type="verification",
            entity_type="vendor",
            entity_id=vendor_id,
            details=f"Commission rate: {vendor.commission_rate}%, Payment cycle: {vendor.payment_cycle}"
        )
        
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
                for doc_type in ['pan', 'aadhar', 'bank', 'workshop', 'signature', 'business_document', 'quotation']:
                    meta_attr = f"{doc_type}_meta"
                    if hasattr(doc_row, meta_attr):
                        meta = getattr(doc_row, meta_attr)
                        meta = dict(meta) if meta else {}
                        meta['status'] = 'rejected'
                        meta['remarks'] = reason
                        setattr(doc_row, meta_attr, meta)
                        flag_modified(doc_row, meta_attr)
        
        db.session.commit()
        
        # Log activity
        vendor_name = vendor.business_name or vendor.username or f"Vendor #{vendor_id}"
        log_activity_from_request(
            action=f"Rejected vendor verification: {vendor_name}",
            action_type="verification",
            entity_type="vendor",
            entity_id=vendor_id,
            details=reason
        )
        
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
        
        # Log activity
        rider_name = rider.name or rider.email or f"Rider #{rider_id}"
        log_activity_from_request(
            action=f"Approved rider verification: {rider_name}",
            action_type="verification",
            entity_type="rider",
            entity_id=rider_id
        )
        
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
        rejected_docs = data.get('rejected_documents', {})
        
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        rider.verification_status = 'rejected'
        rider.admin_remarks = reason
        
        # Update document statuses
        doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
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
                for doc_type in ['aadhar', 'dl', 'pan', 'photo', 'vehicle_rc', 'insurance', 'bank']:
                    meta_attr = f"{doc_type}_meta"
                    if hasattr(doc_row, meta_attr):
                        meta = getattr(doc_row, meta_attr)
                        meta = dict(meta) if meta else {}
                        meta['status'] = 'rejected'
                        meta['remarks'] = reason
                        setattr(doc_row, meta_attr, meta)
                        flag_modified(doc_row, meta_attr)
        
        db.session.commit()
        
        # Log activity
        rider_name = rider.name or rider.email or f"Rider #{rider_id}"
        log_activity_from_request(
            action=f"Rejected rider verification: {rider_name}",
            action_type="verification",
            entity_type="rider",
            entity_id=rider_id,
            details=reason
        )
        
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
                    "filename": sub.quotation_filename or "No file",
                    "submitted_at": sub.submitted_at.isoformat() if sub.submitted_at else None,
                    "status": sub.status or "pending"
                })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get quotation submissions error: {e}")
        return jsonify({"error": "Failed to retrieve quotation submissions"}), 500


# CSV Header Mapping: Maps CSV column names to database column names
CSV_HEADER_MAP = {
    "Product Type": "product_type",
    "Category": "category",
    "Neck Type": "neck_type",
    "Fabric": "fabric",
    "Size": "size",
    "Base Cost": "base_cost",
    "Notes": "notes"
}


def ensure_product_catalog_exists(product_type, category, neck_type, fabric, size, notes=None):
    """
    Insert product catalog entry ONLY if it does not exist.
    Does NOT update pricing - pricing is calculated by the Pricing Engine from vendor_quotations.
    
    Args:
        product_type, category, neck_type, fabric, size, notes
    Returns:
        ProductCatalog id
    """
    pc = ProductCatalog.query.filter(
        func.lower(ProductCatalog.product_type) == product_type.strip().lower(),
        func.lower(ProductCatalog.category) == category.strip().lower(),
        func.lower(ProductCatalog.neck_type) == neck_type.strip().lower(),
        func.lower(ProductCatalog.fabric) == fabric.strip().lower(),
        func.upper(ProductCatalog.size) == size.strip().upper()
    ).first()
    if pc:
        if notes and not pc.notes:
            pc.notes = notes
        return pc.id
    # Insert new with 0/0/0 - pricing engine will populate after vendor_quotations exist
    sql = text("""
        INSERT INTO product_catalog
        (product_type, category, neck_type, fabric, size, notes, average_price, final_price, vendor_count)
        VALUES (:product_type, :category, :neck_type, :fabric, :size, :notes, 0, 0, 0)
    """)
    db.session.execute(sql, {
        "product_type": product_type.strip(),
        "category": category.strip(),
        "neck_type": neck_type.strip(),
        "fabric": fabric.strip(),
        "size": size.strip().upper(),
        "notes": notes
    })
    db.session.flush()
    # Fetch the new id
    pc = ProductCatalog.query.filter(
        func.lower(ProductCatalog.product_type) == product_type.strip().lower(),
        func.lower(ProductCatalog.category) == category.strip().lower(),
        func.lower(ProductCatalog.neck_type) == neck_type.strip().lower(),
        func.lower(ProductCatalog.fabric) == fabric.strip().lower(),
        func.upper(ProductCatalog.size) == size.strip().upper()
    ).first()
    return pc.id if pc else None


def recalculate_product_catalog_pricing(product_catalog_ids):
    """
    Pricing Engine: Recalculate product_catalog from approved vendor_quotations.
    
    average_price = AVG(quoted_price) where is_approved (status='approved')
    vendor_count = COUNT(approved quotations)
    final_price = average_price * 1.30 (30% platform margin)
    
    Only approved quotations affect pricing. Vendors cannot manipulate marketplace price.
    """
    if not product_catalog_ids:
        return
    for pcid in product_catalog_ids:
        # Aggregate from vendor_quotations (vendor DB) - use product_id = product_catalog_id
        agg = db.session.query(
            func.avg(VendorQuotation.base_cost).label('avg_price'),
            func.count(VendorQuotation.id).label('cnt')
        ).filter(
            VendorQuotation.product_id == pcid,
            VendorQuotation.status == 'approved'
        ).first()
        avg_price = float(agg.avg_price) if agg and agg.avg_price else None
        vendor_count = int(agg.cnt) if agg and agg.cnt else 0
        pc = ProductCatalog.query.get(pcid)
        if pc:
            # 🔥 SECURITY: Only update pricing if we have approved vendors
            # If vendor_count = 0, keep previous price (don't set to ₹0)
            # This prevents accidental zero-price exposure if all vendors are rejected
            if vendor_count > 0 and avg_price is not None:
                final_price = round(avg_price * 1.30, 2)
                pc.average_price = avg_price
                pc.final_price = final_price
                pc.vendor_count = vendor_count
            elif vendor_count == 0:
                # No approved vendors - keep existing price, set vendor_count to 0
                # Frontend should check vendor_count > 0 before displaying price
                pc.vendor_count = 0
                # Don't modify average_price or final_price - keep last known good price
                app_logger.warning(
                    f"Product {pcid} has no approved vendors. Keeping previous price: "
                    f"avg={pc.average_price}, final={pc.final_price}"
                )
            pc.updated_at = datetime.utcnow()
    db.session.flush()


def process_quotation_csv(submission):
    """
    Process quotation CSV file (FINAL ARCHITECTURE):
    
    1. Ensure product_catalog rows exist (INSERT only if new - NO pricing update)
    2. Insert/update vendor_quotations (vendor_id, product_catalog_id, base_cost, status='approved')
    3. Run Pricing Engine: recalculate product_catalog from AVG(approved vendor_quotations)
    
    Vendors can add new product types; pricing is ALWAYS derived from approved quotations.
    """
    try:
        upload_root = current_app.config.get('UPLOAD_FOLDER')
        if not upload_root:
            app_logger.error("UPLOAD_FOLDER not configured")
            raise ValueError("Upload folder not configured")
        
        csv_path = get_file_path_from_db(submission.quotation_file)
        if not csv_path or not os.path.exists(csv_path):
            app_logger.error(f"CSV file not found: {submission.quotation_file}")
            raise FileNotFoundError(f"CSV file not found: {submission.quotation_file}")
        
        app_logger.info(f"Processing quotation CSV: {csv_path}")
        
        processed_count = 0
        error_count = 0
        affected_product_catalog_ids = set()
        
        # Open CSV with UTF-8-sig encoding to handle BOM from Excel
        with open(csv_path, newline='', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            
            # Validate headers
            csv_headers = reader.fieldnames
            if not csv_headers:
                raise ValueError("CSV file has no headers")
            
            # Check for required headers
            required_headers = list(CSV_HEADER_MAP.keys())
            missing_headers = [h for h in required_headers if h not in csv_headers]
            if missing_headers:
                app_logger.warning(f"Missing CSV headers: {missing_headers}. Available: {csv_headers}")
            
            for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
                try:
                    # Map CSV headers to database columns
                    product = {}
                    for csv_key, db_key in CSV_HEADER_MAP.items():
                        if csv_key in row and row[csv_key]:
                            product[db_key] = row[csv_key].strip()
                    
                    # Extract base_cost (required)
                    if 'base_cost' not in product or not product['base_cost']:
                        app_logger.warning(f"Row {row_num}: Missing Base Cost, skipping")
                        error_count += 1
                        continue
                    
                    try:
                        base_cost = float(product.pop('base_cost'))
                    except (ValueError, TypeError):
                        app_logger.warning(f"Row {row_num}: Invalid Base Cost '{product.get('base_cost')}', skipping")
                        error_count += 1
                        continue
                    
                    # Validate required fields
                    required_fields = ['product_type', 'category', 'neck_type', 'fabric', 'size']
                    missing_fields = [f for f in required_fields if not product.get(f)]
                    if missing_fields:
                        app_logger.warning(f"Row {row_num}: Missing required fields {missing_fields}, skipping")
                        error_count += 1
                        continue
                    
                    # Extract notes (optional)
                    notes = product.pop('notes', None)
                    
                    # Step 1: Ensure product_catalog exists (no pricing - pricing engine handles that)
                    pcid = ensure_product_catalog_exists(
                        product_type=product['product_type'],
                        category=product['category'],
                        neck_type=product['neck_type'],
                        fabric=product['fabric'],
                        size=product['size'],
                        notes=notes
                    )
                    if not pcid:
                        app_logger.warning(f"Row {row_num}: Could not resolve product_catalog id, skipping")
                        error_count += 1
                        continue
                    db.session.flush()

                    # Step 2: Create/update vendor_quotations (pricing input layer)
                    vq = VendorQuotation.query.filter_by(
                        vendor_id=submission.vendor_id,
                        product_id=pcid
                    ).first()
                    if vq:
                        vq.base_cost = base_cost
                        vq.status = 'approved'
                        vq.admin_remarks = None
                    else:
                        vq = VendorQuotation(
                            vendor_id=submission.vendor_id,
                            product_id=pcid,
                            base_cost=base_cost,
                            status='approved'
                        )
                        db.session.add(vq)

                    affected_product_catalog_ids.add(pcid)
                    processed_count += 1
                    
                except Exception as e:
                    app_logger.warning(f"Row {row_num}: Error processing row: {e}")
                    error_count += 1
                    continue
        
        # Step 3: Pricing Engine - recalculate product_catalog from approved vendor_quotations
        if affected_product_catalog_ids:
            recalculate_product_catalog_pricing(list(affected_product_catalog_ids))
        
        app_logger.info(f"CSV processing complete: {processed_count} rows processed, {error_count} errors")
        return processed_count, error_count
        
    except Exception as e:
        app_logger.exception(f"Error processing quotation CSV: {e}")
        raise


@bp.route('/quotation-submissions/<int:submission_id>/approve', methods=['POST'])
@admin_required
def approve_quotation_submission(submission_id):
    """
    POST /api/admin/quotation-submissions/<submission_id>/approve
    Approve quotation submission
    """
    try:
        data = request.get_json() or {}
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
        
        # Process CSV and update product catalog
        processed_count = 0
        error_count = 0
        try:
            processed_count, error_count = process_quotation_csv(submission)
            app_logger.info(f"Quotation CSV processed: {processed_count} rows processed, {error_count} errors")
        except Exception as csv_error:
            app_logger.exception(f"Error processing quotation CSV: {csv_error}")
            # Don't fail approval if CSV processing fails, but log it
            # Admin can manually fix CSV issues
            db.session.rollback()
            return jsonify({
                "error": "Failed to process quotation CSV",
                "details": str(csv_error)
            }), 500
        
        db.session.commit()
        
        # Create notification
        notif = Notification(
            user_id=vendor.id,
            user_type='vendor',
            title='Quotation Approved',
            message='Your quotation has been approved.',
            type='verification'
        )
        db.session.add(notif)
        db.session.commit()
        
        return jsonify({
            "message": "Quotation approved successfully",
            "csv_processed": processed_count,
            "csv_errors": error_count
        }), 200
        
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


@bp.route('/quotation-submissions/<int:submission_id>/download', methods=['GET'])
@admin_required
def download_quotation(submission_id):
    """
    GET /api/admin/quotation-submissions/<submission_id>/download
    Download quotation file (admin access)
    """
    try:
        submission = VendorQuotationSubmission.query.get(submission_id)
        if not submission:
            return jsonify({"error": "Quotation submission not found"}), 404
        
        if not submission.quotation_file:
            return jsonify({"error": "Quotation file not found"}), 404
        
        # Get absolute file path from relative path stored in database
        absolute_path = get_file_path_from_db(submission.quotation_file)
        
        if not absolute_path or not os.path.exists(absolute_path):
            return jsonify({"error": "File not found on disk"}), 404
        
        # Return file with proper MIME type and filename
        return send_file(
            absolute_path,
            mimetype=submission.quotation_mimetype or 'text/csv',
            as_attachment=True,
            download_name=submission.quotation_filename or 'quotation.csv'
        )
        
    except Exception as e:
        app_logger.exception(f"Download quotation error: {e}")
        return jsonify({"error": "Failed to download quotation file"}), 500


@bp.route('/production-orders', methods=['GET'])
@admin_required
def get_production_orders():
    """
    GET /api/admin/production-orders
    Get all orders currently in production
    """
    try:
        production_statuses = [
            'assigned', 'in_production', 'material_prep',
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
            
            # Progress calculation - removed 'assigned' and 'accepted_by_vendor' stages (not in state machine)
            # Orders enter production after advance payment, starting with 'in_production'
            status_order = ['in_production', 'material_prep', 'printing', 
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
                "deadline": o.delivery_date.isoformat() if o.delivery_date else None,
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
                    for doc_type in ['pan', 'aadhar', 'bank', 'workshop', 'signature', 'business_document']:
                        if hasattr(doc_row, f"{doc_type}_meta"):
                            meta = getattr(doc_row, f"{doc_type}_meta")
                            if meta:
                                doc_data = {
                                    'status': meta.get('status', 'pending'),
                                    'fileName': meta.get('filename'),
                                    'fileSize': meta.get('size'),
                                    'uploadedDate': meta.get('uploaded_at'),
                                    'resubmitted': meta.get('resubmitted', False),
                                    'adminRemarks': meta.get('remarks', ''),
                                    'previousRejectionReason': meta.get('previous_rejection_reason', '')
                                }
                                # Add file path if document exists
                                if hasattr(doc_row, doc_type):
                                    doc_path = getattr(doc_row, doc_type)
                                    if doc_path:
                                        doc_data['file'] = doc_path
                                        doc_data['path'] = doc_path
                                if doc_type == 'pan':
                                    doc_data['pan_number'] = doc_row.pan_number
                                if doc_type == 'aadhar':
                                    doc_data['aadhar_number'] = doc_row.aadhar_number
                                if doc_type == 'bank':
                                    doc_data['bank_account_number'] = doc_row.bank_account_number
                                    doc_data['bank_holder_name'] = doc_row.bank_holder_name
                                    doc_data['bank_branch'] = doc_row.bank_branch
                                    doc_data['ifsc_code'] = doc_row.ifsc_code
                                documents[doc_type] = doc_data
                
                # Add business details fields (handle missing columns gracefully)
                business_details = {}
                if doc_row:
                    # Use getattr with default None to handle missing columns (before migration runs)
                    company_unique_id = getattr(doc_row, 'company_unique_id', None)
                    company_id_number = getattr(doc_row, 'company_id_number', None)
                    date_of_est = getattr(doc_row, 'date_of_establishment', None)
                    business_details = {
                        'company_unique_id': company_unique_id,
                        'company_id_number': company_id_number,
                        'date_of_establishment': date_of_est.strftime('%Y-%m-%d') if date_of_est else None
                    }
                
                result.append({
                    "id": v.id,
                    "name": v.business_name or v.username or "Unknown",
                    "businessType": v.business_type or "N/A",
                    "submitted": v.created_at.strftime('%Y-%m-%d') if v.created_at else "N/A",
                    "status": v.verification_status or "pending",
                    "documents": documents,
                    "business_details": business_details,
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
                    for doc_type in ['pan', 'aadhar', 'bank', 'workshop', 'signature', 'business_document']:
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
                                # Add file path if document exists
                                if hasattr(doc_row, doc_type):
                                    doc_path = getattr(doc_row, doc_type)
                                    if doc_path:
                                        doc_data['file'] = doc_path
                                        doc_data['path'] = doc_path
                                documents[doc_type] = doc_data
                
                # Add business details fields (handle missing columns gracefully)
                business_details = {}
                if doc_row:
                    # Use getattr with default None to handle missing columns (before migration runs)
                    company_unique_id = getattr(doc_row, 'company_unique_id', None)
                    company_id_number = getattr(doc_row, 'company_id_number', None)
                    date_of_est = getattr(doc_row, 'date_of_establishment', None)
                    business_details = {
                        'company_unique_id': company_unique_id,
                        'company_id_number': company_id_number,
                        'date_of_establishment': date_of_est.strftime('%Y-%m-%d') if date_of_est else None
                    }
                
                result.append({
                    'id': v.id,
                    'name': v.username or 'Unknown',
                    'businessName': v.business_name,
                    'email': v.email,
                    'phone': v.phone,
                    'status': v.verification_status,
                    'submitted': v.created_at.strftime('%Y-%m-%d') if v.created_at else "N/A",
                    'adminRemarks': v.admin_remarks,
                    'documents': documents,
                    'business_details': business_details
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


@bp.route('/vendor-requests/<int:vendor_id>/document/<doc_type>', methods=['GET'])
@admin_required
def view_vendor_document(vendor_id, doc_type):
    """
    GET /api/admin/vendor-requests/<vendor_id>/document/<doc_type>
    View vendor verification document (admin access)
    """
    try:
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        doc_row = VendorDocument.query.filter_by(vendor_id=vendor_id).first()
        
        if not doc_row or not hasattr(doc_row, doc_type):
            return jsonify({"error": "Document not found"}), 404
        
        file_path = getattr(doc_row, doc_type)
        meta = getattr(doc_row, f"{doc_type}_meta")
        
        if not file_path:
            return jsonify({"error": "Document file path not found"}), 404
        
        if not meta:
            return jsonify({"error": "Document metadata not found"}), 404
        
        # Get absolute file path
        absolute_path = get_file_path_from_db(file_path)
        
        if not absolute_path or not os.path.exists(absolute_path):
            return jsonify({"error": "File not found on disk"}), 404
        
        # Return file with proper MIME type
        return send_file(
            absolute_path,
            mimetype=meta.get('mimetype', 'application/octet-stream') if isinstance(meta, dict) else 'application/octet-stream',
            as_attachment=False,
            download_name=meta.get('filename', f'{doc_type}.pdf') if isinstance(meta, dict) else f'{doc_type}.pdf'
        )
        
    except Exception as e:
        app_logger.exception(f"View vendor document error: {e}")
        return jsonify({"error": "Failed to retrieve document"}), 500


@bp.route('/verified-vendors', methods=['GET'])
@admin_required
def get_verified_vendors():
    """
    GET /api/admin/verified-vendors
    Get all verified vendors (only vendors with verification_status = 'approved')
    🔥 FIX: DB only uses 'approved', not 'verified' - updated for consistency
    """
    try:
        vendors = Vendor.query.filter(
            Vendor.verification_status == 'approved'  # 🔥 FIX: DB uses 'approved', not 'verified'
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
                                # Handle resubmitted status - show as rejected with resubmitted flag
                                doc_status = meta.get('status', 'pending')
                                is_resubmitted = meta.get('resubmitted', False) or doc_status == 'resubmitted'
                                
                                doc_data = {
                                    'status': 'rejected' if is_resubmitted else doc_status,
                                    'fileName': meta.get('filename'),
                                    'fileSize': meta.get('size'),
                                    'uploadedDate': meta.get('uploaded_at'),
                                    'resubmitted': is_resubmitted,
                                    'adminRemarks': meta.get('remarks', ''),
                                    'previousRejectionReason': meta.get('previous_rejection_reason', '')
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


@bp.route('/rider-requests/<int:rider_id>/document/<doc_type>', methods=['GET'])
@admin_required
def view_rider_document(rider_id, doc_type):
    """
    GET /api/admin/rider-requests/<rider_id>/document/<doc_type>
    View rider verification document (admin access)
    """
    try:
        rider = Rider.query.get(rider_id)
        if not rider:
            return jsonify({"error": "Rider not found"}), 404
        
        doc_row = RiderDocument.query.filter_by(rider_id=rider_id).first()
        
        if not doc_row or not hasattr(doc_row, doc_type):
            return jsonify({"error": "Document not found"}), 404
        
        file_path = getattr(doc_row, doc_type)
        meta = getattr(doc_row, f"{doc_type}_meta")
        
        if not file_path:
            return jsonify({"error": "Document file path not found"}), 404
        
        if not meta:
            return jsonify({"error": "Document metadata not found"}), 404
        
        # Get absolute file path
        absolute_path = get_file_path_from_db(file_path)
        
        if not absolute_path or not os.path.exists(absolute_path):
            return jsonify({"error": "File not found on disk"}), 404
        
        # Return file with proper MIME type
        return send_file(
            absolute_path,
            mimetype=meta.get('mimetype', 'application/octet-stream') if isinstance(meta, dict) else 'application/octet-stream',
            as_attachment=False,
            download_name=meta.get('filename', f'{doc_type}.pdf') if isinstance(meta, dict) else f'{doc_type}.pdf'
        )
        
    except Exception as e:
        app_logger.exception(f"View rider document error: {e}")
        return jsonify({"error": "Failed to retrieve document"}), 500


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
                'vendor_assigned'
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
        from app_pkg.models import ProductCatalog, compute_price_splits
        products = ProductCatalog.query.all()
        
        result = []
        for p in products:
            # Calculate final_price if not set (for existing records)
            avg_price = float(p.average_price) if p.average_price else 0
            final_price = float(p.final_price) if p.final_price else (avg_price * 1.30)
            splits = compute_price_splits(final_price)
            
            result.append({
                'id': p.id,
                'product_type': p.product_type,
                'category': p.category,
                'neck_type': p.neck_type,
                'fabric': p.fabric,
                'size': p.size,
                'average_price': avg_price,
                'final_price': final_price,
                'vendor_pay': splits['vendor_pay'],
                'platform_pay': splits['platform_pay'],
                'rider_pay': splits['rider_pay'],
                'support_pay': splits['support_pay'],
                'vendor_count': p.vendor_count or 0,
                'notes': p.notes,
                'updated_at': p.updated_at.isoformat() if p.updated_at else None
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get product catalog error: {e}")
        return jsonify({"error": "Failed to retrieve product catalog"}), 500


@bp.route('/product-catalog/recalculate-pricing', methods=['POST'])
@admin_required
def recalculate_product_catalog_pricing_all():
    """
    POST /api/admin/product-catalog/recalculate-pricing
    Recalculate all product_catalog pricing from approved vendor_quotations.
    Use after data fixes or migration.
    """
    try:
        all_ids = [p.id for p in ProductCatalog.query.all()]
        recalculate_product_catalog_pricing(all_ids)
        db.session.commit()
        return jsonify({
            "message": "Pricing engine completed successfully",
            "products_updated": len(all_ids)
        }), 200
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Recalculate pricing error: {e}")
        return jsonify({"error": "Failed to recalculate pricing"}), 500


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
        from app_pkg.models import ProductCatalog, VendorQuotation, compute_price_splits
        products = ProductCatalog.query.filter(ProductCatalog.vendor_count > 0).all()
        
        result = []
        for p in products:
            quotations = VendorQuotation.query.filter_by(product_id=p.id, status='approved').all()
            min_price = min([float(q.base_cost) for q in quotations], default=float(p.average_price)) if quotations else float(p.average_price)
            max_price = max([float(q.base_cost) for q in quotations], default=float(p.average_price)) if quotations else float(p.average_price)
            final_price = float(p.final_price) if p.final_price else (float(p.average_price) * 1.30)
            splits = compute_price_splits(final_price)
            
            result.append({
                'id': p.id,
                'product_type': p.product_type,
                'category': p.category,
                'neck_type': p.neck_type,
                'fabric': p.fabric,
                'size': p.size,
                'average_price': float(p.average_price) if p.average_price else 0,
                'final_price': final_price,
                'vendor_pay': splits['vendor_pay'],
                'platform_pay': splits['platform_pay'],
                'rider_pay': splits['rider_pay'],
                'support_pay': splits['support_pay'],
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


# ============================================================================
# Marketplace Products Approval (Vendor → Admin Approval → Customer Display)
# ============================================================================

@bp.route('/products/pending', methods=['GET'])
@admin_required
def get_pending_products():
    """
    GET /api/admin/products/pending
    Get all products with status='PENDING' for admin review
    """
    try:
        from sqlalchemy import text
        
        # Get vendor information via cross-database join
        # marketplace_products is in admin DB, vendors is in vendor DB
        admin_db = current_app.config.get('DB_NAME_ADMIN', 'impromptuindian_admin')
        vendor_db = current_app.config.get('DB_NAME_VENDOR', 'impromptuindian_vendor')
        
        sql = text(f"""
            SELECT 
                mp.id,
                mp.vendor_id,
                mp.product_name,
                mp.description,
                mp.price,
                mp.sizes,
                mp.colors,
                mp.image_url,
                mp.status,
                mp.admin_comment,
                mp.created_at,
                mp.updated_at,
                v.business_name as vendor_name,
                v.username as vendor_username
            FROM {admin_db}.marketplace_products mp
            LEFT JOIN {vendor_db}.vendors v ON mp.vendor_id = v.id
            WHERE mp.status = 'PENDING'
            ORDER BY mp.created_at ASC
        """)
        
        result = db.session.execute(sql)
        products = []
        
        for row in result:
            products.append({
                "id": row.id,
                "vendor_id": row.vendor_id,
                "vendor_name": row.vendor_name or f"Vendor #{row.vendor_id}",
                "vendor_username": row.vendor_username,
                "product_name": row.product_name,
                "description": row.description,
                "price": float(row.price) if row.price else 0,
                "sizes": row.sizes if row.sizes else [],
                "colors": row.colors if row.colors else [],
                "image_url": row.image_url,
                "status": row.status,
                "admin_comment": row.admin_comment,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None
            })
        
        return jsonify({
            "products": products,
            "count": len(products)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get pending products error: {e}")
        return jsonify({"error": "Failed to retrieve pending products"}), 500


@bp.route('/products/<int:product_id>/approve', methods=['PUT'])
@admin_required
def approve_product(product_id):
    """
    PUT /api/admin/products/<product_id>/approve
    Admin approves a product (status = APPROVED)
    """
    try:
        product = MarketplaceProduct.query.get(product_id)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        if product.status == 'APPROVED':
            return jsonify({"message": "Product already approved"}), 200
        
        product.status = 'APPROVED'
        product.admin_comment = None  # Clear any previous rejection comment
        db.session.commit()
        
        app_logger.info(f"Admin approved product #{product_id}: {product.product_name}")
        
        # Create notification for vendor
        try:
            notification = Notification(
                user_id=product.vendor_id,
                user_type='vendor',
                title='Product Approved',
                message=f'Your product "{product.product_name}" has been approved and is now visible to customers.',
                notification_type='product_approved',
                is_read=False
            )
            db.session.add(notification)
            db.session.commit()
        except Exception as notif_error:
            app_logger.warning(f"Failed to create notification for product approval: {notif_error}")
            db.session.rollback()
        
        return jsonify({
            "message": "Product approved successfully",
            "product": {
                "id": product.id,
                "product_name": product.product_name,
                "status": product.status
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Approve product error: {e}")
        return jsonify({"error": "Failed to approve product"}), 500


@bp.route('/products/<int:product_id>/reject', methods=['PUT'])
@admin_required
def reject_product(product_id):
    """
    PUT /api/admin/products/<product_id>/reject
    Admin rejects a product (status = REJECTED) with optional comment
    """
    try:
        product = MarketplaceProduct.query.get(product_id)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        data = request.get_json() or {}
        admin_comment = data.get('admin_comment', '').strip()
        
        if not admin_comment:
            return jsonify({"error": "admin_comment is required for rejection"}), 400
        
        product.status = 'REJECTED'
        product.admin_comment = admin_comment
        db.session.commit()
        
        app_logger.info(f"Admin rejected product #{product_id}: {product.product_name}. Reason: {admin_comment}")
        
        # Create notification for vendor
        try:
            notification = Notification(
                user_id=product.vendor_id,
                user_type='vendor',
                title='Product Rejected',
                message=f'Your product "{product.product_name}" was rejected. Reason: {admin_comment}',
                notification_type='product_rejected',
                is_read=False
            )
            db.session.add(notification)
            db.session.commit()
        except Exception as notif_error:
            app_logger.warning(f"Failed to create notification for product rejection: {notif_error}")
            db.session.rollback()
        
        return jsonify({
            "message": "Product rejected successfully",
            "product": {
                "id": product.id,
                "product_name": product.product_name,
                "status": product.status,
                "admin_comment": product.admin_comment
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Reject product error: {e}")
        return jsonify({"error": "Failed to reject product"}), 500


# ============================================================================
# Cart Products Approval (Vendor → Admin Approval → Customer Display)
# ============================================================================

@bp.route('/cart-products/pending', methods=['GET'])
@admin_required
def get_pending_cart_products():
    """
    GET /api/admin/cart-products/pending
    Get all cart products with status='pending' for admin review
    """
    try:
        from sqlalchemy import text
        
        # Get vendor information via cross-database join
        # cart_products is in vendor DB, vendors is in vendor DB (same DB, but using cross-schema pattern)
        vendor_db = current_app.config.get('DB_NAME_VENDOR', 'impromptuindian_vendor')
        
        sql = text(f"""
            SELECT 
                cp.id,
                cp.vendor_id,
                cp.product_type_id,
                cp.product_type,
                cp.category,
                cp.product_name,
                cp.description,
                cp.cost_price,
                cp.sizes,
                cp.images,
                cp.status,
                cp.admin_remarks,
                cp.created_at,
                cp.updated_at,
                v.business_name as vendor_name,
                v.username as vendor_username,
                pt.name as product_type_name,
                pt.slug as product_type_slug
            FROM {vendor_db}.cart_products cp
            LEFT JOIN {vendor_db}.vendors v ON cp.vendor_id = v.id
            LEFT JOIN {vendor_db}.product_types pt ON cp.product_type_id = pt.id
            WHERE cp.status = 'pending'
            ORDER BY cp.created_at ASC
        """)
        
        result = db.session.execute(sql)
        products = []
        
        for row in result:
            # Parse JSON strings to arrays (MySQL JSON columns return as strings)
            sizes = row.sizes
            if isinstance(sizes, str):
                try:
                    import json
                    sizes = json.loads(sizes)
                except (json.JSONDecodeError, TypeError):
                    sizes = []
            if not isinstance(sizes, list):
                sizes = []
            
            images = row.images
            if isinstance(images, str):
                try:
                    import json
                    images = json.loads(images)
                except (json.JSONDecodeError, TypeError):
                    images = []
            if not isinstance(images, list):
                images = []
            
            products.append({
                "id": row.id,
                "vendor_id": row.vendor_id,
                "vendor_name": row.vendor_name or f"Vendor #{row.vendor_id}",
                "vendor_username": row.vendor_username,
                "product_type": row.product_type_name or row.product_type or 'Unknown',
                "product_type_slug": row.product_type_slug,
                "category": row.category or 'N/A',
                "product_name": row.product_name,
                "description": row.description,
                "cost_price": float(row.cost_price) if row.cost_price else 0,
                "sizes": sizes,
                "images": images,
                "status": row.status,
                "admin_remarks": row.admin_remarks,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "updated_at": row.updated_at.isoformat() if row.updated_at else None
            })
        
        return jsonify({
            "products": products,
            "count": len(products)
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get pending cart products error: {e}")
        return jsonify({"error": "Failed to retrieve pending cart products"}), 500


@bp.route('/cart-products/<int:product_id>/approve', methods=['POST'])
@admin_required
def approve_cart_product(product_id):
    """
    POST /api/admin/cart-products/<product_id>/approve
    Admin approves a cart product (status = approved)
    """
    try:
        product = CartProduct.query.get(product_id)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        if product.status == 'approved':
            return jsonify({"message": "Product already approved"}), 200
        
        data = request.get_json() or {}
        remarks = data.get('remarks', '')
        
        product.status = 'approved'
        product.admin_remarks = remarks if remarks else None
        db.session.commit()
        
        app_logger.info(f"Admin approved cart product #{product_id}: {product.product_name}")
        
        # Create notification for vendor
        try:
            notification = Notification(
                user_id=product.vendor_id,
                user_type='vendor',
                title='Product Approved',
                message=f'Your product "{product.product_name}" has been approved and is now visible to customers.',
                type='product_approved',
                is_read=False
            )
            db.session.add(notification)
            db.session.commit()
        except Exception as notif_error:
            app_logger.warning(f"Failed to create notification for cart product approval: {notif_error}")
            db.session.rollback()
        
        return jsonify({
            "message": "Product approved successfully",
            "product": {
                "id": product.id,
                "product_name": product.product_name,
                "status": product.status
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Approve cart product error: {e}")
        return jsonify({"error": "Failed to approve product"}), 500


@bp.route('/cart-products/<int:product_id>/reject', methods=['POST'])
@admin_required
def reject_cart_product(product_id):
    """
    POST /api/admin/cart-products/<product_id>/reject
    Admin rejects a cart product (status = rejected) with required remarks
    """
    try:
        product = CartProduct.query.get(product_id)
        if not product:
            return jsonify({"error": "Product not found"}), 404
        
        data = request.get_json() or {}
        admin_remarks = data.get('remarks', '').strip()
        
        if not admin_remarks:
            return jsonify({"error": "remarks are required for rejection"}), 400
        
        product.status = 'rejected'
        product.admin_remarks = admin_remarks
        db.session.commit()
        
        app_logger.info(f"Admin rejected cart product #{product_id}: {product.product_name}. Reason: {admin_remarks}")
        
        # Create notification for vendor
        try:
            notification = Notification(
                user_id=product.vendor_id,
                user_type='vendor',
                title='Product Rejected',
                message=f'Your product "{product.product_name}" was rejected. Reason: {admin_remarks}',
                type='product_rejected',
                is_read=False
            )
            db.session.add(notification)
            db.session.commit()
        except Exception as notif_error:
            app_logger.warning(f"Failed to create notification for cart product rejection: {notif_error}")
            db.session.rollback()
        
        return jsonify({
            "message": "Product rejected successfully",
            "product": {
                "id": product.id,
                "product_name": product.product_name,
                "status": product.status,
                "admin_remarks": product.admin_remarks
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Reject cart product error: {e}")
        return jsonify({"error": "Failed to reject product"}), 500


# ============================================================================
# Support Users Management Routes (Admin Only)
# ============================================================================

@bp.route('/support-users', methods=['POST'])
@admin_required
def create_support_user():
    """
    POST /api/admin/support-users
    Create a new support user (admin only)
    """
    try:
        from werkzeug.security import generate_password_hash
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        phone = data.get('phone', '').strip() if data.get('phone') else None
        password = data.get('password', '').strip()
        role = data.get('role', 'support').strip()
        
        # Validation
        if not name or not email or not password:
            return jsonify({"error": "Name, email, and password are required"}), 400
        
        # Password: min 8 chars, 1 upper, 1 lower, 1 number, 1 special (!@#$%^&*)
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        if not re.search(r'[A-Z]', password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not re.search(r'[a-z]', password):
            return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
        if not re.search(r'\d', password):
            return jsonify({"error": "Password must contain at least one number"}), 400
        if not re.search(r'[!@#$%^&*]', password):
            return jsonify({"error": "Password must contain at least one special character (!@#$%^&*)"}), 400
        
        # Phone validation (Indian: 10 digits, first digit 6/7/8/9, prefixes +91/91/0 allowed)
        if phone:
            digits = re.sub(r'\D', '', phone)
            core = digits
            if len(digits) == 12 and digits.startswith('91'):
                core = digits[2:]
            elif len(digits) == 11 and digits.startswith('0'):
                core = digits[1:]
            elif len(digits) == 10:
                core = digits
            else:
                return jsonify({"error": "Invalid phone number. Use 10 digits starting with 6/7/8/9. Prefixes +91, 91, or 0 allowed."}), 400
            if len(core) != 10 or not re.match(r'^[6789]', core):
                return jsonify({"error": "Invalid phone number. The 10-digit number must start with 6, 7, 8, or 9."}), 400
            phone = core  # Normalize to 10 digits for storage
        
        valid_roles = ['support', 'senior_support', 'manager']
        if role not in valid_roles:
            return jsonify({"error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"}), 400
        
        # Check if email already exists
        existing = SupportUser.query.filter_by(email=email).first()
        if existing:
            return jsonify({
                "error": "Email already exists",
                "message": f"The email address '{email}' is already registered to another support user."
            }), 400
        
        # Check if phone already exists (if provided)
        if phone:
            existing_phone = SupportUser.query.filter_by(phone=phone).first()
            if existing_phone:
                return jsonify({
                    "error": "Phone number already exists",
                    "message": f"The phone number '{phone}' is already registered to another support user."
                }), 400
        
        # Hash password
        hashed_password = generate_password_hash(password)
        
        # Create user
        user = SupportUser(
            name=name,
            email=email,
            phone=phone,
            password_hash=hashed_password,
            role=role,
            is_active=True
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log activity
        log_activity_from_request(
            action=f"Created support user: {name} ({email})",
            action_type="support_user_created",
            entity_type="support_user",
            entity_id=user.id
        )
        
        return jsonify({
            "message": "Support user created successfully",
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "phone": user.phone,
                "role": user.role,
                "is_active": user.is_active
            }
        }), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Create support user error: {e}")
        return jsonify({"error": "Failed to create support user"}), 500


@bp.route('/support-users', methods=['GET'])
@admin_required
def list_support_users():
    """
    GET /api/admin/support-users
    List all support users (admin only)
    """
    try:
        users = SupportUser.query.order_by(SupportUser.created_at.desc()).all()
        
        users_list = [{
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "phone": user.phone,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None
        } for user in users]
        
        return jsonify({"users": users_list}), 200
        
    except Exception as e:
        app_logger.exception(f"List support users error: {e}")
        return jsonify({"error": "Failed to retrieve support users"}), 500


@bp.route('/support-users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def reset_support_user_password(user_id):
    """
    POST /api/admin/support-users/<user_id>/reset-password
    Reset support user password (admin only)
    """
    try:
        from werkzeug.security import generate_password_hash
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body required"}), 400
        
        password = data.get('password', '').strip()
        if not password:
            return jsonify({"error": "Password is required"}), 400
        
        # Password: min 8 chars, 1 upper, 1 lower, 1 number, 1 special (!@#$%^&*)
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        if not re.search(r'[A-Z]', password):
            return jsonify({"error": "Password must contain at least one uppercase letter"}), 400
        if not re.search(r'[a-z]', password):
            return jsonify({"error": "Password must contain at least one lowercase letter"}), 400
        if not re.search(r'\d', password):
            return jsonify({"error": "Password must contain at least one number"}), 400
        if not re.search(r'[!@#$%^&*]', password):
            return jsonify({"error": "Password must contain at least one special character (!@#$%^&*)"}), 400
        
        user = SupportUser.query.get(user_id)
        if not user:
            return jsonify({"error": "Support user not found"}), 404
        
        # Hash and update password
        user.password_hash = generate_password_hash(password)
        db.session.commit()
        
        # Log activity
        log_activity_from_request(
            action=f"Reset password for support user: {user.name} ({user.email})",
            action_type="support_user_password_reset",
            entity_type="support_user",
            entity_id=user.id
        )
        
        return jsonify({"message": "Password reset successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Reset support user password error: {e}")
        return jsonify({"error": "Failed to reset password"}), 500


@bp.route('/support-users/<int:user_id>/toggle-status', methods=['POST'])
@admin_required
def toggle_support_user_status(user_id):
    """
    POST /api/admin/support-users/<user_id>/toggle-status
    Activate or deactivate support user (admin only)
    """
    try:
        data = request.get_json()
        is_active = data.get('is_active', True) if data else True
        
        user = SupportUser.query.get(user_id)
        if not user:
            return jsonify({"error": "Support user not found"}), 404
        
        user.is_active = bool(is_active)
        db.session.commit()
        
        # Log activity
        action = "activated" if is_active else "deactivated"
        log_activity_from_request(
            action=f"{action.capitalize()} support user: {user.name} ({user.email})",
            action_type="support_user_status_changed",
            entity_type="support_user",
            entity_id=user.id
        )
        
        return jsonify({
            "message": f"User {action} successfully",
            "user": {
                "id": user.id,
                "name": user.name,
                "email": user.email,
                "is_active": user.is_active
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Toggle support user status error: {e}")
        return jsonify({"error": "Failed to update user status"}), 500


@bp.route('/support-users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_support_user(user_id):
    """
    DELETE /api/admin/support-users/<user_id>
    Delete support user (admin only)
    """
    try:
        user = SupportUser.query.get(user_id)
        if not user:
            return jsonify({"error": "Support user not found"}), 404
        
        user_name = user.name
        user_email = user.email
        
        db.session.delete(user)
        db.session.commit()
        
        # Log activity
        log_activity_from_request(
            action=f"Deleted support user: {user_name} ({user_email})",
            action_type="support_user_deleted",
            entity_type="support_user",
            entity_id=user_id
        )
        
        return jsonify({"message": "Support user deleted successfully"}), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Delete support user error: {e}")
        return jsonify({"error": "Failed to delete support user"}), 500


# ============================================================================
# Support Overview & Settings Routes (Admin Only)
# ============================================================================

@bp.route('/support/overview', methods=['GET'])
@admin_required
def get_support_overview():
    """
    GET /api/admin/support/overview
    Get support overview statistics (admin only)
    """
    try:
        from datetime import datetime, timedelta
        from sqlalchemy import func
        
        # Safe query with error handling
        try:
            # Total open tickets
            total_open = SupportTicket.query.filter(
                SupportTicket.status.in_(['open', 'in_progress', 'assigned'])
            ).count()
        except Exception as e:
            app_logger.warning(f"Error querying open tickets: {e}")
            total_open = 0
        
        try:
            # Escalated tickets
            escalated_count = SupportTicket.query.filter(
                SupportTicket.status == 'escalated'
            ).count()
        except Exception as e:
            app_logger.warning(f"Error querying escalated tickets: {e}")
            escalated_count = 0
        
        try:
            # SLA breach count (tickets past their SLA deadline)
            now = datetime.utcnow()
            sla_breach_count = SupportTicket.query.filter(
                SupportTicket.status.in_(['open', 'in_progress', 'assigned']),
                SupportTicket.sla_deadline.isnot(None),
                SupportTicket.sla_deadline < now
            ).count()
        except Exception as e:
            app_logger.warning(f"Error querying SLA breaches: {e}")
            sla_breach_count = 0
        
        try:
            # Average resolution time (in hours)
            resolved_tickets = SupportTicket.query.filter(
                SupportTicket.status.in_(['resolved', 'closed']),
                SupportTicket.resolved_at.isnot(None)
            ).all()
            
            avg_resolution_hours = 0
            if resolved_tickets:
                total_hours = sum([
                    (ticket.resolved_at - ticket.created_at).total_seconds() / 3600
                    for ticket in resolved_tickets
                    if ticket.resolved_at and ticket.created_at
                ])
                avg_resolution_hours = round(total_hours / len(resolved_tickets), 1) if resolved_tickets else 0
        except Exception as e:
            app_logger.warning(f"Error calculating avg resolution time: {e}")
            avg_resolution_hours = 0
        
        # Agent workload
        try:
            active_users = SupportUser.query.filter_by(is_active=True).all()
            agent_workload = []
            agent_performance = []
            
            for user in active_users:
                try:
                    active_tickets = SupportTicket.query.filter(
                        SupportTicket.assigned_to == user.id,
                        SupportTicket.status.in_(['open', 'in_progress', 'assigned'])
                    ).count()
                except Exception:
                    active_tickets = 0
                
                try:
                    resolved_today = SupportTicket.query.filter(
                        SupportTicket.assigned_to == user.id,
                        SupportTicket.status.in_(['resolved', 'closed']),
                        func.date(SupportTicket.resolved_at) == func.curdate()
                    ).count()
                except Exception:
                    resolved_today = 0
                
                agent_workload.append({
                    "id": user.id,
                    "name": user.name,
                    "role": user.role,
                    "active_tickets": active_tickets
                })
                
                agent_performance.append({
                    "id": user.id,
                    "name": user.name,
                    "role": user.role,
                    "active_tickets": active_tickets,
                    "resolved_today": resolved_today,
                    "avg_response_time": "N/A",  # Would calculate from ticket history
                    "is_active": user.is_active
                })
        except Exception as e:
            app_logger.warning(f"Error querying agent workload: {e}")
            agent_workload = []
            agent_performance = []
        
        # Recent escalations
        try:
            recent_escalations = SupportTicket.query.filter(
                SupportTicket.status == 'escalated'
            ).order_by(SupportTicket.created_at.desc()).limit(10).all()
            
            escalations_list = [{
                "id": ticket.id,
                "user_type": ticket.user_type,
                "subject": ticket.subject,
                "escalated_to": "Senior Support",  # Would be calculated from escalation rules
                "hours_since_created": int((datetime.utcnow() - ticket.created_at).total_seconds() / 3600) if ticket.created_at else 0,
                "sla_status": "breached" if ticket.sla_deadline and ticket.sla_deadline < datetime.utcnow() else "OK"
            } for ticket in recent_escalations]
        except Exception as e:
            app_logger.warning(f"Error querying escalations: {e}")
            escalations_list = []
        
        # Customer satisfaction (placeholder - would come from ratings)
        satisfaction_percent = 85  # Would calculate from ticket ratings
        
        return jsonify({
            "total_open": total_open,
            "escalated_count": escalated_count,
            "sla_breach_count": sla_breach_count,
            "avg_resolution_hours": avg_resolution_hours,
            "agent_workload": agent_workload,
            "agent_performance": agent_performance,
            "recent_escalations": escalations_list,
            "satisfaction_percent": satisfaction_percent
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get support overview error: {e}")
        return jsonify({"error": "Failed to retrieve overview"}), 500


# Categories Routes
@bp.route('/support/categories', methods=['GET'])
@admin_required
def list_support_categories():
    """List all ticket categories"""
    try:
        categories = SupportTicketCategory.query.order_by(SupportTicketCategory.name).all()
        return jsonify({
            "categories": [{
                "id": cat.id,
                "name": cat.name,
                "description": cat.description,
                "is_active": cat.is_active
            } for cat in categories]
        }), 200
    except Exception as e:
        app_logger.exception(f"List categories error: {e}")
        return jsonify({"error": "Failed to retrieve categories"}), 500


@bp.route('/support/categories', methods=['POST'])
@admin_required
def create_support_category():
    """Create a new ticket category"""
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        
        if not name:
            return jsonify({"error": "Category name is required"}), 400
        
        # Check if category exists
        existing = SupportTicketCategory.query.filter_by(name=name).first()
        if existing:
            return jsonify({"error": "Category already exists"}), 400
        
        category = SupportTicketCategory(name=name, description=description, is_active=True)
        db.session.add(category)
        db.session.commit()
        
        log_activity_from_request(
            action=f"Created support category: {name}",
            action_type="support_category_created",
            entity_type="support_category",
            entity_id=category.id
        )
        
        return jsonify({
            "message": "Category created successfully",
            "category": {
                "id": category.id,
                "name": category.name,
                "description": category.description,
                "is_active": category.is_active
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Create category error: {e}")
        return jsonify({"error": "Failed to create category"}), 500


@bp.route('/support/categories/<int:category_id>', methods=['GET'])
@admin_required
def get_support_category(category_id):
    """Get a specific category"""
    try:
        category = SupportTicketCategory.query.get(category_id)
        if not category:
            return jsonify({"error": "Category not found"}), 404
        
        return jsonify({
            "category": {
                "id": category.id,
                "name": category.name,
                "description": category.description,
                "is_active": category.is_active
            }
        }), 200
    except Exception as e:
        app_logger.exception(f"Get category error: {e}")
        return jsonify({"error": "Failed to retrieve category"}), 500


@bp.route('/support/categories/<int:category_id>', methods=['PUT'])
@admin_required
def update_support_category(category_id):
    """Update a category"""
    try:
        category = SupportTicketCategory.query.get(category_id)
        if not category:
            return jsonify({"error": "Category not found"}), 404
        
        data = request.get_json()
        if 'name' in data:
            category.name = data['name'].strip()
        if 'description' in data:
            category.description = data.get('description', '').strip()
        
        db.session.commit()
        
        return jsonify({"message": "Category updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update category error: {e}")
        return jsonify({"error": "Failed to update category"}), 500


@bp.route('/support/categories/<int:category_id>/toggle', methods=['POST'])
@admin_required
def toggle_support_category(category_id):
    """Toggle category active status"""
    try:
        category = SupportTicketCategory.query.get(category_id)
        if not category:
            return jsonify({"error": "Category not found"}), 404
        
        data = request.get_json()
        category.is_active = bool(data.get('is_active', not category.is_active))
        db.session.commit()
        
        return jsonify({"message": "Category status updated"}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Toggle category error: {e}")
        return jsonify({"error": "Failed to update category"}), 500


# Priority Rules Routes
@bp.route('/support/priority-rules', methods=['GET'])
@admin_required
def list_priority_rules():
    """List all priority rules"""
    try:
        rules = SupportPriorityRule.query.order_by(SupportPriorityRule.priority_level).all()
        return jsonify({
            "rules": [{
                "id": rule.id,
                "priority_level": rule.priority_level,
                "sla_hours": rule.sla_hours,
                "description": rule.description,
                "is_active": rule.is_active
            } for rule in rules]
        }), 200
    except Exception as e:
        app_logger.exception(f"List priority rules error: {e}")
        return jsonify({"error": "Failed to retrieve priority rules"}), 500


@bp.route('/support/priority-rules', methods=['POST'])
@admin_required
def create_priority_rule():
    """Create a new priority rule"""
    try:
        data = request.get_json()
        priority_level = data.get('priority_level', '').strip().lower()
        sla_hours = data.get('sla_hours')
        description = data.get('description', '').strip()
        
        if not priority_level or sla_hours is None:
            return jsonify({"error": "Priority level and SLA hours are required"}), 400
        
        valid_levels = ['low', 'medium', 'high', 'critical']
        if priority_level not in valid_levels:
            return jsonify({"error": f"Invalid priority level. Must be one of: {', '.join(valid_levels)}"}), 400
        
        # Check if rule exists
        existing = SupportPriorityRule.query.filter_by(priority_level=priority_level).first()
        if existing:
            return jsonify({"error": "Priority rule already exists"}), 400
        
        rule = SupportPriorityRule(
            priority_level=priority_level,
            sla_hours=int(sla_hours),
            description=description,
            is_active=True
        )
        db.session.add(rule)
        db.session.commit()
        
        return jsonify({
            "message": "Priority rule created successfully",
            "rule": {
                "id": rule.id,
                "priority_level": rule.priority_level,
                "sla_hours": rule.sla_hours,
                "description": rule.description,
                "is_active": rule.is_active
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Create priority rule error: {e}")
        return jsonify({"error": "Failed to create priority rule"}), 500


@bp.route('/support/priority-rules/<int:rule_id>', methods=['GET'])
@admin_required
def get_priority_rule(rule_id):
    """Get a specific priority rule"""
    try:
        rule = SupportPriorityRule.query.get(rule_id)
        if not rule:
            return jsonify({"error": "Priority rule not found"}), 404
        
        return jsonify({
            "rule": {
                "id": rule.id,
                "priority_level": rule.priority_level,
                "sla_hours": rule.sla_hours,
                "description": rule.description,
                "is_active": rule.is_active
            }
        }), 200
    except Exception as e:
        app_logger.exception(f"Get priority rule error: {e}")
        return jsonify({"error": "Failed to retrieve priority rule"}), 500


@bp.route('/support/priority-rules/<int:rule_id>', methods=['PUT'])
@admin_required
def update_priority_rule(rule_id):
    """Update a priority rule"""
    try:
        rule = SupportPriorityRule.query.get(rule_id)
        if not rule:
            return jsonify({"error": "Priority rule not found"}), 404
        
        data = request.get_json()
        if 'priority_level' in data:
            rule.priority_level = data['priority_level'].strip().lower()
        if 'sla_hours' in data:
            rule.sla_hours = int(data['sla_hours'])
        if 'description' in data:
            rule.description = data.get('description', '').strip()
        
        db.session.commit()
        
        return jsonify({"message": "Priority rule updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update priority rule error: {e}")
        return jsonify({"error": "Failed to update priority rule"}), 500


@bp.route('/support/priority-rules/<int:rule_id>/toggle', methods=['POST'])
@admin_required
def toggle_priority_rule(rule_id):
    """Toggle priority rule active status"""
    try:
        rule = SupportPriorityRule.query.get(rule_id)
        if not rule:
            return jsonify({"error": "Priority rule not found"}), 404
        
        data = request.get_json()
        rule.is_active = bool(data.get('is_active', not rule.is_active))
        db.session.commit()
        
        return jsonify({"message": "Priority rule status updated"}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Toggle priority rule error: {e}")
        return jsonify({"error": "Failed to update priority rule"}), 500


# Escalation Rules Routes
@bp.route('/support/escalation-rules', methods=['GET'])
@admin_required
def list_escalation_rules():
    """List all escalation rules"""
    try:
        rules = SupportEscalationRule.query.order_by(SupportEscalationRule.hours_threshold).all()
        return jsonify({
            "rules": [{
                "id": rule.id,
                "hours_threshold": rule.hours_threshold,
                "escalate_to_role": rule.escalate_to_role,
                "notify_admin": rule.notify_admin,
                "is_active": rule.is_active
            } for rule in rules]
        }), 200
    except Exception as e:
        app_logger.exception(f"List escalation rules error: {e}")
        return jsonify({"error": "Failed to retrieve escalation rules"}), 500


@bp.route('/support/escalation-rules', methods=['POST'])
@admin_required
def create_escalation_rule():
    """Create a new escalation rule"""
    try:
        data = request.get_json()
        hours_threshold = data.get('hours_threshold')
        escalate_to_role = data.get('escalate_to_role', '').strip()
        notify_admin = bool(data.get('notify_admin', False))
        
        if hours_threshold is None or not escalate_to_role:
            return jsonify({"error": "Hours threshold and escalate to role are required"}), 400
        
        valid_roles = ['senior_support', 'manager', 'admin']
        if escalate_to_role not in valid_roles:
            return jsonify({"error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"}), 400
        
        rule = SupportEscalationRule(
            hours_threshold=int(hours_threshold),
            escalate_to_role=escalate_to_role,
            notify_admin=notify_admin,
            is_active=True
        )
        db.session.add(rule)
        db.session.commit()
        
        return jsonify({
            "message": "Escalation rule created successfully",
            "rule": {
                "id": rule.id,
                "hours_threshold": rule.hours_threshold,
                "escalate_to_role": rule.escalate_to_role,
                "notify_admin": rule.notify_admin,
                "is_active": rule.is_active
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Create escalation rule error: {e}")
        return jsonify({"error": "Failed to create escalation rule"}), 500


@bp.route('/support/escalation-rules/<int:rule_id>', methods=['GET'])
@admin_required
def get_escalation_rule(rule_id):
    """Get a specific escalation rule"""
    try:
        rule = SupportEscalationRule.query.get(rule_id)
        if not rule:
            return jsonify({"error": "Escalation rule not found"}), 404
        
        return jsonify({
            "rule": {
                "id": rule.id,
                "hours_threshold": rule.hours_threshold,
                "escalate_to_role": rule.escalate_to_role,
                "notify_admin": rule.notify_admin,
                "is_active": rule.is_active
            }
        }), 200
    except Exception as e:
        app_logger.exception(f"Get escalation rule error: {e}")
        return jsonify({"error": "Failed to retrieve escalation rule"}), 500


@bp.route('/support/escalation-rules/<int:rule_id>', methods=['PUT'])
@admin_required
def update_escalation_rule(rule_id):
    """Update an escalation rule"""
    try:
        rule = SupportEscalationRule.query.get(rule_id)
        if not rule:
            return jsonify({"error": "Escalation rule not found"}), 404
        
        data = request.get_json()
        if 'hours_threshold' in data:
            rule.hours_threshold = int(data['hours_threshold'])
        if 'escalate_to_role' in data:
            rule.escalate_to_role = data['escalate_to_role'].strip()
        if 'notify_admin' in data:
            rule.notify_admin = bool(data['notify_admin'])
        
        db.session.commit()
        
        return jsonify({"message": "Escalation rule updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update escalation rule error: {e}")
        return jsonify({"error": "Failed to update escalation rule"}), 500


@bp.route('/support/escalation-rules/<int:rule_id>/toggle', methods=['POST'])
@admin_required
def toggle_escalation_rule(rule_id):
    """Toggle escalation rule active status"""
    try:
        rule = SupportEscalationRule.query.get(rule_id)
        if not rule:
            return jsonify({"error": "Escalation rule not found"}), 404
        
        data = request.get_json()
        rule.is_active = bool(data.get('is_active', not rule.is_active))
        db.session.commit()
        
        return jsonify({"message": "Escalation rule status updated"}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Toggle escalation rule error: {e}")
        return jsonify({"error": "Failed to update escalation rule"}), 500


# Auto Assignment Routes
@bp.route('/support/auto-assignment', methods=['GET'])
@admin_required
def get_auto_assignment():
    """Get auto assignment configuration"""
    try:
        methods = SupportAutoAssignment.query.all()
        
        # Default methods if none exist
        default_methods = ['round_robin', 'workload', 'category', 'manual']
        method_map = {m.assignment_method: m for m in methods}
        
        result = []
        for method_name in default_methods:
            if method_name in method_map:
                result.append({
                    "assignment_method": method_map[method_name].assignment_method,
                    "is_enabled": method_map[method_name].is_enabled,
                    "config_json": method_map[method_name].config_json
                })
            else:
                result.append({
                    "assignment_method": method_name,
                    "is_enabled": False,
                    "config_json": None
                })
        
        return jsonify({"methods": result}), 200
    except Exception as e:
        app_logger.exception(f"Get auto assignment error: {e}")
        return jsonify({"error": "Failed to retrieve auto assignment"}), 500


@bp.route('/support/auto-assignment', methods=['PUT'])
@admin_required
def update_auto_assignment():
    """Update auto assignment configuration"""
    try:
        data = request.get_json()
        assignment_method = data.get('assignment_method', '').strip()
        is_enabled = bool(data.get('is_enabled', False))
        config_json = data.get('config_json')
        
        if not assignment_method:
            return jsonify({"error": "Assignment method is required"}), 400
        
        # Find or create
        assignment = SupportAutoAssignment.query.filter_by(assignment_method=assignment_method).first()
        if not assignment:
            assignment = SupportAutoAssignment(assignment_method=assignment_method)
            db.session.add(assignment)
        
        assignment.is_enabled = is_enabled
        if config_json:
            assignment.config_json = config_json
        
        db.session.commit()
        
        return jsonify({"message": "Auto assignment updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update auto assignment error: {e}")
        return jsonify({"error": "Failed to update auto assignment"}), 500
