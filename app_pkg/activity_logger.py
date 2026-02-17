"""
Activity Logger Utility
Helper function to log user actions across the platform
"""
from flask import request
from datetime import datetime
from app_pkg.models import db, ActivityLog, Admin, Customer, Vendor, Rider, Support
from app_pkg.logger_config import app_logger


def log_activity(
    user_id,
    user_type,
    action,
    action_type,
    entity_type=None,
    entity_id=None,
    details=None,
    ip_address=None
):
    """
    Log an activity performed by any user type
    
    Args:
        user_id: ID of the user performing the action
        user_type: Type of user ('admin', 'customer', 'vendor', 'rider', 'support')
        action: Human-readable action description
        action_type: Type of action ('order_creation', 'order_status_change', 'payment', etc.)
        entity_type: Type of entity the action was performed on ('order', 'payment', etc.)
        entity_id: ID of the entity
        details: Additional context or notes
        ip_address: IP address of the user (optional, will try to get from request if not provided)
    
    Returns:
        ActivityLog: The created activity log entry
    """
    try:
        # Get user name based on user type
        user_name = "Unknown"
        if user_type == 'admin':
            admin = Admin.query.get(user_id)
            user_name = admin.username if admin else f"Admin #{user_id}"
        elif user_type == 'customer':
            customer = Customer.query.get(user_id)
            user_name = customer.username if customer else (customer.email if customer else f"Customer #{user_id}")
        elif user_type == 'vendor':
            vendor = Vendor.query.get(user_id)
            user_name = vendor.business_name if vendor and vendor.business_name else (vendor.username if vendor else f"Vendor #{user_id}")
        elif user_type == 'rider':
            rider = Rider.query.get(user_id)
            user_name = rider.name if rider else f"Rider #{user_id}"
        elif user_type == 'support':
            support = Support.query.get(user_id)
            user_name = support.username if support else f"Support #{user_id}"
        else:
            user_name = f"{user_type} #{user_id}"
        
        # Get IP address from request if not provided
        # Check for proxy headers (X-Forwarded-For, X-Real-IP) for accurate client IP
        if not ip_address and request:
            # Try to get real IP from proxy headers first
            if request.headers.get('X-Forwarded-For'):
                # X-Forwarded-For can contain multiple IPs, take the first one
                ip_address = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            elif request.headers.get('X-Real-IP'):
                ip_address = request.headers.get('X-Real-IP').strip()
            else:
                # Fallback to remote_addr
                ip_address = request.remote_addr
        
        # Create activity log entry
        activity_log = ActivityLog(
            user_id=user_id,
            user_type=user_type,
            user_name=user_name,
            action=action,
            action_type=action_type,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
            ip_address=ip_address,
            timestamp=datetime.utcnow()
        )
        
        db.session.add(activity_log)
        db.session.commit()
        
        return activity_log
        
    except Exception as e:
        # Log error but don't fail the main operation
        app_logger.exception(f"Failed to log activity: {e}")
        db.session.rollback()
        return None


def log_activity_from_request(
    action,
    action_type,
    entity_type=None,
    entity_id=None,
    details=None
):
    """
    Convenience function to log activity using user info from Flask request
    Requires request to have user_id and role attributes (set by @login_required decorator)
    
    Args:
        action: Human-readable action description
        action_type: Type of action
        entity_type: Type of entity
        entity_id: ID of the entity
        details: Additional context
    
    Returns:
        ActivityLog: The created activity log entry or None
    """
    if not hasattr(request, 'user_id') or not hasattr(request, 'role'):
        app_logger.warning("Cannot log activity: request missing user_id or role")
        return None
    
    return log_activity(
        user_id=request.user_id,
        user_type=request.role,
        action=action,
        action_type=action_type,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details
    )
