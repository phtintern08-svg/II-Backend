"""
Helper utility functions for backend_api
"""
import math
from datetime import datetime
from app.models import db, Rider, DeliveryLog, Vendor, Order, VendorQuotationSubmission, ProductCatalog, Notification
from app.logger_config import app_logger
from app.error_handler import get_error_message


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
