"""
Routes package - contains all Flask blueprints
"""
from .auth_routes import bp as auth_bp
from .customer_routes import bp as customer_bp
from .support_routes import bp as support_bp
from .orders_routes import bp as orders_bp
from .vendor_routes import bp as vendor_bp
from .rider_routes import bp as rider_bp
from .admin_routes import bp as admin_bp
from .config_routes import bp as config_bp
from . import health

__all__ = ['auth_bp', 'customer_bp', 'support_bp', 'orders_bp', 'vendor_bp', 'rider_bp', 'admin_bp', 'config_bp', 'health']