"""
Orders Routes Blueprint
Handles order creation, management, and tracking endpoints
"""
from flask import Blueprint, request, jsonify
from datetime import datetime

from app_pkg.models import db, Order, OrderStatusHistory, Customer, Vendor, VendorOrderAssignment, Payment, CustomerPayment
from app_pkg.auth import login_required, admin_required, role_required
from app_pkg.validation import validate_request_data, OrderSchema
from app_pkg.schemas import order_schema, orders_schema
from app_pkg.logger_config import app_logger

# Create blueprint
bp = Blueprint('orders', __name__, url_prefix='/orders')


@bp.route('/', methods=['GET'])
@login_required
def get_orders():
    """
    GET /api/orders/
    Get all orders (filtered by user role)
    """
    try:
        user_id = request.user_id
        role = request.role
        
        if role == 'admin':
            # Admin sees all orders
            orders = Order.query.all()
        elif role == 'customer':
            # Customer sees only their orders
            orders = Order.query.filter_by(customer_id=user_id).all()
        elif role == 'vendor':
            # Vendor sees only their assigned orders
            vendor_orders = Order.query.filter_by(selected_vendor_id=user_id).all()
            orders = vendor_orders
        else:
            return jsonify({"error": "Unauthorized"}), 403
        
        # Use schema for serialization
        if role == 'admin':
            return orders_schema.jsonify(orders), 200
        else:
            # For customer/vendor, return simplified format
            orders_data = [order_schema.dump(order) for order in orders]
            return jsonify({
                "orders": orders_data,
                "count": len(orders_data)
            }), 200
        
    except Exception as e:
        app_logger.exception(f"Get orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/<int:order_id>', methods=['GET'])
@login_required
def get_order(order_id):
    """
    GET /api/orders/<order_id>
    Get specific order details
    """
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        # Check authorization
        role = request.role
        user_id = request.user_id
        
        if role == 'customer' and order.customer_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        # Use schema for detailed order information
        return order_schema.jsonify(order), 200
        
    except Exception as e:
        app_logger.exception(f"Get order error: {e}")
        return jsonify({"error": "Failed to retrieve order"}), 500


@bp.route('/', methods=['POST'])
@login_required
@role_required(['customer'])
def create_order():
    """
    POST /api/orders/
    Create a new order
    """
    try:
        # SECURITY: Get customer_id from JWT token, never from frontend
        customer_id = getattr(request, 'user_id', None)
        if not customer_id:
            return jsonify({"error": "Authentication required"}), 401
        
        # Validate input data
        data = request.get_json() or {}
        validated_data, errors = validate_request_data(OrderSchema, data)
        
        if errors:
            return jsonify({"error": "Validation failed", "details": errors}), 400
        
        # Extract validated fields
        product_type = validated_data['product_type']
        category = validated_data['category']
        neck_type = validated_data.get('neck_type')
        color = validated_data.get('color')
        fabric = validated_data.get('fabric')
        print_type = validated_data.get('print_type')
        quantity = validated_data['quantity']
        delivery_date = validated_data.get('delivery_date')
        price_per_piece_offered = validated_data['price_per_piece']
        
        # Address fields
        address_line1 = validated_data['address_line1']
        address_line2 = validated_data.get('address_line2')
        city = validated_data['city']
        state = validated_data['state']
        pincode = validated_data['pincode']
        country = validated_data.get('country', 'India')
        
        # Payment details
        transaction_id = validated_data.get('transaction_id')
        sample_cost = validated_data.get('sample_cost', 0.0)
        sample_size = validated_data.get('sample_size')
        
        # SECURITY: Always fetch final_price from database - NEVER trust frontend price
        from app_pkg.models import ProductCatalog
        from decimal import Decimal
        
        # Normalize and trim all values
        product_type = product_type.strip() if product_type and isinstance(product_type, str) else product_type
        category = category.strip() if category and isinstance(category, str) else category
        if neck_type:
            neck_type = neck_type.strip() if isinstance(neck_type, str) else neck_type
        # Normalize: empty/null becomes "None" (string) to match DB
        neck_type = neck_type if neck_type else "None"
        
        if fabric:
            fabric = fabric.strip() if isinstance(fabric, str) else fabric
        
        if sample_size:
            sample_size = sample_size.strip() if isinstance(sample_size, str) else sample_size
        else:
            return jsonify({"error": "Sample size is required"}), 400
        
        # Debug logging
        app_logger.info(
            f"Order creation - Fetching catalog price: product_type={product_type}, category={category}, "
            f"neck_type={neck_type}, fabric={fabric}, size={sample_size}"
        )
        
        # Build query with EXACT match
        # DB stores "None" as string for neck_type, not SQL NULL
        # If fabric is not provided, don't filter by fabric (match any fabric for that product)
        query = ProductCatalog.query.filter_by(
            product_type=product_type,
            category=category,
            neck_type=neck_type,  # "None" string if not provided
            size=sample_size
        )
        
        # Only filter by fabric if it's provided
        if fabric:
            query = query.filter_by(fabric=fabric)
        # If fabric not provided, don't filter - match any fabric
        
        product = query.first()
        
        # Debug logging for query result
        if product:
            app_logger.info(
                f"Product found for order: id={product.id}, final_price={product.final_price}, "
                f"average_price={product.average_price}"
            )
        else:
            app_logger.warning(
                f"No product found for order: product_type={product_type}, category={category}, "
                f"neck_type={neck_type}, fabric={fabric}, size={sample_size}"
            )
        
        # SECURITY: Reject if product not found or no final_price
        if not product:
            app_logger.warning(
                f"Product not found in catalog: product_type={product_type}, "
                f"category={category}, neck_type={neck_type}, fabric={fabric}, size={sample_size}"
            )
            return jsonify({
                "error": "Invalid product configuration. Product not found in catalog.",
                "details": {
                    "product_type": product_type,
                    "category": category,
                    "neck_type": neck_type or None,
                    "fabric": fabric or None,
                    "size": sample_size
                }
            }), 400
        
        if not product.final_price:
            app_logger.warning(f"Product found but no final_price: product_id={product.id}")
            return jsonify({"error": "Product price not available. Please contact support."}), 400
        
        final_price_from_catalog = float(product.final_price)
        
        # SECURITY: Validate payment amount matches catalog price
        # Only validate if transaction_id exists (payment was made)
        if transaction_id:
            # Use Decimal for precise money comparison
            try:
                catalog_price_decimal = Decimal(str(final_price_from_catalog))
                sample_cost_decimal = Decimal(str(sample_cost))
                
                if sample_cost_decimal != catalog_price_decimal:
                    app_logger.warning(
                        f"Price mismatch detected for customer {customer_id}: "
                        f"paid={sample_cost}, expected={final_price_from_catalog}, transaction_id={transaction_id}"
                    )
                    return jsonify({
                        "error": "Price mismatch detected. Payment amount does not match product price.",
                        "expected_price": final_price_from_catalog,
                        "paid_amount": float(sample_cost)
                    }), 400
            except (ValueError, TypeError) as e:
                app_logger.error(f"Invalid price format: {e}")
                return jsonify({"error": "Invalid price format"}), 400
        
        # Use catalog price as the authoritative quotation price
        quotation_price = final_price_from_catalog
        
        # Determine initial status
        initial_status = 'awaiting_sample_payment'
        if transaction_id:
            initial_status = 'sample_payment_received'

        new_order = Order(
            customer_id=customer_id,
            product_type=product_type,
            category=category,
            neck_type=neck_type,
            color=color,
            fabric=fabric,
            print_type=print_type,
            quantity=quantity,
            price_per_piece_offered=price_per_piece_offered,
            quotation_price_per_piece=quotation_price,  # Set from catalog final_price
            quotation_total_price=quotation_price * quantity if quotation_price else None,
            delivery_date=delivery_date.isoformat() if isinstance(delivery_date, datetime) else delivery_date,
            address_line1=address_line1,
            address_line2=address_line2,
            city=city,
            state=state,
            pincode=pincode,
            country=country,
            status=initial_status,
            sample_cost=sample_cost,
            sample_size=sample_size
        )
        
        db.session.add(new_order)
        db.session.flush()  # Flush to get new_order.id

        # Record Payment if transaction_id exists
        if transaction_id:
            try:
                payment_method = data.get('payment_method', 'card')
                payment_details_str = data.get('payment_details', '')
                
                new_payment = Payment(
                    transaction_id=transaction_id,
                    order_id=new_order.id,
                    customer_id=customer_id,
                    payment_type='sample',
                    payment_method=payment_method,
                    amount=float(sample_cost) if sample_cost else 0.0,
                    currency='INR',
                    status='success',
                    payment_details=payment_details_str,
                    processed_at=datetime.utcnow()
                )
                db.session.add(new_payment)
            except Exception:
                # Don't fail the order creation if payment record fails
                pass

        db.session.commit()
        
        return order_schema.jsonify(new_order), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Create order error: {e}")
        return jsonify({"error": "Failed to create order"}), 500


@bp.route('/<int:order_id>/status', methods=['PUT'])
@login_required
@role_required(['admin', 'vendor'])
def update_order_status(order_id):
    """
    PUT /api/orders/<order_id>/status
    Update order status
    """
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if not new_status:
            return jsonify({"error": "Status is required"}), 400
        
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        # Check authorization for vendor
        role = request.role
        user_id = request.user_id
        
        if role == 'vendor' and order.selected_vendor_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        # Update order status
        old_status = order.status
        order.status = new_status
        
        # Log status change
        status_history = OrderStatusHistory(
            order_id=order_id,
            status=new_status,
            status_label=new_status.replace('_', ' ').title(),
            changed_by_type=request.role,
            changed_by_id=request.user_id,
            notes=data.get('remarks', '')
        )
        db.session.add(status_history)
        db.session.commit()
        
        return jsonify({
            "message": "Order status updated successfully",
            "order_id": order_id,
            "status": new_status
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Update order status error: {e}")
        return jsonify({"error": "Failed to update order status"}), 500


@bp.route('/customer/<int:customer_id>', methods=['GET'])
@login_required
def get_customer_orders(customer_id):
    """
    GET /api/orders/customer/<customer_id>
    Get orders for a specific customer
    """
    try:
        role = request.role
        user_id = request.user_id
        
        # Authorization check
        if role == 'customer' and customer_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        orders = Order.query.filter_by(customer_id=customer_id).order_by(Order.created_at.desc()).all()
        return orders_schema.jsonify(orders), 200
        
    except Exception as e:
        app_logger.exception(f"Get customer orders error: {e}")
        return jsonify({"error": "Failed to retrieve orders"}), 500


@bp.route('/<int:order_id>/request-bulk', methods=['POST'])
@login_required
@role_required(['customer'])
def request_bulk_order(order_id):
    """
    POST /api/orders/<order_id>/request-bulk
    Request bulk order from a sample order
    """
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        if order.customer_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        data = request.get_json()
        quantity = data.get('quantity')
        
        if not quantity or quantity < 1:
            return jsonify({"error": "Invalid quantity"}), 400
        
        # Create new bulk order based on sample
        new_order = Order(
            customer_id=order.customer_id,
            product_type=order.product_type,
            category=order.category,
            neck_type=order.neck_type,
            color=order.color,
            fabric=order.fabric,
            print_type=order.print_type,
            quantity=quantity,
            price_per_piece_offered=order.price_per_piece_offered,
            delivery_date=order.delivery_date,
            address_line1=order.address_line1,
            address_line2=order.address_line2,
            city=order.city,
            state=order.state,
            pincode=order.pincode,
            country=order.country,
            status='pending_admin_review',
            sample_size=order.sample_size
        )
        
        db.session.add(new_order)
        db.session.commit()
        
        return order_schema.jsonify(new_order), 201
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Request bulk order error: {e}")
        return jsonify({"error": "Failed to create bulk order"}), 500


@bp.route('/<int:order_id>/assign-vendor', methods=['POST'])
@login_required
@role_required(['admin'])
def assign_vendor_to_order(order_id):
    """
    POST /api/orders/<order_id>/assign-vendor
    Admin assigns vendor to order
    """
    try:
        data = request.get_json()
        vendor_id = data.get('vendor_id')
        quotation_price_per_piece = data.get('quotation_price_per_piece')
        sample_cost = data.get('sample_cost', 500.0)
        
        if not vendor_id or not quotation_price_per_piece:
            return jsonify({"error": "vendor_id and quotation_price_per_piece are required"}), 400
        
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        vendor = Vendor.query.get(vendor_id)
        if not vendor:
            return jsonify({"error": "Vendor not found"}), 404
        
        order.selected_vendor_id = vendor_id
        order.quotation_price_per_piece = float(quotation_price_per_piece)
        order.quotation_total_price = float(quotation_price_per_piece) * order.quantity
        order.sample_cost = float(sample_cost)
        order.status = 'quotation_sent_to_customer'
        
        # Create vendor order assignment
        assignment = VendorOrderAssignment(
            order_id=order_id,
            vendor_id=vendor_id,
            status='pending',
            assigned_at=datetime.utcnow()
        )
        db.session.add(assignment)
        
        # Notify vendor
        from app.models import Notification
        notif = Notification(
            user_id=vendor_id,
            user_type='vendor',
            title='New Order Assigned',
            message=f'You have been assigned Order ORD-{order_id}. Please review and accept.',
            type='order'
        )
        db.session.add(notif)
        
        db.session.commit()
        
        return order_schema.jsonify(order), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Assign vendor error: {e}")
        return jsonify({"error": "Failed to assign vendor"}), 500


@bp.route('/<int:order_id>/quotation-response', methods=['POST'])
@login_required
@role_required(['customer'])
def customer_quotation_response(order_id):
    """
    POST /api/orders/<order_id>/quotation-response
    Customer accepts or rejects quotation
    """
    try:
        data = request.get_json()
        action = data.get('action')  # 'accept' or 'reject'
        
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        if order.customer_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        if action == 'reject':
            order.status = 'quotation_rejected_by_customer'
            db.session.commit()
            return jsonify({"message": "Quotation rejected"}), 200
        
        elif action == 'accept':
            # Create payment record for sample
            sample_payment = CustomerPayment(
                order_id=order_id,
                payer_type='customer',
                payer_id=order.customer_id,
                receiver_type='admin',
                receiver_id=1,
                amount=order.sample_cost,
                payment_type='sample_payment',
                status='completed'
            )
            
            db.session.add(sample_payment)
            order.status = 'sample_requested'
            db.session.commit()
            
            return jsonify({"message": "Sample payment successful, sample requested"}), 200
        else:
            return jsonify({"error": "Invalid action"}), 400
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Quotation response error: {e}")
        return jsonify({"error": "Failed to process quotation response"}), 500


@bp.route('/<int:order_id>/sample-response', methods=['POST'])
@login_required
@role_required(['customer'])
def customer_sample_response(order_id):
    """
    POST /api/orders/<order_id>/sample-response
    Customer approves or rejects sample
    """
    try:
        data = request.get_json()
        action = data.get('action')  # 'approve' or 'reject'
        
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        if order.customer_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        if action == 'reject':
            order.status = 'sample_rejected'
            db.session.commit()
            return jsonify({"message": "Sample rejected"}), 200
        
        elif action == 'approve':
            order.status = 'awaiting_advance_payment'
            db.session.commit()
            return jsonify({
                "message": "Sample approved, awaiting 50% advance payment",
                "advance_amount": order.quotation_total_price * 0.50
            }), 200
        else:
            return jsonify({"error": "Invalid action"}), 400
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Sample response error: {e}")
        return jsonify({"error": "Failed to process sample response"}), 500


@bp.route('/<int:order_id>/advance-payment', methods=['POST'])
@login_required
@role_required(['customer'])
def process_advance_payment(order_id):
    """
    POST /api/orders/<order_id>/advance-payment
    Process 50% advance payment
    """
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        if order.customer_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        advance_amount = order.quotation_total_price * 0.50
        vendor_initial_payout = order.quotation_total_price * 0.25
        
        # Record customer's 50% advance payment to admin
        advance_payment = CustomerPayment(
            order_id=order_id,
            payer_type='customer',
            payer_id=order.customer_id,
            receiver_type='admin',
            receiver_id=1,
            amount=advance_amount,
            payment_type='advance_50',
            status='completed'
        )
        
        # Record admin's 25% payout to vendor
        vendor_payment = CustomerPayment(
            order_id=order_id,
            payer_type='admin',
            payer_id=1,
            receiver_type='vendor',
            receiver_id=order.selected_vendor_id,
            amount=vendor_initial_payout,
            payment_type='vendor_initial_payout',
            status='completed'
        )
        
        order.vendor_initial_payout = vendor_initial_payout
        order.status = 'in_production'
        
        db.session.add(advance_payment)
        db.session.add(vendor_payment)
        db.session.commit()
        
        return jsonify({
            "message": "Advance payment processed successfully",
            "customer_paid": advance_amount,
            "vendor_received": vendor_initial_payout,
            "admin_holds": advance_amount - vendor_initial_payout
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Advance payment error: {e}")
        return jsonify({"error": "Failed to process advance payment"}), 500


@bp.route('/<int:order_id>/feedback', methods=['POST'])
@login_required
@role_required(['customer'])
def submit_order_feedback(order_id):
    """
    POST /api/orders/<order_id>/feedback
    Submit order feedback after delivery
    """
    try:
        data = request.get_json()
        
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        if order.customer_id != request.user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        order.rating = data.get('rating')
        order.delivery_on_time = data.get('delivery_on_time', True)
        order.delivery_delay_days = data.get('delivery_delay_days', 0)
        order.defect_reported = data.get('defect_reported', False)
        order.feedback_comment = data.get('feedback_comment', '')
        
        # Calculate penalties
        total_price = order.quotation_total_price
        penalty = 0.0
        
        # Late delivery penalty
        if order.delivery_delay_days > 0:
            if order.delivery_delay_days <= 3:
                penalty += total_price * 0.05
            elif order.delivery_delay_days <= 7:
                penalty += total_price * 0.10
            else:
                penalty += total_price * 0.20
        
        # Rating penalty
        if order.rating == 3:
            penalty += total_price * 0.05
        elif order.rating == 2:
            penalty += total_price * 0.10
        elif order.rating == 1:
            penalty += total_price * 0.20
        
        # Defect penalty
        if order.defect_reported:
            penalty += total_price * 0.15
        
        # Calculate final vendor payout
        vendor_remaining_base = total_price * 0.25
        vendor_final_payout = max(0, vendor_remaining_base - penalty)
        
        order.penalty_amount_total = penalty
        order.vendor_final_payout = vendor_final_payout
        order.status = 'completed_with_penalty' if penalty > 0 else 'completed'
        
        # Create final vendor payment record
        final_payment = CustomerPayment(
            order_id=order_id,
            payer_type='admin',
            payer_id=1,
            receiver_type='vendor',
            receiver_id=order.selected_vendor_id,
            amount=vendor_final_payout,
            payment_type='vendor_final_payout',
            status='completed'
        )
        
        db.session.add(final_payment)
        db.session.commit()
        
        return jsonify({
            "message": "Feedback submitted successfully",
            "penalty_applied": penalty,
            "vendor_final_payout": vendor_final_payout,
            "order_status": order.status
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app_logger.exception(f"Submit feedback error: {e}")
        return jsonify({"error": "Failed to submit feedback"}), 500


@bp.route('/<int:order_id>/payments', methods=['GET'])
@login_required
def get_order_payments(order_id):
    """
    GET /api/orders/<order_id>/payments
    Get all payments for an order
    """
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        # Check authorization
        role = request.role
        user_id = request.user_id
        
        if role == 'customer' and order.customer_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        elif role == 'vendor' and order.selected_vendor_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        admin_payments = Payment.query.filter_by(order_id=order_id).all()
        customer_payments = CustomerPayment.query.filter_by(order_id=order_id).all()
        
        result = []
        for p in admin_payments:
            result.append({
                'id': p.id,
                'type': 'transaction',
                'transaction_id': p.transaction_id,
                'payment_type': p.payment_type,
                'payment_method': p.payment_method,
                'amount': p.amount,
                'currency': p.currency,
                'status': p.status,
                'created_at': p.created_at.isoformat() if p.created_at else None
            })
        
        for p in customer_payments:
            result.append({
                'id': p.id,
                'type': 'internal',
                'payer_type': p.payer_type,
                'payer_id': p.payer_id,
                'receiver_type': p.receiver_type,
                'receiver_id': p.receiver_id,
                'payment_type': p.payment_type,
                'amount': p.amount,
                'status': p.status,
                'timestamp': p.timestamp.isoformat() if p.timestamp else None
            })
        
        return jsonify(result), 200
        
    except Exception as e:
        app_logger.exception(f"Get order payments error: {e}")
        return jsonify({"error": "Failed to retrieve payments"}), 500


@bp.route('/<int:order_id>/tracking', methods=['GET'])
@login_required
def get_order_tracking(order_id):
    """
    GET /api/orders/<order_id>/tracking
    Get complete order tracking history
    """
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({"error": "Order not found"}), 404
        
        # Check authorization
        role = request.role
        user_id = request.user_id
        
        if role == 'customer' and order.customer_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        elif role == 'vendor' and order.selected_vendor_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        
        # Get all status history records
        history = OrderStatusHistory.query.filter_by(order_id=order_id).order_by(OrderStatusHistory.created_at.asc()).all()
        
        # Define tracking stages
        TRACKING_STAGES = [
            {'id': 'pending_admin_review', 'label': 'Order Received', 'icon': 'clipboard-check'},
            {'id': 'quotation_sent_to_customer', 'label': 'Quotation Sent', 'icon': 'file-text'},
            {'id': 'sample_requested', 'label': 'Sample Stage', 'icon': 'package'},
            {'id': 'awaiting_advance_payment', 'label': 'Payment Received', 'icon': 'credit-card'},
            {'id': 'assigned', 'label': 'Vendor Assigned', 'icon': 'user-check'},
            {'id': 'accepted_by_vendor', 'label': 'Accepted by Vendor', 'icon': 'check-circle'},
            {'id': 'material_prep', 'label': 'Material Preparation', 'icon': 'scissors'},
            {'id': 'printing', 'label': 'Printing', 'icon': 'printer'},
            {'id': 'printing_completed', 'label': 'Printing Completed', 'icon': 'check-square'},
            {'id': 'quality_check', 'label': 'Quality Check', 'icon': 'search'},
            {'id': 'packed_ready', 'label': 'Packed & Ready', 'icon': 'package'},
            {'id': 'reached_vendor', 'label': 'Rider Arrived', 'icon': 'map-pin'},
            {'id': 'picked_up', 'label': 'Picked Up', 'icon': 'package-check'},
            {'id': 'out_for_delivery', 'label': 'Out for Delivery', 'icon': 'truck'},
            {'id': 'delivered', 'label': 'Delivered', 'icon': 'home'}
        ]
        
        # Build history timeline
        history_timeline = [{
            'status': h.status,
            'status_label': h.status_label,
            'changed_by_type': h.changed_by_type,
            'changed_by_id': h.changed_by_id,
            'notes': h.notes,
            'timestamp': h.created_at.isoformat() if h.created_at else None
        } for h in history]
        
        # Calculate current stage index
        current_status = order.status
        current_index = -1
        for i, stage in enumerate(TRACKING_STAGES):
            if stage['id'] == current_status:
                current_index = i
                break
        
        return jsonify({
            'order_id': order_id,
            'current_status': current_status,
            'current_stage_index': current_index,
            'stages': TRACKING_STAGES,
            'history': history_timeline
        }), 200
        
    except Exception as e:
        app_logger.exception(f"Get order tracking error: {e}")
        return jsonify({"error": "Failed to retrieve tracking information"}), 500
