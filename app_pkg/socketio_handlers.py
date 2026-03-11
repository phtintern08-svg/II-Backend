"""
Socket.IO Event Handlers for Real-Time Support Chat
====================================================
Handles WebSocket connections for customer-agent chat
"""

from flask_socketio import emit, join_room, leave_room
from flask import request, current_app
from datetime import datetime
from app_pkg.models import db, SupportTicket, Thread, Comment
from app_pkg.logger_config import app_logger
from app_pkg.intelligent_support import EscalationEngine


def get_status_based_ai_response(issue_key, order_status, order_id=None):
    """
    Get AI response for status-based support options.
    Returns a response string based on the issue_key and order_status.
    """
    # Map issue keys to AI responses
    response_map = {
        # pending_admin_review
        'when_confirmed': 'Your order is currently under review by our team. We typically confirm orders within 24-48 hours. You will receive a confirmation email once your order is approved.',
        'change_address': 'I can help you change your delivery address. Please provide the new address details, and I\'ll update it for you.',
        # vendor_assigned
        'who_vendor': f'Your order #{order_id} has been assigned to a verified vendor. The vendor details will be shared with you once production begins.',
        'when_production': 'Production typically starts within 1-2 business days after vendor assignment. You will receive updates as your order progresses through each stage.',
        'change_order_details': 'I understand you want to modify your order. Let me check if changes are still possible at this stage. Some modifications may not be allowed once production has started.',
        # in_production
        'estimated_completion': 'Based on your order details, production typically takes 5-7 business days. You will receive regular updates as your order moves through each production stage.',
        'preview_print': 'I can request a preview from the vendor once printing begins. Would you like me to ask for a preview image?',
        'expedite_order': 'I understand you need this order expedited. Let me check with the vendor if rush production is possible. There may be additional charges for expedited orders.',
        # material_prep / printing
        'printing_duration': 'Printing typically takes 2-3 business days depending on the order size and complexity. Your order is currently in the printing stage and will move to quality check once complete.',
        'design_mistake': 'I\'m sorry to hear about the design issue. Let me connect you with our support team immediately to address this. This is time-sensitive, so we\'ll prioritize your request.',
        'why_printing_stage': 'Your order is in the printing stage, which is a normal part of the production process. This stage ensures high-quality output. It typically takes 2-3 business days.',
        # printing_completed
        'next_step': 'Great! Your order has completed printing. The next step is quality check, where our team will inspect the items for any defects before packing.',
        'quality_check_status': 'Your order is currently in the quality check stage. This typically takes 1 business day. Once approved, it will be packed and ready for dispatch.',
        'when_packed': 'Your order will be packed after passing quality check, which typically happens within 1 business day. Once packed, it will be marked as "Ready for Dispatch".',
        # quality_check
        'if_fails_check': 'If an item fails quality check, it will be sent back for rework at no extra cost to you. We ensure all items meet our quality standards before dispatch.',
        'inspection_duration': 'Quality check typically takes 1 business day. Our team thoroughly inspects each item for defects, color accuracy, and overall quality.',
        'order_okay': 'Your order is currently being inspected. Once the quality check is complete, you will receive an update. We ensure all items meet our standards before dispatch.',
        # packed_ready
        'when_dispatched': 'Your order is packed and ready for dispatch. A delivery partner will be assigned shortly, and you will receive tracking details once dispatch begins.',
        'pickup_myself': 'I can arrange for self-pickup. Please provide your preferred pickup location and time, and I\'ll coordinate with the vendor.',
        'package_photo': 'I\'ll request a photo of the packaged order from the vendor. This may take a few minutes. Would you like me to proceed?',
        # rider_assigned
        'who_delivery_partner': 'A delivery partner has been assigned to your order. You will receive their contact details and tracking information shortly.',
        'rider_contact': 'I\'ll share the delivery partner\'s contact details with you. They will contact you before delivery to confirm the delivery address and time.',
        'expected_delivery_time': 'Based on your location and the delivery partner\'s route, your order should be delivered within 24-48 hours. You will receive real-time tracking updates.',
        # reached_vendor
        'rider_picked_up': 'The delivery partner has reached the vendor location. They will pick up your order shortly. You will receive an update once pickup is confirmed.',
        'rider_not_moving': 'I understand your concern. Let me check the delivery partner\'s current status and location. Sometimes there may be delays at the pickup location.',
        'cancel_delivery': 'I can help you cancel the delivery. However, once the order is picked up, cancellation may not be possible. Let me check the current status.',
        # picked_up / out_for_delivery
        'track_order': f'Your order #{order_id} is on the way! You can track it in real-time. The delivery partner will contact you before delivery.',
        'delivery_delayed': 'I\'m sorry for the delay. Let me check the current status and estimated delivery time. I\'ll update you shortly with the latest information.',
        'share_location': 'I\'ll share the live tracking link with you. You can track your order in real-time and see the delivery partner\'s current location.',
        # delivered
        'not_received': 'I\'m sorry to hear you haven\'t received your order. Let me verify the delivery status and contact the delivery partner to confirm the delivery address.',
        'damaged_missing': 'I\'m very sorry about this. Please provide details about the damaged or missing items, and I\'ll immediately escalate this to our quality team for resolution.',
        'rate_experience': 'Thank you for your order! Your feedback helps us improve. You can rate your experience in your order history page.',
        # completed
        'download_invoice': f'You can download your invoice from the order details page for order #{order_id}. I can also email it to you if needed.',
        'reorder_item': 'I can help you reorder this item. Would you like me to create a new order with the same specifications?',
        'quality_complaint': 'I\'m sorry to hear about the quality issue. Please provide details about the problem, and I\'ll escalate this to our quality assurance team for immediate resolution.',
        # Generic fallbacks
        'general_issue': 'I\'m here to help! Please describe your issue in detail, and I\'ll assist you right away.',
        'track_order': f'Your order #{order_id} status is being tracked. You can view real-time updates in your order history.',
        'cancel_order': 'I can help you cancel your order. Please note that cancellation policies may vary based on the current order status. Let me check the details for you.'
    }
    
    # Return specific response or generic fallback
    return response_map.get(issue_key, 'Thank you for contacting support. I\'m here to help you with your order. Please provide more details about your concern.')


def get_status_based_support_options(order_status):
    """
    Get status-based support options (Flipkart-style buttons) based on order status.
    Returns a list of option dictionaries with 'key' and 'title'.
    """
    status_options_map = {
        'pending_admin_review': [
            {'key': 'when_confirmed', 'title': 'When will my order be confirmed?'},
            {'key': 'change_address', 'title': 'I want to change my delivery address.'},
            {'key': 'cancel_order', 'title': 'Cancel my order.'}
        ],
        'vendor_assigned': [
            {'key': 'who_vendor', 'title': 'Who is the vendor?'},
            {'key': 'when_production', 'title': 'When will production start?'},
            {'key': 'change_order_details', 'title': 'Can I still change my order details?'}
        ],
        'in_production': [
            {'key': 'estimated_completion', 'title': 'What is the estimated completion date?'},
            {'key': 'preview_print', 'title': 'Can I see a preview of the print?'},
            {'key': 'expedite_order', 'title': 'I need to expedite this order.'}
        ],
        'material_prep': [
            {'key': 'printing_duration', 'title': 'How much longer will printing take?'},
            {'key': 'design_mistake', 'title': 'I noticed a mistake in my design.'},
            {'key': 'why_printing_stage', 'title': 'Why is it still in the printing stage?'}
        ],
        'printing': [
            {'key': 'printing_duration', 'title': 'How much longer will printing take?'},
            {'key': 'design_mistake', 'title': 'I noticed a mistake in my design.'},
            {'key': 'why_printing_stage', 'title': 'Why is it still in the printing stage?'}
        ],
        'printing_completed': [
            {'key': 'next_step', 'title': 'What is the next step?'},
            {'key': 'quality_check_status', 'title': 'Has it passed quality check yet?'},
            {'key': 'when_packed', 'title': 'When will it be packed?'}
        ],
        'quality_check': [
            {'key': 'if_fails_check', 'title': 'What happens if it fails the check?'},
            {'key': 'inspection_duration', 'title': 'How long does the inspection take?'},
            {'key': 'order_okay', 'title': 'Is my order okay?'}
        ],
        'packed_ready': [
            {'key': 'when_dispatched', 'title': 'When will it be dispatched?'},
            {'key': 'pickup_myself', 'title': 'I want to pick it up myself.'},
            {'key': 'package_photo', 'title': 'Send me a photo of the package.'}
        ],
        'rider_assigned': [
            {'key': 'who_delivery_partner', 'title': 'Who is my delivery partner?'},
            {'key': 'rider_contact', 'title': "Get rider's contact details."},
            {'key': 'expected_delivery_time', 'title': 'What is the expected delivery time?'}
        ],
        'reached_vendor': [
            {'key': 'rider_picked_up', 'title': 'Has the rider picked up the order?'},
            {'key': 'rider_not_moving', 'title': "The rider hasn't moved for a long time."},
            {'key': 'cancel_delivery', 'title': 'Cancel delivery.'}
        ],
        'picked_up': [
            {'key': 'track_order', 'title': 'Track my order'},
            {'key': 'delivery_delayed', 'title': 'Delivery delayed'},
            {'key': 'share_location', 'title': 'Share live location link.'}
        ],
        'out_for_delivery': [
            {'key': 'track_order', 'title': 'Track my order'},
            {'key': 'delivery_delayed', 'title': 'Delivery delayed'},
            {'key': 'share_location', 'title': 'Share live location link.'}
        ],
        'delivered': [
            {'key': 'not_received', 'title': "I haven't received the items."},
            {'key': 'damaged_missing', 'title': 'Items are damaged/missing.'},
            {'key': 'rate_experience', 'title': 'Rate my experience.'}
        ],
        'completed': [
            {'key': 'download_invoice', 'title': 'Download Invoice.'},
            {'key': 'reorder_item', 'title': 'Re-order this item.'},
            {'key': 'quality_complaint', 'title': 'Submit a complaint about the quality.'}
        ],
        'completed_with_penalty': [
            {'key': 'download_invoice', 'title': 'Download Invoice.'},
            {'key': 'reorder_item', 'title': 'Re-order this item.'},
            {'key': 'quality_complaint', 'title': 'Submit a complaint about the quality.'}
        ]
    }
    
    # Return options for the specific status, or fallback to generic options
    return status_options_map.get(order_status, [
        {'key': 'general_issue', 'title': 'General Issue'},
        {'key': 'track_order', 'title': 'Track Order'},
        {'key': 'cancel_order', 'title': 'Cancel Order'}
    ])


def register_handlers(socketio):
    """Register all Socket.IO event handlers"""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection with detailed logging"""
        try:
            from flask import request as flask_request
            import time
            
            # Get client information
            client_ip = flask_request.remote_addr or 'Unknown'
            user_agent = flask_request.headers.get('User-Agent', 'Unknown')
            session_id = request.sid
            timestamp = datetime.utcnow().isoformat()
            
            # Log connection details
            app_logger.info(
                f"🔌 WEBSOCKET CONNECTED | "
                f"Session: {session_id} | "
                f"IP: {client_ip} | "
                f"Time: {timestamp} | "
                f"User-Agent: {user_agent[:50]}"
            )
            
            # Store connection time for duration calculation
            if not hasattr(request, 'connect_time'):
                request.connect_time = time.time()
            
            # Emit connection confirmation to client
            emit('system_message', {
                'msg': '✅ Connected to support chat',
                'status': 'connected',
                'session_id': session_id,
                'timestamp': timestamp
            })
            
            # Log to console for debugging
            print(f"[WEBSOCKET] ✅ Connection established: {session_id} from {client_ip}")
            
        except Exception as e:
            app_logger.exception(f"❌ Error in handle_connect: {e}")
            emit('error', {'msg': 'Connection error occurred'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection with detailed logging"""
        try:
            from flask import request as flask_request
            import time
            
            # Get client information
            client_ip = flask_request.remote_addr or 'Unknown'
            session_id = request.sid
            timestamp = datetime.utcnow().isoformat()
            
            # Calculate connection duration if available
            duration = None
            if hasattr(request, 'connect_time'):
                duration = round(time.time() - request.connect_time, 2)
                duration_str = f"{duration}s"
            else:
                duration_str = "Unknown"
            
            # Log disconnection details
            app_logger.info(
                f"🔌 WEBSOCKET DISCONNECTED | "
                f"Session: {session_id} | "
                f"IP: {client_ip} | "
                f"Duration: {duration_str} | "
                f"Time: {timestamp}"
            )
            
            # Log to console for debugging
            print(f"[WEBSOCKET] ❌ Connection closed: {session_id} from {client_ip} (Duration: {duration_str})")
            
        except Exception as e:
            app_logger.exception(f"❌ Error in handle_disconnect: {e}")
    
    @socketio.on('connection_status')
    def handle_connection_status():
        """Handle client requesting connection status"""
        try:
            session_id = request.sid
            timestamp = datetime.utcnow().isoformat()
            
            app_logger.info(f"📊 Connection status requested: {session_id}")
            
            emit('connection_status', {
                'status': 'connected',
                'session_id': session_id,
                'timestamp': timestamp,
                'server_time': timestamp
            })
            
        except Exception as e:
            app_logger.exception(f"❌ Error in handle_connection_status: {e}")
            emit('error', {'msg': 'Failed to get connection status'})
    
    @socketio.on_error_default
    def default_error_handler(e):
        """Handle Socket.IO errors"""
        try:
            session_id = request.sid if hasattr(request, 'sid') else 'Unknown'
            error_msg = str(e)
            
            app_logger.error(
                f"❌ WEBSOCKET ERROR | "
                f"Session: {session_id} | "
                f"Error: {error_msg} | "
                f"Time: {datetime.utcnow().isoformat()}"
            )
            
            print(f"[WEBSOCKET] ❌ Error for session {session_id}: {error_msg}")
            
            emit('error', {
                'msg': 'An error occurred',
                'error': error_msg
            })
            
        except Exception as e:
            app_logger.exception(f"❌ Error in default_error_handler: {e}")
    
    @socketio.on('join_ticket')
    def handle_join_ticket(data):
        """
        Join a ticket room
        Data: {ticket_id: int/str, user_type: 'customer'|'agent', user_id: int}
        """
        try:
            ticket_id = data.get('ticket_id')
            user_type = data.get('user_type', 'customer')
            user_id = data.get('user_id')
            
            if not ticket_id:
                emit('error', {'msg': 'Ticket ID required'})
                return
            
            # Find ticket (handle both ticket_number and id)
            try:
                ticket_id_int = int(ticket_id)
            except (ValueError, TypeError):
                ticket_id_int = None
            
            if ticket_id_int:
                ticket = SupportTicket.query.filter(
                    (SupportTicket.ticket_number == str(ticket_id)) |
                    (SupportTicket.id == ticket_id_int)
                ).first()
            else:
                ticket = SupportTicket.query.filter(
                    SupportTicket.ticket_number == str(ticket_id)
                ).first()
            
            if not ticket:
                emit('error', {'msg': 'Ticket not found'})
                return
            
            # Verify user has access to this ticket
            if user_type == 'customer' and ticket.user_id != user_id:
                emit('error', {'msg': 'Unauthorized access'})
                return
            
            # Join room
            room = f"ticket_{ticket.id}"
            join_room(room)
            
            app_logger.info(f"User {user_id} ({user_type}) joined ticket room {room}")
            
            # Send system message
            emit('system_message', {
                'msg': f'Connected to ticket {ticket.ticket_number or ticket.id}'
            }, room=room)
            
            # Send SLA timer if available
            if hasattr(ticket, 'sla_due_at') and ticket.sla_due_at:
                emit('sla_timer', {
                    'sla_due_at': ticket.sla_due_at.isoformat(),
                    'ticket_id': ticket.ticket_number or str(ticket.id)
                }, room=room)
            
            # Notify others in room that user joined
            emit('user_joined', {
                'user_type': user_type,
                'user_id': user_id,
                'ticket_id': ticket.ticket_number or str(ticket.id)
            }, room=room, include_self=False)
            
        except Exception as e:
            app_logger.exception(f"Error joining ticket room: {e}")
            emit('error', {'msg': 'Failed to join ticket room'})
    
    @socketio.on('leave_ticket')
    def handle_leave_ticket(data):
        """Leave a ticket room"""
        try:
            ticket_id = data.get('ticket_id')
            if ticket_id:
                room = f"ticket_{ticket_id}"
                leave_room(room)
                app_logger.info(f"User left ticket room {room}")
        except Exception as e:
            app_logger.exception(f"Error leaving ticket room: {e}")
    
    @socketio.on('send_message')
    def handle_send_message(data):
        """
        Handle message sending
        Data: {
            ticket_id: int/str,
            message: str,
            sender: 'customer'|'agent',
            sender_id: int,
            sender_name: str (optional)
        }
        """
        try:
            ticket_id = data.get('ticket_id')
            message = data.get('message', '').strip()
            sender = data.get('sender', 'customer')
            sender_id = data.get('sender_id')
            sender_name = data.get('sender_name', sender.title())
            
            if not message or not ticket_id:
                emit('error', {'msg': 'Message and ticket ID required'})
                return
            
            # Find ticket
            try:
                ticket_id_int = int(ticket_id)
            except (ValueError, TypeError):
                ticket_id_int = None
            
            if ticket_id_int:
                ticket = SupportTicket.query.filter(
                    (SupportTicket.ticket_number == str(ticket_id)) |
                    (SupportTicket.id == ticket_id_int)
                ).first()
            else:
                ticket = SupportTicket.query.filter(
                    SupportTicket.ticket_number == str(ticket_id)
                ).first()
            
            if not ticket:
                emit('error', {'msg': 'Ticket not found'})
                return
            
            # Verify sender has access
            if sender == 'customer' and ticket.user_id != sender_id:
                emit('error', {'msg': 'Unauthorized'})
                return
            
            # Store message in database
            try:
                thread = Thread(
                    title=ticket.subject,
                    content=message,
                    user_id=sender_id,
                    ticket_id=ticket.id
                )
                db.session.add(thread)
                
                # Update ticket timestamps
                ticket.updated_at = datetime.utcnow()
                
                # Set first_response_at if this is first agent response
                if sender == 'agent' and not hasattr(ticket, 'first_response_at') or not ticket.first_response_at:
                    try:
                        ticket.first_response_at = datetime.utcnow()
                    except AttributeError:
                        pass
                
                db.session.commit()
                message_id = thread.id
            except Exception as e:
                app_logger.exception(f"Error saving message: {e}")
                db.session.rollback()
                message_id = None
            
            # Broadcast message to room
            room = f"ticket_{ticket.id}"
            message_data = {
                'message_id': message_id,
                'ticket_id': ticket.ticket_number or str(ticket.id),  # Display ID
                'ticket_id_raw': ticket.id,  # ✅ Numeric ID for room matching
                'message': message, 
                'sender': sender,
                'sender_id': sender_id,
                'sender_name': sender_name,
                'sender_type': sender,  # ✅ For appendMessage compatibility
                'timestamp': datetime.utcnow().isoformat(),
                'created_at': datetime.utcnow().isoformat()  # ✅ For appendMessage compatibility
            }
            
            emit('receive_message', message_data, room=room)
            
            app_logger.info(f"Message sent in ticket {ticket.id} by {sender} {sender_id}")
            
        except Exception as e:
            app_logger.exception(f"Error sending message: {e}")
            emit('error', {'msg': 'Failed to send message'})
    
    @socketio.on('typing')
    def handle_typing(data):
        """
        Handle typing indicator
        Data: {ticket_id: int/str, user_type: str, user_id: int}
        """
        try:
            ticket_id = data.get('ticket_id')
            user_type = data.get('user_type', 'customer')
            user_id = data.get('user_id')
            
            if not ticket_id:
                return
            
            # Find ticket
            try:
                ticket_id_int = int(ticket_id)
            except (ValueError, TypeError):
                ticket_id_int = None
            
            if ticket_id_int:
                ticket = SupportTicket.query.filter(
                    (SupportTicket.ticket_number == str(ticket_id)) |
                    (SupportTicket.id == ticket_id_int)
                ).first()
            else:
                ticket = SupportTicket.query.filter(
                    SupportTicket.ticket_number == str(ticket_id)
                ).first()
            
            if not ticket:
                return
            
            room = f"ticket_{ticket.id}"
            
            # Broadcast typing indicator (exclude sender)
            emit('show_typing', {
                'user_type': user_type,
                'user_id': user_id
            }, room=room, include_self=False)
            
        except Exception as e:
            app_logger.exception(f"Error handling typing: {e}")
    
    @socketio.on('stop_typing')
    def handle_stop_typing(data):
        """Handle stop typing"""
        try:
            ticket_id = data.get('ticket_id')
            if not ticket_id:
                return
            
            try:
                ticket_id_int = int(ticket_id)
            except (ValueError, TypeError):
                ticket_id_int = None
            
            if ticket_id_int:
                ticket = SupportTicket.query.filter(
                    (SupportTicket.ticket_number == str(ticket_id)) |
                    (SupportTicket.id == ticket_id_int)
                ).first()
            else:
                ticket = SupportTicket.query.filter(
                    SupportTicket.ticket_number == str(ticket_id)
                ).first()
            
            if not ticket:
                return
            
            room = f"ticket_{ticket.id}"
            emit('hide_typing', {}, room=room, include_self=False)
            
        except Exception as e:
            app_logger.exception(f"Error handling stop typing: {e}")
    
    @socketio.on('request_sla_timer')
    def handle_request_sla_timer(data):
        """Send SLA timer to client"""
        try:
            ticket_id = data.get('ticket_id')
            if not ticket_id:
                return
            
            try:
                ticket_id_int = int(ticket_id)
            except (ValueError, TypeError):
                ticket_id_int = None
            
            if ticket_id_int:
                ticket = SupportTicket.query.filter(
                    (SupportTicket.ticket_number == str(ticket_id)) |
                    (SupportTicket.id == ticket_id_int)
                ).first()
            else:
                ticket = SupportTicket.query.filter(
                    SupportTicket.ticket_number == str(ticket_id)
                ).first()
            
            if ticket and hasattr(ticket, 'sla_due_at') and ticket.sla_due_at:
                emit('sla_timer', {
                    'sla_due_at': ticket.sla_due_at.isoformat(),
                    'ticket_id': ticket.ticket_number or str(ticket.id)
                })
                
        except Exception as e:
            app_logger.exception(f"Error sending SLA timer: {e}")
    
    @socketio.on('start_support')
    def handle_start_support(data):
        """
        Flipkart-style guided support flow
        Data: {order_id: int, customer_id: int}
        """
        try:
            order_id = data.get('order_id')
            customer_id = data.get('customer_id')
            
            # If customer_id not provided, try to get from request context
            if not customer_id:
                # Try to get from JWT token or session
                try:
                    from app_pkg.auth import verify_token
                    token = request.headers.get('Authorization', '').replace('Bearer ', '')
                    if token:
                        payload = verify_token(token)
                        customer_id = payload.get('user_id')
                except:
                    pass
            
            app_logger.info(f"✅ START SUPPORT - Order: {order_id}, Customer: {customer_id}")
            
            if not customer_id:
                emit('error', {'msg': 'Customer ID required. Please login again.'})
                return
            
            if not order_id:
                emit('error', {'msg': 'Order ID required'})
                return
            
            # ✅ CRITICAL: Wrap ALL database work in the application context
            # This is essential for standalone server thread stability
            from flask import current_app
            with current_app.app_context():
                from app_pkg.models import SupportTicket, Order, db
                from app_pkg.intelligent_support import AutoAssignment
                from datetime import datetime, timedelta
                from sqlalchemy import text
                
                app_logger.info(f"🔍 Processing support for Order {order_id}")
                
                # ✅ Use session.get for better stability in standalone mode
                try:
                    order = db.session.get(Order, order_id)
                except Exception as db_error:
                    app_logger.exception(f"Database error getting order {order_id}: {db_error}")
                    emit('error', {'msg': 'Database connection error. Please try again.'})
                    return
                
                if not order:
                    app_logger.warning(f"Order {order_id} not found in database")
                    emit('error', {'msg': 'Order not found'})
                    return
                
                app_logger.info(f"✅ Order {order_id} found, status: {order.status}")
                
                order_status = order.status or 'pending'
                vendor_id = getattr(order, 'selected_vendor_id', None)
                rider_id = getattr(order, 'rider_id', None)
                
                # Get available flows for this order status (from admin database)
                # ⭐ Enterprise-safe: Never crash if table missing
                flows = []
                try:
                    flows_query = text("""
                        SELECT issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected
                        FROM impromptuindian_admin.support_order_flows
                        WHERE order_status = :status
                        ORDER BY id ASC
                    """)
                    flows = db.session.execute(flows_query, {'status': order_status}).fetchall()
                except Exception as e:
                    current_app.logger.error(f"Support flow query failed (table may not exist): {e}")
                    # Continue with empty flows - fallback options will be shown
                    flows = []
                
                # Create ticket
                subject = f'Support Request - Order #{order_id}'
                new_ticket = SupportTicket(
                    ticket_number=None,
                    user_id=customer_id,
                    user_type='customer',
                    subject=subject,
                    description=f"Guided support initiated for Order #{order_id} (Status: {order_status})",
                    status='open',
                    priority='medium'
                )
                
                # Set order context
                try:
                    new_ticket.order_id = order_id
                except AttributeError:
                    pass
                
                if vendor_id:
                    try:
                        new_ticket.vendor_id = vendor_id
                    except AttributeError:
                        pass
                
                if rider_id:
                    try:
                        new_ticket.rider_id = rider_id
                    except AttributeError:
                        pass
                
                # Generate ticket number
                year = datetime.utcnow().year
                ticket_count = SupportTicket.query.filter(
                    db.func.extract('year', SupportTicket.created_at) == year
                ).count() + 1
                new_ticket.ticket_number = f"TKT-{year}-{str(ticket_count).zfill(5)}"
                
                # Set SLA deadline (10 minutes for first response)
                try:
                    new_ticket.sla_due_at = datetime.utcnow() + timedelta(minutes=10)
                except AttributeError:
                    pass
                
                db.session.add(new_ticket)
                db.session.flush()
                ticket_id = new_ticket.id
                db.session.commit()
                
                # Join ticket room
                room = f"ticket_{ticket_id}"
                join_room(room)
                
                app_logger.info(f"✅ USER JOINED {room}")
                
                # Send AI message with order status
                status_display = order_status.replace('_', ' ').title()
                ai_message = (
                    f"🤖 Your order #{order_id} is currently **{status_display}**.\n\n"
                    "How can I help you today?"
                )
                
                emit('ai_message', {
                    'text': ai_message,
                    'sender_type': 'ai',  # ✅ Add this for support.js compatibility
                    'ticket_id': new_ticket.ticket_number or str(ticket_id),
                    'ticket_id_raw': ticket_id,  # ✅ Add numeric ID for matching
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Send issue options (Flipkart-style buttons)
                # Priority: Database flows > Status-based options > Generic fallback
                if flows:
                    # Use database-defined flows if available
                    options = [{
                        'key': flow.issue_key,
                        'title': flow.issue_title
                    } for flow in flows]
                    app_logger.info(f"✅ Using database flows for status {order_status}: {len(options)} options")
                else:
                    # Use status-based options as fallback
                    options = get_status_based_support_options(order_status)
                    app_logger.info(f"✅ Using status-based options for status {order_status}: {len(options)} options")
                
                emit('ai_options', {
                    'options': options,
                    'ticket_id': new_ticket.ticket_number or str(ticket_id),
                    'ticket_id_raw': ticket_id  # Add numeric ID for frontend matching
                })
                
                # Send ticket info
                emit('ticket_created', {
                    'ticket_id': new_ticket.ticket_number or str(ticket_id),
                    'ticket_id_raw': ticket_id,
                    'order_id': order_id
                })
                
                # Send SLA timer
                if hasattr(new_ticket, 'sla_due_at') and new_ticket.sla_due_at:
                    emit('sla_timer', {
                        'ticket_id': ticket_id,
                        'sla_due_at': new_ticket.sla_due_at.isoformat()
                    }, room=room)
                
                app_logger.info(f"✅ Guided support started for ticket {ticket_id}")
                
        except Exception as e:
            import traceback
            error_log = traceback.format_exc()
            app_logger.error(f"❌ DATABASE/LOGIC CRASH: {str(e)}")
            app_logger.error(error_log)
            # This will send the REAL error to your browser console
            emit('error', {'msg': f'Backend Error: {str(e)}'})
    
    @socketio.on('issue_selected')
    def handle_issue_selected(data):
        """
        Handle when customer selects an issue option
        Data: {issue_key: str, ticket_id: int, order_id: int}
        """
        try:
            issue_key = data.get('issue_key')
            ticket_id = data.get('ticket_id')
            order_id = data.get('order_id')
            
            if not issue_key or not ticket_id:
                emit('error', {'msg': 'Missing issue_key or ticket_id'})
                return
            
            with current_app.app_context():
                from app_pkg.models import SupportTicket, Order
                from app_pkg.intelligent_support import AutoAssignment
                from datetime import datetime
                from sqlalchemy import text
                
                # Get ticket
                ticket = SupportTicket.query.get(ticket_id)
                if not ticket:
                    emit('error', {'msg': 'Ticket not found'})
                    return
                
                # Get order to find status
                order = None
                if order_id:
                    order = Order.query.filter_by(id=order_id).first()
                
                order_status = order.status if order else 'pending'
                
                # Get flow details (from admin database)
                # ⭐ Enterprise-safe: Never crash if table missing
                flow_result = None
                try:
                    flow_query = text("""
                        SELECT issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected
                        FROM impromptuindian_admin.support_order_flows
                        WHERE order_status = :status AND issue_key = :issue_key
                        LIMIT 1
                    """)
                    flow_result = db.session.execute(
                        flow_query, 
                        {'status': order_status, 'issue_key': issue_key}
                    ).fetchone()
                except Exception as e:
                    current_app.logger.error(f"Support flow query failed (table may not exist): {e}")
                    # Continue without flow - will show generic response
                    flow_result = None
                
                room = f"ticket_{ticket_id}"
                
                if flow_result:
                    flow = flow_result
                    
                    # Send AI reply
                    emit('ai_message', {
                        'text': flow.ai_reply,
                        'sender_type': 'ai',  # Add for frontend compatibility
                        'ticket_id': ticket.ticket_number or str(ticket_id),
                        'ticket_id_raw': ticket_id,  # Add numeric ID for matching
                        'timestamp': datetime.utcnow().isoformat()
                    }, room=room)
                    
                    # Update ticket issue type
                    try:
                        ticket.issue_type = issue_key
                        db.session.commit()
                    except AttributeError:
                        pass
                    
                    # Handle auto-resolution or escalation
                    if flow.auto_resolve:
                        # Show resolution options
                        emit('ai_options', {
                            'options': [
                                {'key': 'resolved', 'title': '✅ Issue Resolved'},
                                {'key': 'agent', 'title': 'Talk to Agent'}
                            ],
                            'ticket_id': ticket.ticket_number or str(ticket_id),
                            'ticket_id_raw': ticket_id
                        }, room=room)
                    elif flow.escalate_if_selected:
                        # Auto-assign agent
                        agent_id = AutoAssignment.assign_agent()
                        if agent_id:
                            try:
                                ticket.assigned_agent_id = agent_id
                                ticket.status = 'assigned'
                                # Set first_response_at when agent is assigned
                                ticket.first_response_at = datetime.utcnow()
                                ticket.assigned_at = datetime.utcnow()
                                db.session.commit()
                                
                                emit('agent_joined', {
                                    'agent_id': agent_id,
                                    'message': f'👤 Support agent has joined the conversation'
                                }, room=room)
                                
                                app_logger.info(f"Agent {agent_id} auto-assigned to ticket {ticket_id}")
                            except Exception as e:
                                app_logger.warning(f"Auto-assignment failed: {e}")
                else:
                    # Fallback: Use status-based AI response if database flow not found
                    ai_response = get_status_based_ai_response(issue_key, order_status, order_id)
                    
                    emit('ai_message', {
                        'text': ai_response,
                        'sender_type': 'ai',  # Add for frontend compatibility
                        'ticket_id': ticket.ticket_number or str(ticket_id),
                        'ticket_id_raw': ticket_id,  # Add numeric ID for matching
                        'timestamp': datetime.utcnow().isoformat()
                    }, room=room)
                    
                    # Update ticket issue type
                    try:
                        ticket.issue_type = issue_key
                        db.session.commit()
                    except AttributeError:
                        pass
                    
                    # For certain critical issues, auto-assign agent
                    critical_issues = ['design_mistake', 'damaged_missing', 'not_received', 'cancel_delivery', 'quality_complaint']
                    if issue_key in critical_issues:
                        agent_id = AutoAssignment.assign_agent()
                        if agent_id:
                            try:
                                ticket.assigned_agent_id = agent_id
                                ticket.status = 'assigned'
                                ticket.first_response_at = datetime.utcnow()
                                ticket.assigned_at = datetime.utcnow()
                                db.session.commit()
                                
                                emit('agent_joined', {
                                    'agent_id': agent_id,
                                    'message': f'👤 Support agent has joined the conversation'
                                }, room=room)
                                
                                app_logger.info(f"Agent {agent_id} auto-assigned to ticket {ticket_id} for critical issue: {issue_key}")
                            except Exception as e:
                                app_logger.warning(f"Auto-assignment failed: {e}")
                    else:
                        # For non-critical issues, offer option to talk to agent
                        emit('ai_options', {
                            'options': [
                                {'key': 'resolved', 'title': '✅ Issue Resolved'},
                                {'key': 'agent', 'title': 'Talk to Agent'}
                            ],
                            'ticket_id': ticket.ticket_number or str(ticket_id),
                            'ticket_id_raw': ticket_id
                        }, room=room)
                
        except Exception as e:
            app_logger.exception(f"Error in issue_selected: {e}")
            emit('error', {'msg': 'Failed to process issue selection'})
    
    @socketio.on('start_ai_chat')
    def handle_start_ai_chat(data):
        """
        Legacy handler - redirects to start_support for backward compatibility
        """
        # Convert to new format
        data['order_id'] = data.get('order_id')
        handle_start_support(data)
    
    app_logger.info("✅ Socket.IO event handlers registered")


def notify_ticket_escalated(ticket_id):
    """Notify all users in ticket room about escalation"""
    try:
        from app_pkg import socketio
        room = f"ticket_{ticket_id}"
        
        socketio.emit('ticket_escalated', {
            'ticket_id': ticket_id,
            'message': '⚠️ Ticket has been escalated to senior support'
        }, room=room)
        
        app_logger.info(f"Escalation notification sent for ticket {ticket_id}")
    except Exception as e:
        app_logger.exception(f"Error sending escalation notification: {e}")
