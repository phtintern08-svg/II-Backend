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


def register_handlers(socketio):
    """Register all Socket.IO event handlers"""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        app_logger.info(f"Client connected: {request.sid}")
        emit('system_message', {'msg': 'Connected to support chat'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        app_logger.info(f"Client disconnected: {request.sid}")
    
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
                'ticket_id': ticket.ticket_number or str(ticket.id),
                'message': message,
                'sender': sender,
                'sender_id': sender_id,
                'sender_name': sender_name,
                'timestamp': datetime.utcnow().isoformat()
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
            
            app_logger.info(f"✅ START SUPPORT - Order: {order_id}, Customer: {customer_id}")
            
            if not customer_id:
                emit('error', {'msg': 'Customer ID required'})
                return
            
            if not order_id:
                emit('error', {'msg': 'Order ID required'})
                return
            
            with current_app.app_context():
                from app_pkg.models import SupportTicket, Order
                from app_pkg.intelligent_support import AutoAssignment
                from datetime import datetime, timedelta
                from sqlalchemy import text
                
                # Get order details
                order = Order.query.filter_by(id=order_id).first()
                if not order:
                    emit('error', {'msg': 'Order not found'})
                    return
                
                order_status = order.status or 'pending'
                vendor_id = getattr(order, 'selected_vendor_id', None)
                rider_id = getattr(order, 'rider_id', None)
                
                # Get available flows for this order status
                flows_query = text("""
                    SELECT issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected
                    FROM support_order_flows
                    WHERE order_status = :status
                    ORDER BY id ASC
                """)
                
                flows = db.session.execute(flows_query, {'status': order_status}).fetchall()
                
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
                    'ticket_id': new_ticket.ticket_number or str(ticket_id),
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Send issue options (Flipkart-style buttons)
                if flows:
                    options = [{
                        'key': flow.issue_key,
                        'title': flow.issue_title
                    } for flow in flows]
                    
                    emit('ai_options', {
                        'options': options,
                        'ticket_id': new_ticket.ticket_number or str(ticket_id)
                    })
                else:
                    # Fallback if no flows defined for this status
                    emit('ai_options', {
                        'options': [
                            {'key': 'general_issue', 'title': 'General Issue'},
                            {'key': 'track_order', 'title': 'Track Order'},
                            {'key': 'cancel_order', 'title': 'Cancel Order'}
                        ],
                        'ticket_id': new_ticket.ticket_number or str(ticket_id)
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
            app_logger.exception(f"Error in start_support: {e}")
            emit('error', {'msg': 'Failed to start support'})
    
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
                
                # Get flow details
                flow_query = text("""
                    SELECT issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected
                    FROM support_order_flows
                    WHERE order_status = :status AND issue_key = :issue_key
                    LIMIT 1
                """)
                
                flow_result = db.session.execute(
                    flow_query, 
                    {'status': order_status, 'issue_key': issue_key}
                ).fetchone()
                
                room = f"ticket_{ticket_id}"
                
                if flow_result:
                    flow = flow_result
                    
                    # Send AI reply
                    emit('ai_message', {
                        'text': flow.ai_reply,
                        'ticket_id': ticket.ticket_number or str(ticket_id),
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
                            'ticket_id': ticket.ticket_number or str(ticket_id)
                        }, room=room)
                    elif flow.escalate_if_selected:
                        # Auto-assign agent
                        agent_id = AutoAssignment.assign_agent()
                        if agent_id:
                            try:
                                ticket.assigned_agent_id = agent_id
                                ticket.status = 'assigned'
                                db.session.commit()
                                
                                emit('agent_joined', {
                                    'agent_id': agent_id,
                                    'message': f'👤 Support agent has joined the conversation'
                                }, room=room)
                                
                                app_logger.info(f"Agent {agent_id} auto-assigned to ticket {ticket_id}")
                            except Exception as e:
                                app_logger.warning(f"Auto-assignment failed: {e}")
                else:
                    # Fallback: assign agent for unknown issues
                    agent_id = AutoAssignment.assign_agent()
                    if agent_id:
                        try:
                            ticket.assigned_agent_id = agent_id
                            ticket.status = 'assigned'
                            db.session.commit()
                            
                            emit('agent_joined', {
                                'agent_id': agent_id,
                                'message': f'👤 Support agent has joined the conversation'
                            }, room=room)
                        except Exception as e:
                            app_logger.warning(f"Auto-assignment failed: {e}")
                
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
