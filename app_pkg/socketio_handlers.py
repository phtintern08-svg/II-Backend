"""
Socket.IO Event Handlers for Real-Time Support Chat
====================================================
Handles WebSocket connections for customer-agent chat
"""

from flask_socketio import emit, join_room, leave_room
from flask import request
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
