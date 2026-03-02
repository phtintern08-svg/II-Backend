"""
Support System Integration
==========================
Hooks intelligent support features into ticket creation and message handling
"""

from datetime import datetime, timedelta
from app_pkg.models import db, SupportTicket
from app_pkg.intelligent_support import (
    AIAutoReply, SmartTicketContext, AutoAssignment, EscalationEngine
)
from app_pkg.logger_config import app_logger


def process_new_ticket(ticket_id, order_id=None, customer_message=None):
    """
    Process a newly created ticket with intelligent features
    
    Args:
        ticket_id: Newly created ticket ID
        order_id: Optional order ID
        customer_message: Initial customer message
    """
    try:
        ticket = SupportTicket.query.filter_by(id=ticket_id).first()
        if not ticket:
            return
        
        # 1. Enrich with order context if order_id provided
        if order_id:
            SmartTicketContext.enrich_ticket_with_order_context(ticket_id, order_id)
        
        # 2. Try AI auto-reply if customer message provided
        if customer_message:
            ai = AIAutoReply()
            ai_result = ai.analyze_message(customer_message, ticket_id)
            
            if ai_result and ai_result.get('reply'):
                # Send AI reply
                send_ai_reply(ticket_id, ai_result['reply'])
                
                # Auto-resolve if AI confident
                if ai_result.get('resolved', False):
                    ticket.status = 'resolved'
                    ticket.resolved_at = datetime.utcnow()
                    db.session.commit()
                    app_logger.info(f"Ticket {ticket_id} auto-resolved by AI")
                    return
                
                # If not resolved, assign agent
                if ai_result.get('requires_agent', True):
                    AutoAssignment.assign_ticket_to_agent(ticket_id)
        else:
            # No AI message, directly assign agent
            AutoAssignment.assign_ticket_to_agent(ticket_id)
        
        # 3. Calculate SLA deadline
        calculate_sla_deadline(ticket_id)
        
        db.session.commit()
        
    except Exception as e:
        app_logger.error(f"Error processing new ticket {ticket_id}: {e}")
        db.session.rollback()


def process_customer_message(ticket_id, message):
    """
    Process incoming customer message with AI auto-reply
    
    Args:
        ticket_id: Ticket ID
        message: Customer message text
    """
    try:
        ticket = SupportTicket.query.filter_by(id=ticket_id).first()
        if not ticket:
            return None
        
        # Check if ticket is resolved/closed
        if ticket.status in ['resolved', 'closed']:
            # Reopen ticket if customer sends message
            ticket.status = 'open'
            ticket.resolved_at = None
            db.session.commit()
        
        # Try AI auto-reply
        ai = AIAutoReply()
        ai_result = ai.analyze_message(message, ticket_id)
        
        if ai_result and ai_result.get('reply'):
            # Send AI reply
            send_ai_reply(ticket_id, ai_result['reply'])
            
            # Auto-resolve if AI confident
            if ai_result.get('resolved', False):
                ticket.status = 'resolved'
                ticket.resolved_at = datetime.utcnow()
                db.session.commit()
                return ai_result
        
        # If AI didn't resolve, ensure agent is assigned
        if not ticket.assigned_to:
            AutoAssignment.assign_ticket_to_agent(ticket_id)
        
        db.session.commit()
        return ai_result
        
    except Exception as e:
        app_logger.error(f"Error processing customer message: {e}")
        db.session.rollback()
        return None


def send_ai_reply(ticket_id, ai_message):
    """
    Send AI-generated reply as a message in the ticket
    
    Args:
        ticket_id: Ticket ID
        ai_message: AI-generated message text
    """
    try:
        # Insert AI reply as a system message
        db.session.execute(
            db.text("""
                INSERT INTO support_messages
                (ticket_id, sender_id, sender_role, message, created_at)
                VALUES (:ticket_id, 0, 'support_agent', :message, :created_at)
            """),
            {
                'ticket_id': ticket_id,
                'message': f"🤖 Impromptu Assistant: {ai_message}",
                'created_at': datetime.utcnow()
            }
        )
        
        # Update first_response_at if this is the first response
        ticket = SupportTicket.query.filter_by(id=ticket_id).first()
        if ticket and not ticket.first_response_at:
            ticket.first_response_at = datetime.utcnow()
        
        db.session.commit()
        app_logger.info(f"AI reply sent for ticket {ticket_id}")
        
    except Exception as e:
        app_logger.error(f"Error sending AI reply: {e}")
        db.session.rollback()


def calculate_sla_deadline(ticket_id):
    """
    Calculate SLA deadline based on ticket priority
    
    Args:
        ticket_id: Ticket ID
    """
    try:
        ticket = SupportTicket.query.filter_by(id=ticket_id).first()
        if not ticket:
            return
        
        priority = ticket.priority or 'medium'
        
        # SLA rules based on priority
        sla_rules = {
            'high': timedelta(minutes=10),
            'critical': timedelta(minutes=5),
            'medium': timedelta(minutes=30),
            'low': timedelta(hours=2)
        }
        
        deadline = datetime.utcnow() + sla_rules.get(priority, timedelta(minutes=30))
        ticket.sla_deadline = deadline
        
        db.session.commit()
        app_logger.info(f"SLA deadline set for ticket {ticket_id}: {deadline}")
        
    except Exception as e:
        app_logger.error(f"Error calculating SLA deadline: {e}")
        db.session.rollback()


def update_first_response_time(ticket_id):
    """Update first_response_at when agent sends first message"""
    try:
        ticket = SupportTicket.query.filter_by(id=ticket_id).first()
        if ticket and not ticket.first_response_at:
            ticket.first_response_at = datetime.utcnow()
            db.session.commit()
    except Exception as e:
        app_logger.error(f"Error updating first response time: {e}")
        db.session.rollback()


def run_escalation_worker():
    """
    Background worker to check and escalate tickets
    Should be called periodically (e.g., every minute via cron or scheduler)
    """
    try:
        count = EscalationEngine.check_and_escalate_tickets()
        app_logger.info(f"Escalation worker completed: {count} tickets escalated")
        return count
    except Exception as e:
        app_logger.error(f"Error in escalation worker: {e}")
        return 0
