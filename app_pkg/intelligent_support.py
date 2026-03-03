"""
Intelligent Support System - Enterprise AI Layer
================================================
This module provides:
1. AI Auto-Reply System
2. Order-Aware Smart Tickets
3. Escalation Engine
4. Analytics Queries
"""

from datetime import datetime, timedelta
from sqlalchemy import text, func, and_, or_
from app_pkg.models import db, SupportTicket, Order, Vendor, Rider, SupportUser
from app_pkg.logger_config import app_logger
import re
import json


# ============================================================================
# 1. AI AUTO-REPLY SYSTEM
# ============================================================================

class AIAutoReply:
    """AI-powered auto-reply system to reduce agent workload"""
    
    def __init__(self):
        self.intents = self._load_intents()
    
    def _load_intents(self):
        """Load AI intents from database"""
        try:
            result = db.session.execute(text("""
                SELECT intent_name, keywords, auto_reply_template, 
                       confidence_threshold, auto_resolve, requires_agent
                FROM support_ai_intents
            """)).fetchall()
            
            intents = {}
            for row in result:
                intents[row[0]] = {
                    'keywords': [k.strip() for k in row[1].split(',')],
                    'template': row[2],
                    'confidence_threshold': float(row[3]),
                    'auto_resolve': bool(row[4]),
                    'requires_agent': bool(row[5])
                }
            return intents
        except Exception as e:
            app_logger.error(f"Error loading AI intents: {e}")
            return self._get_default_intents()
    
    def _get_default_intents(self):
        """Default intents if database fails"""
        return {
            'order_status': {
                'keywords': ['where', 'order', 'status', 'location', 'track'],
                'template': 'Your order is currently being processed. You can track it from your orders page.',
                'confidence_threshold': 0.90,
                'auto_resolve': True,
                'requires_agent': False
            },
            'delivery_delay': {
                'keywords': ['late', 'delay', 'delivery', 'when', 'arrive'],
                'template': 'We apologize for the delay. Our team is working to deliver your order as soon as possible.',
                'confidence_threshold': 0.85,
                'auto_resolve': False,
                'requires_agent': True
            },
            'refund': {
                'keywords': ['refund', 'money back', 'return payment'],
                'template': 'Refund requests are handled by our support team. An agent will assist you shortly.',
                'confidence_threshold': 0.60,
                'auto_resolve': False,
                'requires_agent': True
            }
        }
    
    def analyze_message(self, message, ticket_id=None):
        """
        Analyze customer message and generate AI reply if applicable
        
        Returns:
            dict: {
                'reply': str or None,
                'confidence': float,
                'intent': str or None,
                'resolved': bool,
                'requires_agent': bool
            }
        """
        if not message:
            return None
        
        message_lower = message.lower()
        best_match = None
        best_confidence = 0.0
        
        # Check each intent
        for intent_name, intent_data in self.intents.items():
            keyword_matches = sum(1 for keyword in intent_data['keywords'] 
                                if keyword in message_lower)
            
            if keyword_matches > 0:
                # Calculate confidence based on keyword matches
                confidence = min(0.95, 0.5 + (keyword_matches * 0.15))
                
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = {
                        'intent': intent_name,
                        'template': intent_data['template'],
                        'confidence_threshold': intent_data['confidence_threshold'],
                        'auto_resolve': intent_data['auto_resolve'],
                        'requires_agent': intent_data['requires_agent']
                    }
        
        # Only return reply if confidence meets threshold
        if best_match and best_confidence >= best_match['confidence_threshold']:
            # Log AI attempt
            self._log_ai_attempt(ticket_id, message, best_match['template'], 
                               best_confidence, best_match['intent'], 
                               best_match['auto_resolve'])
            
            return {
                'reply': best_match['template'],
                'confidence': best_confidence,
                'intent': best_match['intent'],
                'resolved': best_match['auto_resolve'],
                'requires_agent': best_match['requires_agent']
            }
        
        return None
    
    def _log_ai_attempt(self, ticket_id, customer_message, ai_reply, 
                       confidence, intent, resolved):
        """Log AI auto-reply attempt to database"""
        try:
            db.session.execute(text("""
                INSERT INTO support_ai_logs 
                (ticket_id, customer_message, ai_reply, confidence, intent_detected, resolved)
                VALUES (:ticket_id, :customer_message, :ai_reply, :confidence, :intent, :resolved)
            """), {
                'ticket_id': ticket_id,
                'customer_message': customer_message,
                'ai_reply': ai_reply,
                'confidence': confidence,
                'intent': intent,
                'resolved': resolved
            })
            db.session.commit()
        except Exception as e:
            app_logger.error(f"Error logging AI attempt: {e}")
            db.session.rollback()
    
    @staticmethod
    def detect_intent(message):
        """
        Static method to detect intent from message
        Returns: {'intent': str, 'confidence': float}
        """
        try:
            ai = AIAutoReply()
            result = ai.analyze_message(message)
            if result:
                return {
                    'intent': result.get('intent', 'general_issue'),
                    'confidence': result.get('confidence', 0.5)
                }
            return {'intent': 'general_issue', 'confidence': 0.3}
        except Exception as e:
            app_logger.error(f"Error detecting intent: {e}")
            return {'intent': 'general_issue', 'confidence': 0.3}
    
    @staticmethod
    def generate_reply(message, ticket_id=None):
        """
        Static method to generate AI reply
        Returns: {'reply': str, 'confidence': float, 'resolved': bool} or None
        """
        try:
            ai = AIAutoReply()
            return ai.analyze_message(message, ticket_id)
        except Exception as e:
            app_logger.error(f"Error generating AI reply: {e}")
            return None


# ============================================================================
# 2. ORDER-AWARE SMART TICKETS
# ============================================================================

class SmartTicketContext:
    """Automatically fetch and attach order context to tickets"""
    
    @staticmethod
    def enrich_ticket_with_order_context(ticket_id, order_id):
        """
        Enrich ticket with order context (vendor, rider, issue type)
        
        Args:
            ticket_id: Support ticket ID
            order_id: Order ID to fetch context from
        """
        try:
            # Fetch order details
            order = Order.query.filter_by(id=order_id).first()
            if not order:
                app_logger.warning(f"Order {order_id} not found for ticket {ticket_id}")
                return
            
            # Update ticket with order context
            ticket = SupportTicket.query.filter_by(id=ticket_id).first()
            if not ticket:
                return
            
            # Set vendor and rider IDs
            ticket.vendor_id = order.vendor_id if hasattr(order, 'vendor_id') else None
            ticket.rider_id = order.rider_id if hasattr(order, 'rider_id') else None
            
            # Auto-detect issue type based on order status
            issue_type = SmartTicketContext._detect_issue_type(order, ticket)
            if issue_type:
                ticket.issue_type = issue_type
            
            db.session.commit()
            app_logger.info(f"Ticket {ticket_id} enriched with order {order_id} context")
            
        except Exception as e:
            app_logger.error(f"Error enriching ticket context: {e}")
            db.session.rollback()
    
    @staticmethod
    def _detect_issue_type(order, ticket):
        """Auto-detect issue type from order status and ticket description"""
        description_lower = (ticket.description or "").lower()
        
        # Check order status
        if hasattr(order, 'status'):
            order_status = str(order.status).lower()
            
            if 'delay' in order_status or 'delayed' in order_status:
                return 'delivery_delay'
            elif 'payment' in order_status or 'pending' in order_status:
                return 'payment_failed'
            elif 'cancelled' in order_status:
                return 'order_cancelled'
        
        # Check description keywords
        if any(word in description_lower for word in ['delay', 'late', 'delivery']):
            return 'delivery_delay'
        elif any(word in description_lower for word in ['payment', 'failed', 'declined']):
            return 'payment_failed'
        elif any(word in description_lower for word in ['quality', 'defect', 'wrong']):
            return 'quality_issue'
        elif any(word in description_lower for word in ['refund', 'money back']):
            return 'refund_request'
        
        return None
    
    @staticmethod
    def get_ticket_context(ticket_id):
        """Get full context for a ticket (order, vendor, rider info)"""
        try:
            ticket = SupportTicket.query.filter_by(id=ticket_id).first()
            if not ticket:
                return None
            
            context = {
                'ticket_id': ticket.id,
                'ticket_number': ticket.ticket_number,
                'status': ticket.status,
                'order_id': ticket.order_id,
                'vendor_id': ticket.vendor_id,
                'rider_id': ticket.rider_id,
                'issue_type': ticket.issue_type
            }
            
            # Add order details if available
            if ticket.order_id:
                order = Order.query.filter_by(id=ticket.order_id).first()
                if order:
                    context['order'] = {
                        'id': order.id,
                        'status': getattr(order, 'status', None),
                        'product_type': getattr(order, 'product_type', None),
                        'created_at': order.created_at.isoformat() if hasattr(order, 'created_at') else None
                    }
            
            # Add vendor details if available
            if ticket.vendor_id:
                vendor = Vendor.query.filter_by(id=ticket.vendor_id).first()
                if vendor:
                    context['vendor'] = {
                        'id': vendor.id,
                        'name': getattr(vendor, 'business_name', None) or getattr(vendor, 'name', None),
                        'email': getattr(vendor, 'email', None)
                    }
            
            # Add rider details if available
            if ticket.rider_id:
                rider = Rider.query.filter_by(id=ticket.rider_id).first()
                if rider:
                    context['rider'] = {
                        'id': rider.id,
                        'name': getattr(rider, 'name', None),
                        'phone': getattr(rider, 'phone', None)
                    }
            
            return context
            
        except Exception as e:
            app_logger.error(f"Error getting ticket context: {e}")
            return None


# ============================================================================
# 3. ESCALATION ENGINE
# ============================================================================

class EscalationEngine:
    """Automatic ticket escalation system"""
    
    ESCALATION_LEVELS = {
        1: 'support_agent',
        2: 'vendor_manager',
        3: 'rider_ops',
        4: 'admin'
    }
    
    @staticmethod
    def check_and_escalate_tickets():
        """Background worker: Check tickets and escalate if needed"""
        try:
            # Get escalation rules from support database
            # Fix: Use correct database binding (support, not admin)
            rules = db.session.execute(text("""
                SELECT id, rule_name, condition_type, condition_value, 
                       escalate_to_level, escalate_to_role
                FROM impromptuindian_support.escalation_rules
                WHERE is_active = TRUE
            """)).fetchall()
            
            escalated_count = 0
            
            for rule in rules:
                tickets = EscalationEngine._get_tickets_for_rule(rule)
                
                for ticket in tickets:
                    if EscalationEngine._should_escalate(ticket, rule):
                        EscalationEngine._escalate_ticket(ticket, rule)
                        escalated_count += 1
            
            app_logger.info(f"Escalation check completed: {escalated_count} tickets escalated")
            return escalated_count
            
        except Exception as e:
            app_logger.error(f"Error in escalation check: {e}")
            return 0
    
    @staticmethod
    def _get_tickets_for_rule(rule):
        """Get tickets matching escalation rule condition"""
        condition_type = rule[2]
        
        if condition_type == 'sla_expired':
            return SupportTicket.query.filter(
                SupportTicket.status.in_(['open', 'in_progress', 'assigned']),
                SupportTicket.sla_deadline.isnot(None),
                SupportTicket.sla_deadline < datetime.utcnow()
            ).all()
        
        elif condition_type == 'no_response':
            # Tickets with no response for X seconds
            seconds = int(rule[3]) if rule[3] else 600
            threshold = datetime.utcnow() - timedelta(seconds=seconds)
            
            return SupportTicket.query.filter(
                SupportTicket.status.in_(['open', 'assigned']),
                SupportTicket.first_response_at.is_(None),
                SupportTicket.created_at < threshold
            ).all()
        
        # Add more condition types as needed
        return []
    
    @staticmethod
    def _should_escalate(ticket, rule):
        """Check if ticket should be escalated based on rule"""
        # Check if already escalated to this level
        # ⭐ Explicitly use support database to avoid wrong database lookup
        existing = db.session.execute(text("""
            SELECT id FROM impromptuindian_support.ticket_escalations
            WHERE ticket_id = :ticket_id AND level = :level
        """), {
            'ticket_id': ticket.id,
            'level': rule[4]
        }).fetchone()
        
        return existing is None
    
    @staticmethod
    def _escalate_ticket(ticket, rule):
        """Escalate ticket to next level"""
        try:
            # Create escalation record
            # ⭐ Explicitly use support database to avoid wrong database lookup
            db.session.execute(text("""
                INSERT INTO impromptuindian_support.ticket_escalations
                (ticket_id, level, assigned_role, escalation_reason)
                VALUES (:ticket_id, :level, :role, :reason)
            """), {
                'ticket_id': ticket.id,
                'level': rule[4],
                'role': rule[5],
                'reason': f"Auto-escalated: {rule[1]}"
            })
            
            # Update ticket status
            ticket.status = 'escalated'
            db.session.commit()
            
            # Send Socket.IO notification
            try:
                from app_pkg.socketio_handlers import notify_ticket_escalated
                notify_ticket_escalated(ticket.id)
            except Exception as e:
                app_logger.warning(f"Failed to send escalation notification: {e}")
            
            app_logger.info(f"Ticket {ticket.id} escalated to level {rule[4]}")
            
        except Exception as e:
            app_logger.error(f"Error escalating ticket {ticket.id}: {e}")
            db.session.rollback()


# ============================================================================
# 4. ANALYTICS QUERIES
# ============================================================================

class SupportAnalytics:
    """Analytics queries for admin dashboard"""
    
    @staticmethod
    def get_support_health():
        """Get overall support health metrics"""
        try:
            result = db.session.execute(text("""
                SELECT * FROM v_support_health
            """)).fetchone()
            
            if result:
                return {
                    'total_tickets': result[0] or 0,
                    'open_tickets': result[1] or 0,
                    'in_progress_tickets': result[2] or 0,
                    'resolved_tickets': result[3] or 0,
                    'avg_response_time_minutes': float(result[4]) if result[4] else 0,
                    'sla_breaches': result[5] or 0,
                    'sla_met': result[6] or 0,
                    'tickets_today': result[7] or 0
                }
            return {}
        except Exception as e:
            app_logger.error(f"Error getting support health: {e}")
            return {}
    
    @staticmethod
    def get_agent_performance():
        """Get agent performance metrics"""
        try:
            results = db.session.execute(text("""
                SELECT 
                    ap.assigned_agent_id,
                    su.name as agent_name,
                    ap.total_assigned,
                    ap.resolved_count,
                    ap.avg_resolution_time_minutes,
                    ap.avg_response_time_minutes,
                    ap.sla_breaches
                FROM v_agent_performance ap
                LEFT JOIN support_users su ON su.id = ap.assigned_agent_id
            """)).fetchall()
            
            agents = []
            for row in results:
                agents.append({
                    'agent_id': row[0],
                    'agent_name': row[1] or f"Agent #{row[0]}",
                    'total_assigned': row[2] or 0,
                    'resolved_count': row[3] or 0,
                    'avg_resolution_time_minutes': float(row[4]) if row[4] else 0,
                    'avg_response_time_minutes': float(row[5]) if row[5] else 0,
                    'sla_breaches': row[6] or 0
                })
            
            return agents
        except Exception as e:
            app_logger.error(f"Error getting agent performance: {e}")
            return []
    
    @staticmethod
    def get_vendor_issues():
        """Get vendor issue statistics"""
        try:
            results = db.session.execute(text("""
                SELECT * FROM v_vendor_issues
            """)).fetchall()
            
            vendors = []
            for row in results:
                vendors.append({
                    'vendor_id': row[0],
                    'total_tickets': row[1],
                    'delivery_delays': row[2],
                    'quality_issues': row[3],
                    'avg_resolution_hours': float(row[4]) if row[4] else 0
                })
            
            return vendors
        except Exception as e:
            app_logger.error(f"Error getting vendor issues: {e}")
            return []
    
    @staticmethod
    def get_ai_performance():
        """Get AI auto-reply performance metrics"""
        try:
            results = db.session.execute(text("""
                SELECT * FROM v_ai_performance
            """)).fetchall()
            
            performance = []
            for row in results:
                performance.append({
                    'date': row[0].isoformat() if row[0] else None,
                    'total_ai_attempts': row[1],
                    'ai_resolved': row[2],
                    'avg_confidence': float(row[3]) if row[3] else 0,
                    'unique_intents': row[4]
                })
            
            return performance
        except Exception as e:
            app_logger.error(f"Error getting AI performance: {e}")
            return []


# ============================================================================
# 5. AUTO AGENT ASSIGNMENT
# ============================================================================

class AutoAssignment:
    """Automatic agent assignment based on load balancing"""
    
    @staticmethod
    def assign_agent():
        """Assign ticket to agent with least load"""
        try:
            # Get agent with least active tickets (using assigned_agent_id)
            result = db.session.execute(text("""
                SELECT su.id, su.name, 
                       COUNT(st.id) as active_tickets
                FROM support_users su
                LEFT JOIN support_tickets st ON st.assigned_agent_id = su.id 
                    AND st.status IN ('open', 'assigned', 'in_progress')
                WHERE su.online_status = 1
                    AND su.role = 'agent'
                GROUP BY su.id, su.name
                ORDER BY active_tickets ASC
                LIMIT 1
            """)).fetchone()
            
            if result:
                return result[0]  # Return agent ID
            
            return None
        except Exception as e:
            app_logger.error(f"Error assigning agent: {e}")
            return None
    
    @staticmethod
    def assign_ticket_to_agent(ticket_id):
        """Assign a ticket to the best available agent"""
        agent_id = AutoAssignment.assign_agent()
        
        if agent_id:
            try:
                ticket = SupportTicket.query.filter_by(id=ticket_id).first()
                if ticket:
                    # Set assigned_agent_id (enterprise standard)
                    try:
                        ticket.assigned_agent_id = agent_id
                    except AttributeError:
                        # Fallback to assigned_to if column doesn't exist yet
                        ticket.assigned_to = agent_id
                    
                    ticket.status = 'assigned'
                    
                    # Set assigned_at timestamp
                    try:
                        ticket.assigned_at = datetime.utcnow()
                    except AttributeError:
                        pass  # Column might not exist yet
                    
                    db.session.commit()
                    app_logger.info(f"Ticket {ticket_id} assigned to agent {agent_id}")
                    return agent_id
            except Exception as e:
                app_logger.error(f"Error assigning ticket {ticket_id}: {e}")
                db.session.rollback()
        
        return None
