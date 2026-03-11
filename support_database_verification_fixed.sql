-- =====================================================
-- IMPROMPTUINDIAN SUPPORT DATABASE VERIFICATION (FIXED)
-- =====================================================
-- Purpose: Verify all essential tables are working correctly
-- 
-- ⚠️ IMPORTANT: Tables are in TWO databases:
-- - impromptuindian_support: support_tickets, threads, support_users, support_auto_assignment
-- - impromptuindian_admin: support_order_flows
-- =====================================================

-- =====================================================
-- 1. VERIFY SUPPORT_ORDER_FLOWS (Primary AI Source)
-- =====================================================

-- Check all flows by order status (in impromptuindian_admin)
SELECT 
    order_status,
    COUNT(*) as flow_count,
    GROUP_CONCAT(
        CONCAT(issue_key, ' (', LEFT(issue_title, 30), ')') 
        SEPARATOR ' | '
    ) as available_flows
FROM impromptuindian_admin.support_order_flows
GROUP BY order_status
ORDER BY order_status;

-- Check flows with missing or empty AI replies
SELECT 
    id,
    order_status,
    issue_key,
    issue_title,
    CASE 
        WHEN ai_reply IS NULL THEN 'NULL ❌'
        WHEN ai_reply = '' THEN 'EMPTY ❌'
        ELSE 'OK ✅'
    END as reply_status,
    LENGTH(ai_reply) as reply_length,
    auto_resolve,
    escalate_if_selected
FROM impromptuindian_admin.support_order_flows
WHERE ai_reply IS NULL OR ai_reply = ''
ORDER BY order_status, issue_key;

-- =====================================================
-- 2. VERIFY THREADS TABLE (Message Storage)
-- =====================================================

-- Overall threads statistics (in impromptuindian_support)
SELECT 
    'Total Messages' as metric,
    COUNT(*) as value
FROM impromptuindian_support.threads
UNION ALL
SELECT 
    'Tickets with Messages' as metric,
    COUNT(DISTINCT ticket_id) as value
FROM impromptuindian_support.threads
WHERE ticket_id IS NOT NULL
UNION ALL
SELECT 
    'Unique Senders' as metric,
    COUNT(DISTINCT user_id) as value
FROM impromptuindian_support.threads
UNION ALL
SELECT 
    'Messages Today' as metric,
    COUNT(*) as value
FROM impromptuindian_support.threads
WHERE DATE(created_at) = CURDATE()
UNION ALL
SELECT 
    'Messages This Week' as metric,
    COUNT(*) as value
FROM impromptuindian_support.threads
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
UNION ALL
SELECT 
    'Messages This Month' as metric,
    COUNT(*) as value
FROM impromptuindian_support.threads
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY);

-- Recent messages activity (verify threads table is populating)
SELECT 
    th.id,
    th.ticket_id,
    t.ticket_number,
    LEFT(th.content, 50) as message_preview,
    th.user_id,
    th.created_at,
    TIMESTAMPDIFF(MINUTE, th.created_at, NOW()) as minutes_ago
FROM impromptuindian_support.threads th
JOIN impromptuindian_support.support_tickets t ON t.id = th.ticket_id
ORDER BY th.created_at DESC
LIMIT 20;

-- Message count per ticket (verify data integrity)
SELECT 
    t.ticket_number,
    t.subject,
    t.status,
    COUNT(th.id) as message_count,
    MAX(th.created_at) as last_message_at,
    TIMESTAMPDIFF(HOUR, MAX(th.created_at), NOW()) as hours_since_last_message
FROM impromptuindian_support.support_tickets t
LEFT JOIN impromptuindian_support.threads th ON th.ticket_id = t.id
WHERE t.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY t.id, t.ticket_number, t.subject, t.status
ORDER BY last_message_at DESC
LIMIT 20;

-- =====================================================
-- 3. VERIFY SUPPORT_TICKETS TABLE
-- =====================================================

-- Ticket status breakdown (in impromptuindian_support)
SELECT 
    status,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM impromptuindian_support.support_tickets), 2) as percentage,
    ROUND(AVG(TIMESTAMPDIFF(HOUR, created_at, COALESCE(resolved_at, NOW()))), 2) as avg_hours_open
FROM impromptuindian_support.support_tickets
GROUP BY status
ORDER BY count DESC;

-- Tickets by priority
SELECT 
    priority,
    COUNT(*) as count,
    ROUND(AVG(TIMESTAMPDIFF(HOUR, created_at, COALESCE(resolved_at, NOW()))), 2) as avg_hours_open,
    MIN(created_at) as oldest_ticket,
    MAX(created_at) as newest_ticket
FROM impromptuindian_support.support_tickets
GROUP BY priority
ORDER BY 
    CASE priority
        WHEN 'high' THEN 1
        WHEN 'medium' THEN 2
        WHEN 'low' THEN 3
        ELSE 4
    END;

-- Tickets without assigned agent (should trigger auto-assignment)
SELECT 
    id,
    ticket_number,
    subject,
    status,
    priority,
    created_at,
    TIMESTAMPDIFF(HOUR, created_at, NOW()) as hours_since_creation
FROM impromptuindian_support.support_tickets
WHERE status = 'open' 
    AND assigned_agent_id IS NULL
    AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY created_at DESC;

-- =====================================================
-- 4. VERIFY SUPPORT_USERS TABLE (Agents)
-- =====================================================

-- Active agents list (in impromptuindian_support)
SELECT 
    id,
    username,
    email,
    role,
    is_active,
    created_at,
    last_login_at,
    TIMESTAMPDIFF(DAY, COALESCE(last_login_at, created_at), NOW()) as days_since_last_login
FROM impromptuindian_support.support_users
WHERE role = 'agent'
ORDER BY is_active DESC, username;

-- Agent assignment statistics
SELECT 
    su.id,
    su.username,
    su.is_active,
    COUNT(DISTINCT st.id) as assigned_tickets,
    COUNT(DISTINCT CASE WHEN st.status = 'open' THEN st.id END) as open_tickets,
    COUNT(DISTINCT CASE WHEN st.status = 'assigned' THEN st.id END) as assigned_tickets_count,
    COUNT(DISTINCT CASE WHEN st.status = 'resolved' THEN st.id END) as resolved_tickets,
    ROUND(AVG(TIMESTAMPDIFF(MINUTE, st.created_at, st.first_response_at)), 2) as avg_response_time_minutes
FROM impromptuindian_support.support_users su
LEFT JOIN impromptuindian_support.support_tickets st ON st.assigned_agent_id = su.id
WHERE su.role = 'agent'
GROUP BY su.id, su.username, su.is_active
ORDER BY assigned_tickets DESC;

-- =====================================================
-- 5. VERIFY SUPPORT_AUTO_ASSIGNMENT TABLE
-- =====================================================

-- Check assignment rules (in impromptuindian_support)
SELECT 
    id,
    assignment_method,
    is_active,
    priority_weight,
    workload_weight,
    created_at,
    updated_at,
    CASE 
        WHEN is_active = 1 THEN 'ACTIVE ✅'
        ELSE 'INACTIVE ❌'
    END as status
FROM impromptuindian_support.support_auto_assignment
ORDER BY is_active DESC, id;

-- =====================================================
-- 6. VERIFY VIEWS (Performance Metrics)
-- =====================================================

-- Test v_agent_performance view (in impromptuindian_support)
SELECT 
    'v_agent_performance' as view_name,
    COUNT(*) as row_count,
    'Agent performance metrics' as description
FROM impromptuindian_support.v_agent_performance;

-- Sample data from v_agent_performance
SELECT * FROM impromptuindian_support.v_agent_performance
ORDER BY total_tickets DESC
LIMIT 10;

-- Test v_ai_performance view
SELECT 
    'v_ai_performance' as view_name,
    COUNT(*) as row_count,
    'AI response metrics' as description
FROM impromptuindian_support.v_ai_performance;

-- Test v_support_health view
SELECT 
    'v_support_health' as view_name,
    COUNT(*) as row_count,
    'Overall support health metrics' as description
FROM impromptuindian_support.v_support_health;

-- Sample data from v_support_health
SELECT * FROM impromptuindian_support.v_support_health;

-- Test v_vendor_issues view
SELECT 
    'v_vendor_issues' as view_name,
    COUNT(*) as row_count,
    'Vendor-related support issues' as description
FROM impromptuindian_support.v_vendor_issues;

-- Sample data from v_vendor_issues
SELECT * FROM impromptuindian_support.v_vendor_issues
ORDER BY issue_count DESC
LIMIT 10;

-- =====================================================
-- 7. DATA INTEGRITY CHECKS
-- =====================================================

-- Check for orphaned threads (threads without valid tickets)
SELECT 
    'Orphaned threads' as check_type,
    COUNT(*) as count
FROM impromptuindian_support.threads th
LEFT JOIN impromptuindian_support.support_tickets t ON t.id = th.ticket_id
WHERE th.ticket_id IS NOT NULL
    AND t.id IS NULL;

-- Check for tickets with messages but no first response
SELECT 
    'Tickets without first response' as check_type,
    COUNT(*) as count
FROM impromptuindian_support.support_tickets t
JOIN impromptuindian_support.threads th ON th.ticket_id = t.id
WHERE t.status != 'resolved'
    AND t.first_response_at IS NULL
    AND th.created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);

-- Check for order statuses that need flows
SELECT 
    'Order statuses needing flows' as check_type,
    COUNT(DISTINCT o.status) as count,
    GROUP_CONCAT(DISTINCT o.status SEPARATOR ', ') as missing_statuses
FROM impromptuindian_support.orders o
LEFT JOIN impromptuindian_admin.support_order_flows sof ON sof.order_status = o.status
WHERE sof.id IS NULL
    AND o.status IS NOT NULL
    AND o.status NOT IN ('completed', 'completed_with_penalty', 'cancelled')
    AND o.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY);

-- =====================================================
-- 8. PERFORMANCE METRICS
-- =====================================================

-- Average response time by agent
SELECT 
    su.username as agent_name,
    COUNT(DISTINCT st.id) as tickets_handled,
    ROUND(AVG(TIMESTAMPDIFF(MINUTE, st.created_at, st.first_response_at)), 2) as avg_first_response_minutes,
    ROUND(AVG(TIMESTAMPDIFF(HOUR, st.created_at, st.resolved_at)), 2) as avg_resolution_hours,
    MIN(st.first_response_at) as first_assignment,
    MAX(st.first_response_at) as last_assignment
FROM impromptuindian_support.support_users su
JOIN impromptuindian_support.support_tickets st ON st.assigned_agent_id = su.id
WHERE st.first_response_at IS NOT NULL
    AND st.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY su.id, su.username
HAVING tickets_handled > 0
ORDER BY avg_first_response_minutes ASC;

-- Ticket volume by day (last 30 days)
SELECT 
    DATE(created_at) as date,
    COUNT(*) as tickets_created,
    SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as tickets_resolved,
    ROUND(AVG(TIMESTAMPDIFF(HOUR, created_at, COALESCE(resolved_at, NOW()))), 2) as avg_hours_to_resolve,
    COUNT(DISTINCT assigned_agent_id) as agents_working
FROM impromptuindian_support.support_tickets
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(created_at)
ORDER BY date DESC;

-- =====================================================
-- 9. REAL-TIME VERIFICATION
-- =====================================================

-- Check if threads table is actively receiving messages
SELECT 
    'Threads table activity' as check_type,
    COUNT(*) as messages_last_hour,
    COUNT(DISTINCT ticket_id) as active_tickets,
    MAX(created_at) as last_message_time,
    TIMESTAMPDIFF(MINUTE, MAX(created_at), NOW()) as minutes_since_last_message
FROM impromptuindian_support.threads
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR);

-- Check recent ticket creation and message activity
SELECT 
    DATE(t.created_at) as date,
    COUNT(DISTINCT t.id) as tickets_created,
    COUNT(DISTINCT th.id) as messages_sent,
    ROUND(COUNT(DISTINCT th.id) / NULLIF(COUNT(DISTINCT t.id), 0), 2) as avg_messages_per_ticket
FROM impromptuindian_support.support_tickets t
LEFT JOIN impromptuindian_support.threads th ON th.ticket_id = t.id
WHERE t.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY DATE(t.created_at)
ORDER BY date DESC;

-- =====================================================
-- END OF VERIFICATION QUERIES
-- =====================================================
