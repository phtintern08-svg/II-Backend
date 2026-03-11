-- =====================================================
-- IMPROMPTUINDIAN SUPPORT DATABASE - MASTER CLEANUP & VERIFICATION
-- =====================================================
-- Purpose: Complete cleanup, verification, and strategic analysis
-- 
-- ⚠️ IMPORTANT DATABASE STRUCTURE:
-- - impromptuindian_support: support_tickets, threads, support_users, support_auto_assignment, views
-- - impromptuindian_admin: support_order_flows
-- 
-- ⚠️ BACKUP YOUR DATABASE BEFORE RUNNING THIS SCRIPT!
-- =====================================================

-- =====================================================
-- PART 1: REMOVE REDUNDANT TABLES
-- =====================================================

-- Step 1.1: Identify redundant tables before deletion
SELECT 
    '=== REDUNDANT TABLES TO REMOVE ===' as section,
    '' as table_name,
    '' as database_name,
    '' as reason;

SELECT 
    'escalation_rules' as table_name,
    table_schema as database_name,
    table_rows as row_count,
    'REMOVE: Duplicate of support_escalation_rules' as reason
FROM information_schema.tables
WHERE table_schema IN ('impromptuindian_admin', 'impromptuindian_support')
    AND table_name = 'escalation_rules'
UNION ALL
SELECT 
    'support_ai_intents' as table_name,
    table_schema as database_name,
    table_rows as row_count,
    'REMOVE: Not used - code uses support_order_flows instead' as reason
FROM information_schema.tables
WHERE table_schema IN ('impromptuindian_admin', 'impromptuindian_support')
    AND table_name = 'support_ai_intents'
UNION ALL
SELECT 
    'support_ticket_categories' as table_name,
    table_schema as database_name,
    table_rows as row_count,
    'REMOVE: Empty and unused - code sets category to NULL' as reason
FROM information_schema.tables
WHERE table_schema IN ('impromptuindian_admin', 'impromptuindian_support')
    AND table_name = 'support_ticket_categories'
ORDER BY database_name, table_name;

-- Step 1.2: Remove redundant tables
SELECT '=== REMOVING REDUNDANT TABLES ===' as action;

-- Remove escalation_rules (duplicate)
DROP TABLE IF EXISTS impromptuindian_admin.escalation_rules;
DROP TABLE IF EXISTS impromptuindian_support.escalation_rules;

-- Remove support_ai_intents (not used)
DROP TABLE IF EXISTS impromptuindian_admin.support_ai_intents;
DROP TABLE IF EXISTS impromptuindian_support.support_ai_intents;

-- Remove support_ticket_categories (empty and unused)
DROP TABLE IF EXISTS impromptuindian_admin.support_ticket_categories;
DROP TABLE IF EXISTS impromptuindian_support.support_ticket_categories;

-- Step 1.3: Verify removal
SELECT 
    '=== VERIFICATION: REDUNDANT TABLES REMOVED ===' as section,
    table_name,
    table_schema as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = t.table_schema AND table_name = t.table_name
        ) THEN 'STILL EXISTS ❌'
        ELSE 'DELETED ✅'
    END as status
FROM (
    SELECT 'escalation_rules' as table_name, 'impromptuindian_admin' as table_schema
    UNION ALL SELECT 'support_ai_intents', 'impromptuindian_admin'
    UNION ALL SELECT 'support_ticket_categories', 'impromptuindian_admin'
    UNION ALL SELECT 'escalation_rules', 'impromptuindian_support'
    UNION ALL SELECT 'support_ai_intents', 'impromptuindian_support'
    UNION ALL SELECT 'support_ticket_categories', 'impromptuindian_support'
) t
ORDER BY table_schema, table_name;

-- =====================================================
-- PART 2: VERIFY ESSENTIAL TABLES
-- =====================================================

SELECT '=== ESSENTIAL TABLES STATUS ===' as section;

-- 2.1: support_tickets (impromptuindian_support) - STAY
SELECT 
    'support_tickets' as table_name,
    'impromptuindian_support' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'support_tickets'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - CRITICAL: This stores all tickets!'
    END as status;

-- Get support_tickets statistics
SELECT 
    'support_tickets' as table_name,
    COUNT(*) as total_tickets,
    SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_tickets,
    SUM(CASE WHEN status = 'assigned' THEN 1 ELSE 0 END) as assigned_tickets,
    SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_tickets,
    SUM(CASE WHEN assigned_to IS NULL THEN 1 ELSE 0 END) as unassigned_tickets
FROM impromptuindian_support.support_tickets;

-- 2.2: support_order_flows (impromptuindian_admin) - STAY (IMPORTANT)
SELECT 
    'support_order_flows' as table_name,
    'impromptuindian_admin' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_order_flows'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - CRITICAL: This is your Flipkart-style question database!'
    END as status;

-- Get support_order_flows statistics
SELECT 
    'support_order_flows' as table_name,
    COUNT(*) as total_flows,
    COUNT(DISTINCT order_status) as unique_statuses,
    SUM(CASE WHEN ai_reply IS NULL OR ai_reply = '' THEN 1 ELSE 0 END) as flows_without_replies,
    CASE 
        WHEN SUM(CASE WHEN ai_reply IS NULL OR ai_reply = '' THEN 1 ELSE 0 END) = 0 
        THEN 'ALL HAVE REPLIES ✅' 
        ELSE 'SOME MISSING REPLIES ❌' 
    END as reply_status
FROM impromptuindian_admin.support_order_flows;

-- Show flows by order status
SELECT 
    order_status,
    COUNT(*) as flow_count,
    GROUP_CONCAT(issue_key SEPARATOR ', ') as available_issues
FROM impromptuindian_admin.support_order_flows
GROUP BY order_status
ORDER BY order_status;

-- 2.3: threads (impromptuindian_support) - STAY
SELECT 
    'threads' as table_name,
    'impromptuindian_support' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'threads'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - CRITICAL: This stores all chat messages!'
    END as status,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'impromptuindian_support'
            AND table_name = 'threads'
            AND column_name = 'ticket_id'
        ) THEN 'HAS ticket_id COLUMN ✅'
        ELSE 'MISSING ticket_id COLUMN ❌ - WRONG TABLE!'
    END as column_check;

-- Get threads statistics (WARNING: If empty, handle_send_message is not committing!)
SELECT 
    'threads' as table_name,
    COUNT(*) as total_messages,
    COUNT(DISTINCT ticket_id) as tickets_with_messages,
    COUNT(DISTINCT user_id) as unique_senders,
    MIN(created_at) as oldest_message,
    MAX(created_at) as newest_message,
    COUNT(CASE WHEN DATE(created_at) = CURDATE() THEN 1 END) as messages_today,
    CASE 
        WHEN COUNT(*) = 0 THEN '⚠️ WARNING: TABLE IS EMPTY! Check handle_send_message commit()'
        WHEN MAX(created_at) < DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN '⚠️ WARNING: No recent messages!'
        ELSE '✅ ACTIVE'
    END as activity_status
FROM impromptuindian_support.threads;

-- 2.4: support_users (impromptuindian_support) - STAY
SELECT 
    'support_users' as table_name,
    'impromptuindian_support' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'support_users'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - CRITICAL: This stores agent info for auto-assignment!'
    END as status;

-- Get support_users statistics
SELECT 
    'support_users' as table_name,
    COUNT(*) as total_users,
    SUM(CASE WHEN role IN ('agent', 'support') THEN 1 ELSE 0 END) as agents,
    SUM(CASE WHEN role IN ('admin', 'manager', 'senior_support') THEN 1 ELSE 0 END) as admins_managers,
    SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_users
FROM impromptuindian_support.support_users;

-- List all support users
SELECT 
    id,
    name,
    email,
    role,
    is_active,
    last_login_at,
    created_at
FROM impromptuindian_support.support_users
ORDER BY role, name;

-- 2.5: support_auto_assignment (impromptuindian_support) - STAY
SELECT 
    'support_auto_assignment' as table_name,
    'impromptuindian_support' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'support_auto_assignment'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - Optional: Used for auto-assignment rules'
    END as status;

-- Get support_auto_assignment details
SELECT 
    id,
    assignment_method,
    is_enabled,
    created_at,
    updated_at,
    CASE 
        WHEN is_enabled = 1 THEN 'ENABLED ✅'
        ELSE 'DISABLED ❌'
    END as status
FROM impromptuindian_support.support_auto_assignment
ORDER BY is_enabled DESC, id;

-- =====================================================
-- PART 3: VERIFY VIEWS (KEEP - Useful for Admin Dashboard)
-- =====================================================

SELECT '=== VIEWS STATUS (KEEP - Useful for Stats) ===' as section;

-- Check which views exist
SELECT 
    table_name as view_name,
    'impromptuindian_support' as database_name,
    'EXISTS ✅' as status
FROM information_schema.views
WHERE table_schema = 'impromptuindian_support'
    AND table_name IN ('v_agent_performance', 'v_ai_performance', 'v_support_health', 'v_vendor_issues')
ORDER BY table_name;

-- Test each view (only if they exist)
-- v_agent_performance
SELECT 
    'v_agent_performance' as view_name,
    COUNT(*) as row_count
FROM impromptuindian_support.v_agent_performance;

-- v_ai_performance
SELECT 
    'v_ai_performance' as view_name,
    COUNT(*) as row_count
FROM impromptuindian_support.v_ai_performance;

-- v_support_health
SELECT 
    'v_support_health' as view_name,
    COUNT(*) as row_count
FROM impromptuindian_support.v_support_health;

-- v_vendor_issues
SELECT 
    'v_vendor_issues' as view_name,
    COUNT(*) as row_count
FROM impromptuindian_support.v_vendor_issues;

-- =====================================================
-- PART 4: DATA INTEGRITY CHECKS
-- =====================================================

SELECT '=== DATA INTEGRITY CHECKS ===' as section;

-- 4.1: Check for orphaned threads (threads without valid tickets)
SELECT 
    'Orphaned threads' as check_type,
    COUNT(*) as count,
    CASE 
        WHEN COUNT(*) > 0 THEN '⚠️ WARNING: Found orphaned threads!'
        ELSE '✅ OK'
    END as status
FROM impromptuindian_support.threads th
LEFT JOIN impromptuindian_support.support_tickets t ON t.id = th.ticket_id
WHERE th.ticket_id IS NOT NULL
    AND t.id IS NULL;

-- 4.2: Check for tickets without messages
SELECT 
    'Tickets without messages (last 7 days)' as check_type,
    COUNT(*) as count
FROM impromptuindian_support.support_tickets t
LEFT JOIN impromptuindian_support.threads th ON th.ticket_id = t.id
WHERE th.id IS NULL
    AND t.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY);

-- 4.3: Check for tickets with messages but no first response
SELECT 
    'Tickets without first response (messages exist)' as check_type,
    COUNT(*) as count
FROM impromptuindian_support.support_tickets t
JOIN impromptuindian_support.threads th ON th.ticket_id = t.id
WHERE t.status != 'resolved'
    AND t.first_response_at IS NULL
    AND th.created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);

-- 4.4: Check for flows with missing AI replies
SELECT 
    'Flows without AI replies' as check_type,
    COUNT(*) as count,
    GROUP_CONCAT(CONCAT(order_status, ':', issue_key) SEPARATOR ', ') as missing_replies
FROM impromptuindian_admin.support_order_flows
WHERE ai_reply IS NULL OR ai_reply = '';

-- =====================================================
-- PART 5: STRATEGIC ANALYSIS (The "Flipkart" Decision)
-- =====================================================

SELECT '=== STRATEGIC ANALYSIS ===' as section;

-- 5.1: Check if support_order_flows has comprehensive coverage
SELECT 
    'support_order_flows Coverage' as analysis_type,
    COUNT(DISTINCT order_status) as statuses_covered,
    COUNT(*) as total_flows,
    ROUND(COUNT(*) / NULLIF(COUNT(DISTINCT order_status), 0), 2) as avg_flows_per_status,
    CASE 
        WHEN COUNT(*) >= 20 THEN '✅ GOOD: Comprehensive coverage'
        WHEN COUNT(*) >= 10 THEN '⚠️ WARNING: Some statuses may be missing'
        ELSE '❌ CRITICAL: Very limited coverage'
    END as coverage_status
FROM impromptuindian_admin.support_order_flows;

-- 5.2: Show which order statuses have flows
SELECT 
    'Order Status Coverage' as analysis_type,
    order_status,
    COUNT(*) as flow_count,
    GROUP_CONCAT(issue_key SEPARATOR ', ') as available_issues
FROM impromptuindian_admin.support_order_flows
GROUP BY order_status
ORDER BY order_status;

-- 5.3: Check threads table activity (Critical for detecting commit issues)
SELECT 
    'Threads Table Activity Check' as analysis_type,
    COUNT(*) as total_messages,
    COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 END) as messages_last_hour,
    COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as messages_last_24h,
    MAX(created_at) as last_message_time,
    TIMESTAMPDIFF(MINUTE, MAX(created_at), NOW()) as minutes_since_last_message,
    CASE 
        WHEN COUNT(*) = 0 THEN '❌ CRITICAL: Table is empty! Check handle_send_message commit() in socketio_handlers.py'
        WHEN MAX(created_at) < DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN '⚠️ WARNING: No recent activity - check if messages are being saved'
        ELSE '✅ OK: Table is receiving messages'
    END as activity_status
FROM impromptuindian_support.threads;

-- =====================================================
-- PART 6: FINAL SUMMARY & RECOMMENDATIONS
-- =====================================================

SELECT '=== FINAL SUMMARY ===' as section;

-- Essential tables summary
SELECT 
    'Essential Tables Status' as summary_type,
    CONCAT(
        'support_tickets: ', 
        CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'impromptuindian_support' AND table_name = 'support_tickets') THEN '✅' ELSE '❌' END,
        ' | support_order_flows: ',
        CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'impromptuindian_admin' AND table_name = 'support_order_flows') THEN '✅' ELSE '❌' END,
        ' | threads: ',
        CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'impromptuindian_support' AND table_name = 'threads') THEN '✅' ELSE '❌' END,
        ' | support_users: ',
        CASE WHEN EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'impromptuindian_support' AND table_name = 'support_users') THEN '✅' ELSE '❌' END
    ) as status
UNION ALL
SELECT 
    'Redundant Tables Removed' as summary_type,
    'escalation_rules, support_ai_intents, support_ticket_categories' as status
UNION ALL
SELECT 
    'Views Status' as summary_type,
    CONCAT(
        (SELECT COUNT(*) FROM information_schema.views WHERE table_schema = 'impromptuindian_support' AND table_name IN ('v_agent_performance', 'v_ai_performance', 'v_support_health', 'v_vendor_issues')),
        ' views found (KEEP - useful for Admin Dashboard)'
    ) as status
UNION ALL
SELECT 
    'Threads Activity' as summary_type,
    CASE 
        WHEN (SELECT COUNT(*) FROM impromptuindian_support.threads) = 0 
        THEN '❌ EMPTY - Check handle_send_message commit() in socketio_handlers.py'
        WHEN (SELECT MAX(created_at) FROM impromptuindian_support.threads) < DATE_SUB(NOW(), INTERVAL 1 HOUR)
        THEN '⚠️ NO RECENT ACTIVITY - Verify messages are being saved'
        ELSE '✅ ACTIVE'
    END as status
UNION ALL
SELECT 
    'Recommendation' as summary_type,
    'Delete get_status_based_support_options() and get_status_based_ai_response() from socketio_handlers.py - Use 100% support_order_flows table for Flipkart-style experience' as status;

-- =====================================================
-- END OF MASTER CLEANUP & VERIFICATION
-- =====================================================
-- 
-- NEXT STEPS:
-- 1. ✅ Redundant tables removed
-- 2. ✅ Essential tables verified
-- 3. ⚠️ If threads table is empty: Check handle_send_message commit() in socketio_handlers.py
-- 4. 📝 Delete Python functions get_status_based_support_options() and get_status_based_ai_response() from socketio_handlers.py
-- 5. 📝 Rely 100% on support_order_flows table for all AI responses
-- 6. ✅ Views kept for Admin Dashboard statistics
-- =====================================================
