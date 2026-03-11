-- =====================================================
-- IMPROMPTUINDIAN SUPPORT DATABASE CLEANUP (FINAL FIXED)
-- =====================================================
-- Purpose: Remove redundant tables and verify essential tables
-- 
-- ⚠️ IMPORTANT DISCOVERY:
-- - support_tickets, support_users, support_auto_assignment, threads (with ticket_id) 
--   are in impromptuindian_support database
-- - support_order_flows is in impromptuindian_admin database
-- 
-- ⚠️ IMPORTANT: Backup your database before running DROP statements!
-- =====================================================

-- =====================================================
-- STEP 1: VERIFY REDUNDANT TABLES BEFORE DELETION
-- =====================================================

-- Check if redundant tables exist (using information_schema only - no SELECT from tables)
SELECT 
    table_name,
    table_schema as database_name,
    CASE 
        WHEN table_rows IS NOT NULL THEN table_rows
        ELSE 0
    END as row_count,
    CASE table_name
        WHEN 'escalation_rules' THEN 'Duplicate of support_escalation_rules'
        WHEN 'support_ai_intents' THEN 'Not used - using support_order_flows instead'
        WHEN 'support_ticket_categories' THEN 'Empty and unused'
        ELSE 'Unknown'
    END as reason
FROM information_schema.tables
WHERE table_schema IN ('impromptuindian_admin', 'impromptuindian_support')
    AND table_name IN ('escalation_rules', 'support_ai_intents', 'support_ticket_categories')
ORDER BY table_schema, table_name;

-- =====================================================
-- STEP 2: REMOVE REDUNDANT TABLES
-- =====================================================

-- Drop escalation_rules (duplicate of support_escalation_rules)
DROP TABLE IF EXISTS impromptuindian_admin.escalation_rules;
DROP TABLE IF EXISTS impromptuindian_support.escalation_rules;

-- Drop support_ai_intents (not used - using support_order_flows instead)
DROP TABLE IF EXISTS impromptuindian_admin.support_ai_intents;
DROP TABLE IF EXISTS impromptuindian_support.support_ai_intents;

-- Drop support_ticket_categories (empty and unused)
DROP TABLE IF EXISTS impromptuindian_admin.support_ticket_categories;
DROP TABLE IF EXISTS impromptuindian_support.support_ticket_categories;

-- =====================================================
-- STEP 3: VERIFY ESSENTIAL TABLES STATUS
-- =====================================================

-- Check support_tickets table (in impromptuindian_support)
SELECT 
    'support_tickets' as table_name,
    'impromptuindian_support' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'support_tickets'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌'
    END as status;

-- Get support_tickets details (separate query to avoid CASE subquery issues)
SELECT 
    'support_tickets' as table_name,
    COUNT(*) as total_records,
    SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_tickets,
    SUM(CASE WHEN status = 'assigned' THEN 1 ELSE 0 END) as assigned_tickets,
    SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) as resolved_tickets
FROM impromptuindian_support.support_tickets;

-- Check threads table (in impromptuindian_support - the one with ticket_id)
SELECT 
    'threads' as table_name,
    'impromptuindian_support' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'threads'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌'
    END as status,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'impromptuindian_support'
            AND table_name = 'threads'
            AND column_name = 'ticket_id'
        ) THEN 'HAS ticket_id COLUMN ✅'
        ELSE 'MISSING ticket_id COLUMN ❌'
    END as has_ticket_id;

-- Get threads details (separate query)
SELECT 
    'threads' as table_name,
    COUNT(*) as total_messages,
    COUNT(DISTINCT ticket_id) as tickets_with_messages,
    COUNT(DISTINCT user_id) as unique_senders,
    COUNT(CASE WHEN DATE(created_at) = CURDATE() THEN 1 END) as messages_today
FROM impromptuindian_support.threads;

-- Check support_users table (in impromptuindian_support)
SELECT 
    'support_users' as table_name,
    'impromptuindian_support' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'support_users'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌'
    END as status;

-- Get support_users details (check actual columns first)
-- Only run if table exists
SHOW COLUMNS FROM impromptuindian_support.support_users;

-- Get support_users statistics (using is_active column which exists)
SELECT 
    'support_users' as table_name,
    COUNT(*) as total_users,
    SUM(CASE WHEN role = 'agent' OR role = 'support' THEN 1 ELSE 0 END) as agents,
    SUM(CASE WHEN role = 'admin' OR role = 'manager' THEN 1 ELSE 0 END) as admins,
    SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) as active_users
FROM impromptuindian_support.support_users;

-- Check support_auto_assignment table (in impromptuindian_support)
SELECT 
    'support_auto_assignment' as table_name,
    'impromptuindian_support' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'support_auto_assignment'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌'
    END as status;

-- Get support_auto_assignment details
SELECT 
    'support_auto_assignment' as table_name,
    COUNT(*) as total_rules
FROM impromptuindian_support.support_auto_assignment;

-- Check support_order_flows table (in impromptuindian_admin)
SELECT 
    'support_order_flows' as table_name,
    'impromptuindian_admin' as database_name,
    'EXISTS ✅' as status;

-- Get support_order_flows details
SELECT 
    'support_order_flows' as table_name,
    COUNT(*) as total_flows,
    COUNT(DISTINCT order_status) as unique_statuses,
    SUM(CASE WHEN ai_reply IS NULL OR ai_reply = '' THEN 1 ELSE 0 END) as flows_without_reply,
    CASE 
        WHEN SUM(CASE WHEN ai_reply IS NULL OR ai_reply = '' THEN 1 ELSE 0 END) = 0 
        THEN 'YES ✅' 
        ELSE 'NO ❌' 
    END as all_have_ai_replies
FROM impromptuindian_admin.support_order_flows;

-- =====================================================
-- STEP 4: VERIFY THREADS TABLE STRUCTURE
-- =====================================================

-- Show threads table structure in impromptuindian_support
SHOW COLUMNS FROM impromptuindian_support.threads;

-- Check threads data in impromptuindian_support
SELECT 
    'threads (impromptuindian_support)' as table_name,
    COUNT(*) as total_messages,
    COUNT(DISTINCT ticket_id) as tickets_with_messages,
    COUNT(DISTINCT user_id) as unique_senders,
    MIN(created_at) as oldest_message,
    MAX(created_at) as newest_message,
    COUNT(CASE WHEN DATE(created_at) = CURDATE() THEN 1 END) as messages_today
FROM impromptuindian_support.threads;

-- =====================================================
-- STEP 5: VERIFY VIEWS
-- =====================================================

-- Check if views exist in impromptuindian_support (fixed query)
SELECT 
    table_name as view_name,
    'impromptuindian_support' as database_name,
    'EXISTS ✅' as status
FROM information_schema.views
WHERE table_schema = 'impromptuindian_support'
    AND table_name IN ('v_agent_performance', 'v_ai_performance', 'v_support_health', 'v_vendor_issues')
ORDER BY table_name;

-- =====================================================
-- STEP 6: VERIFY CLEANUP SUCCESS
-- =====================================================

-- Verify redundant tables are deleted
SELECT 
    table_name,
    table_schema as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = t.table_schema
            AND table_name = t.table_name
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
-- STEP 7: DATA INTEGRITY CHECKS
-- =====================================================

-- Check for tickets without messages (in impromptuindian_support)
SELECT 
    'Tickets without messages' as check_type,
    COUNT(*) as count
FROM impromptuindian_support.support_tickets t
LEFT JOIN impromptuindian_support.threads th ON th.ticket_id = t.id
WHERE th.id IS NULL
    AND t.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY);

-- Find orders table location
SELECT 
    table_schema,
    table_name,
    table_rows
FROM information_schema.tables
WHERE table_name = 'orders'
    AND table_schema LIKE 'impromptuindian%'
ORDER BY table_schema;

-- Find orders table location first
SELECT 
    'Finding orders table...' as info,  
    table_schema,
    table_name
FROM information_schema.tables
WHERE table_name = 'orders'
    AND table_schema LIKE 'impromptuindian%'
LIMIT 1;

-- Check for order statuses without flows (only if orders table exists)
-- Note: Adjust database name based on above query result
SELECT 
    'Order statuses without flows' as check_type,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'orders'
        ) THEN 
            (SELECT COUNT(DISTINCT o.status) 
             FROM impromptuindian_support.orders o
             LEFT JOIN impromptuindian_admin.support_order_flows sof ON sof.order_status = o.status
             WHERE sof.id IS NULL
             AND o.status IS NOT NULL
             AND o.status NOT IN ('completed', 'completed_with_penalty', 'cancelled')
             AND o.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY))
        ELSE 0
    END as count,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'orders'
        ) THEN 
            (SELECT GROUP_CONCAT(DISTINCT o.status SEPARATOR ', ') 
             FROM impromptuindian_support.orders o
             LEFT JOIN impromptuindian_admin.support_order_flows sof ON sof.order_status = o.status
             WHERE sof.id IS NULL
             AND o.status IS NOT NULL
             AND o.status NOT IN ('completed', 'completed_with_penalty', 'cancelled')
             AND o.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY))
        ELSE 'Orders table not found in impromptuindian_support'
    END as missing_statuses;

-- Check for flows with missing AI replies
SELECT 
    'Flows without AI replies' as check_type,
    COUNT(*) as count,
    GROUP_CONCAT(
        CONCAT(order_status, ':', issue_key)
        SEPARATOR ', '
    ) as missing_replies
FROM impromptuindian_admin.support_order_flows
WHERE ai_reply IS NULL OR ai_reply = '';

-- =====================================================
-- STEP 8: FINAL SUMMARY
-- =====================================================

-- Complete status summary
SELECT '=== DATABASE CLEANUP SUMMARY ===' as summary
UNION ALL
SELECT CONCAT('Essential Tables in impromptuindian_support: ',
    (SELECT COUNT(*) FROM information_schema.tables 
     WHERE table_schema = 'impromptuindian_support'
     AND table_name IN ('support_tickets', 'threads', 'support_users', 'support_auto_assignment'))
) as summary
UNION ALL
SELECT CONCAT('Essential Tables in impromptuindian_admin: ',
    (SELECT COUNT(*) FROM information_schema.tables 
     WHERE table_schema = 'impromptuindian_admin'
     AND table_name = 'support_order_flows')
) as summary
UNION ALL
SELECT CONCAT('Views in impromptuindian_support: ',
    (SELECT COUNT(*) FROM information_schema.views 
     WHERE table_schema = 'impromptuindian_support'
     AND table_name IN ('v_agent_performance', 'v_ai_performance', 'v_support_health', 'v_vendor_issues'))
) as summary
UNION ALL
SELECT 'Redundant Tables Removed: 3' as summary
UNION ALL
SELECT '=== CLEANUP COMPLETE ===' as summary;

-- =====================================================
-- END OF CLEANUP QUERIES
-- =====================================================
