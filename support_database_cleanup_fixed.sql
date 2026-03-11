-- =====================================================
-- IMPROMPTUINDIAN SUPPORT DATABASE CLEANUP (FIXED)
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

-- Check if redundant tables exist (both databases)
SELECT 
    'escalation_rules' as table_name,
    'impromptuindian_admin' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'escalation_rules'
        ) THEN 
            (SELECT COUNT(*) FROM impromptuindian_admin.escalation_rules)
        ELSE 0
    END as row_count,
    'Duplicate of support_escalation_rules' as reason
UNION ALL
SELECT 
    'support_ai_intents' as table_name,
    'impromptuindian_admin' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_ai_intents'
        ) THEN 
            (SELECT COUNT(*) FROM impromptuindian_admin.support_ai_intents)
        ELSE 0
    END as row_count,
    'Not used - using support_order_flows instead' as reason
UNION ALL
SELECT 
    'support_ticket_categories' as table_name,
    'impromptuindian_admin' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_ticket_categories'
        ) THEN 
            (SELECT COUNT(*) FROM impromptuindian_admin.support_ticket_categories)
        ELSE 0
    END as row_count,
    'Empty and unused' as reason;

-- =====================================================
-- STEP 2: REMOVE REDUNDANT TABLES
-- =====================================================

-- Drop escalation_rules (duplicate of support_escalation_rules)
DROP TABLE IF EXISTS impromptuindian_admin.escalation_rules;

-- Drop support_ai_intents (not used - using support_order_flows instead)
DROP TABLE IF EXISTS impromptuindian_admin.support_ai_intents;

-- Drop support_ticket_categories (empty and unused)
DROP TABLE IF EXISTS impromptuindian_admin.support_ticket_categories;

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
    END as status,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'support_tickets'
        ) THEN 
            (SELECT CONCAT(
                'Total: ', COUNT(*),
                ', Open: ', SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END),
                ', Assigned: ', SUM(CASE WHEN status = 'assigned' THEN 1 ELSE 0 END)
            ) FROM impromptuindian_support.support_tickets)
        ELSE 'N/A'
    END as details
UNION ALL
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
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'threads'
            AND EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'impromptuindian_support'
                AND table_name = 'threads'
                AND column_name = 'ticket_id'
            )
        ) THEN 
            (SELECT CONCAT(
                'Total Messages: ', COUNT(*),
                ', Tickets with Messages: ', COUNT(DISTINCT ticket_id),
                ', Messages Today: ', SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END)
            ) FROM impromptuindian_support.threads)
        ELSE 'N/A'
    END as details
UNION ALL
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
    END as status,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'support_users'
        ) THEN 
            (SELECT CONCAT(
                'Total: ', COUNT(*),
                ', Agents: ', SUM(CASE WHEN role = 'agent' THEN 1 ELSE 0 END),
                ', Active: ', SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END)
            ) FROM impromptuindian_support.support_users)
        ELSE 'N/A'
    END as details
UNION ALL
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
    END as status,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'support_auto_assignment'
        ) THEN 
            (SELECT CONCAT(
                'Rules: ', COUNT(*),
                ', Active: ', SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END)
            ) FROM impromptuindian_support.support_auto_assignment)
        ELSE 'N/A'
    END as details
UNION ALL
-- Check support_order_flows table (in impromptuindian_admin)
SELECT 
    'support_order_flows' as table_name,
    'impromptuindian_admin' as database_name,
    'EXISTS ✅' as status,
    CONCAT(
        'Total Flows: ', COUNT(*),
        ', Statuses: ', COUNT(DISTINCT order_status),
        ', All have AI replies: ', CASE WHEN SUM(CASE WHEN ai_reply IS NULL OR ai_reply = '' THEN 1 ELSE 0 END) = 0 THEN 'YES ✅' ELSE 'NO ❌' END
    ) as details
FROM impromptuindian_admin.support_order_flows;

-- =====================================================
-- STEP 4: VERIFY THREADS TABLE STRUCTURE
-- =====================================================

-- Check threads table in impromptuindian_support (the correct one)
SELECT 
    'impromptuindian_support.threads' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'threads'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌'
    END as table_exists,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema = 'impromptuindian_support'
            AND table_name = 'threads'
            AND column_name = 'ticket_id'
        ) THEN 'HAS ticket_id COLUMN ✅'
        ELSE 'MISSING ticket_id COLUMN ❌'
    END as has_ticket_id;

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

-- Check if views exist in impromptuindian_support
SELECT 
    table_name as view_name,
    'impromptuindian_support' as database_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.views
            WHERE table_schema = 'impromptuindian_support'
            AND table_name = v.view_name
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌'
    END as status
FROM (
    SELECT 'v_agent_performance' as view_name
    UNION ALL SELECT 'v_ai_performance'
    UNION ALL SELECT 'v_support_health'
    UNION ALL SELECT 'v_vendor_issues'
) v;

-- =====================================================
-- STEP 6: VERIFY CLEANUP SUCCESS
-- =====================================================

-- Verify redundant tables are deleted
SELECT 
    table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = t.table_name
        ) THEN 'STILL EXISTS ❌'
        ELSE 'DELETED ✅'
    END as status
FROM (
    SELECT 'escalation_rules' as table_name
    UNION ALL SELECT 'support_ai_intents'
    UNION ALL SELECT 'support_ticket_categories'
) t;

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

-- Check for order statuses without flows
-- First check which database has orders table
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
             AND o.status NOT IN ('completed', 'completed_with_penalty', 'cancelled'))
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
             AND o.status NOT IN ('completed', 'completed_with_penalty', 'cancelled'))
        ELSE 'Orders table not found'
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
