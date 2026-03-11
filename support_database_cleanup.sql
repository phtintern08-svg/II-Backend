-- =====================================================
-- IMPROMPTUINDIAN SUPPORT DATABASE CLEANUP
-- =====================================================
-- Purpose: Remove redundant tables and verify essential tables
-- Database: impromptuindian_admin
-- 
-- ⚠️ IMPORTANT: Backup your database before running DROP statements!
-- =====================================================

-- =====================================================
-- STEP 1: VERIFY REDUNDANT TABLES BEFORE DELETION
-- =====================================================

-- Check if redundant tables exist and their row counts (Fixed - handles non-existent tables)
SELECT 
    'escalation_rules' as table_name,
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
-- STEP 2: CREATE BACKUP TABLES (Optional Safety)
-- =====================================================

-- Backup escalation_rules before deletion
CREATE TABLE IF NOT EXISTS impromptuindian_admin.escalation_rules_backup_2026 AS 
SELECT * FROM impromptuindian_admin.escalation_rules
WHERE EXISTS (
    SELECT 1 FROM information_schema.tables 
    WHERE table_schema = 'impromptuindian_admin' 
    AND table_name = 'escalation_rules'
);

-- Backup support_ai_intents before deletion
CREATE TABLE IF NOT EXISTS impromptuindian_admin.support_ai_intents_backup_2026 AS 
SELECT * FROM impromptuindian_admin.support_ai_intents
WHERE EXISTS (
    SELECT 1 FROM information_schema.tables 
    WHERE table_schema = 'impromptuindian_admin' 
    AND table_name = 'support_ai_intents'
);

-- Backup support_ticket_categories before deletion
CREATE TABLE IF NOT EXISTS impromptuindian_admin.support_ticket_categories_backup_2026 AS 
SELECT * FROM impromptuindian_admin.support_ticket_categories
WHERE EXISTS (
    SELECT 1 FROM information_schema.tables 
    WHERE table_schema = 'impromptuindian_admin' 
    AND table_name = 'support_ticket_categories'
);

-- =====================================================
-- STEP 3: REMOVE REDUNDANT TABLES
-- =====================================================

-- Drop escalation_rules (duplicate of support_escalation_rules)
DROP TABLE IF EXISTS impromptuindian_admin.escalation_rules;

-- Drop support_ai_intents (not used - using support_order_flows instead)
DROP TABLE IF EXISTS impromptuindian_admin.support_ai_intents;

-- Drop support_ticket_categories (empty and unused)
DROP TABLE IF EXISTS impromptuindian_admin.support_ticket_categories;

-- =====================================================
-- STEP 4: VERIFY ESSENTIAL TABLES STATUS
-- =====================================================

-- Check support_tickets table (check if exists first)
SELECT 
    'support_tickets' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_tickets'
        ) THEN 
            (SELECT CONCAT(
                'EXISTS - Total: ', COUNT(*),
                ', Open: ', SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END)
            ) FROM impromptuindian_admin.support_tickets)
        ELSE 'MISSING - Table does not exist'
    END as status;

-- Check threads table (should have messages)
-- First check if table exists and get column names
SELECT 
    'threads' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'threads'
        ) THEN 'EXISTS'
        ELSE 'MISSING'
    END as table_status;

-- Show threads table structure
SHOW COLUMNS FROM impromptuindian_admin.threads;

-- Check threads data (adjust column names based on actual structure)
-- Common column names: ticket_id, support_ticket_id, thread_ticket_id
SELECT 
    'threads' as table_name,
    COUNT(*) as total_messages,
    MIN(created_at) as oldest_message,
    MAX(created_at) as newest_message,
    COUNT(CASE WHEN DATE(created_at) = CURDATE() THEN 1 END) as messages_today
FROM impromptuindian_admin.threads;

-- Check support_users table (check if exists first)
SELECT 
    'support_users' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_users'
        ) THEN 
            (SELECT CONCAT(
                'EXISTS - Total: ', COUNT(*),
                ', Agents: ', SUM(CASE WHEN role = 'agent' THEN 1 ELSE 0 END)
            ) FROM impromptuindian_admin.support_users)
        ELSE 'MISSING - Table does not exist'
    END as status;

-- Check support_order_flows table (primary source for AI responses)
SELECT 
    'support_order_flows' as table_name,
    COUNT(*) as total_flows,
    COUNT(DISTINCT order_status) as unique_statuses,
    COUNT(CASE WHEN ai_reply IS NULL OR ai_reply = '' THEN 1 END) as flows_without_reply,
    MIN(created_at) as oldest_flow,
    MAX(updated_at) as last_updated
FROM impromptuindian_admin.support_order_flows;

-- Check support_auto_assignment table (check if exists first)
SELECT 
    'support_auto_assignment' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_auto_assignment'
        ) THEN 
            (SELECT CONCAT(
                'EXISTS - Rules: ', COUNT(*),
                ', Active: ', SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END)
            ) FROM impromptuindian_admin.support_auto_assignment)
        ELSE 'MISSING - Table does not exist'
    END as status;

-- =====================================================
-- STEP 5: VERIFY VIEWS EXIST
-- =====================================================

-- Check if views exist (fixed query)
SELECT 
    table_name as view_name,
    view_definition
FROM information_schema.views
WHERE table_schema = 'impromptuindian_admin'
    AND table_name IN (
        'v_agent_performance',
        'v_ai_performance',
        'v_support_health',
        'v_vendor_issues'
    )
ORDER BY table_name;

-- Test views (if they exist)
SELECT 'v_agent_performance' as view_name, COUNT(*) as row_count 
FROM impromptuindian_admin.v_agent_performance
UNION ALL
SELECT 'v_ai_performance' as view_name, COUNT(*) as row_count 
FROM impromptuindian_admin.v_ai_performance
UNION ALL
SELECT 'v_support_health' as view_name, COUNT(*) as row_count 
FROM impromptuindian_admin.v_support_health
UNION ALL
SELECT 'v_vendor_issues' as view_name, COUNT(*) as row_count 
FROM impromptuindian_admin.v_vendor_issues;

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

-- List all remaining support-related tables
SELECT 
    table_name,
    table_rows,
    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb,
    CASE 
        WHEN table_name IN (
            'support_tickets', 'threads', 'support_users', 
            'support_order_flows', 'support_auto_assignment'
        ) THEN 'ESSENTIAL ✅'
        WHEN table_name LIKE 'v_%' THEN 'VIEW ✅'
        WHEN table_name LIKE '%_backup%' THEN 'BACKUP ✅'
        ELSE 'OTHER'
    END as table_type
FROM information_schema.tables
WHERE table_schema = 'impromptuindian_admin'
    AND (
        table_name LIKE 'support%' 
        OR table_name = 'threads'
        OR table_name LIKE 'v_%'
    )
ORDER BY table_type, table_name;

-- =====================================================
-- STEP 7: DATA INTEGRITY CHECKS
-- =====================================================

-- Check for tickets without messages (only if support_tickets exists)
SELECT 
    'Tickets without messages' as check_type,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_tickets'
        ) THEN 
            (SELECT COUNT(*) FROM impromptuindian_admin.support_tickets t
             LEFT JOIN impromptuindian_admin.threads th ON th.ticket_id = t.id
             WHERE th.id IS NULL
             AND t.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY))
        ELSE 0
    END as count;

-- Check for order statuses without flows (check if orders table exists)
SELECT 
    'Order statuses without flows' as check_type,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_support' 
            AND table_name = 'orders'
        ) THEN 
            (SELECT COUNT(DISTINCT o.status) FROM impromptuindian_support.orders o
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
            (SELECT GROUP_CONCAT(DISTINCT o.status SEPARATOR ', ') FROM impromptuindian_support.orders o
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
SELECT 
    '=== DATABASE CLEANUP SUMMARY ===' as summary
UNION ALL
SELECT CONCAT('Essential Tables: ', 
    (SELECT COUNT(*) FROM information_schema.tables 
     WHERE table_schema = 'impromptuindian_admin' 
     AND table_name IN ('support_tickets', 'threads', 'support_users', 'support_order_flows', 'support_auto_assignment'))
) as summary
UNION ALL
SELECT CONCAT('Views: ',
    (SELECT COUNT(*) FROM information_schema.views 
     WHERE table_schema = 'impromptuindian_admin' 
     AND table_name IN ('v_agent_performance', 'v_ai_performance', 'v_support_health', 'v_vendor_issues'))
) as summary
UNION ALL
SELECT CONCAT('Redundant Tables Removed: 3') as summary
UNION ALL
SELECT '=== CLEANUP COMPLETE ===' as summary;

-- =====================================================
-- END OF CLEANUP QUERIES
-- =====================================================
-- 
-- Next Steps:
-- 1. Review the verification results above
-- 2. Check that threads table is populating (see threads table status)
-- 3. Verify support_order_flows has all required order statuses
-- 4. Test the support system to ensure everything works
-- =====================================================
