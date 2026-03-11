-- =====================================================
-- IMPROMPTUINDIAN SUPPORT DATABASE DIAGNOSTIC
-- =====================================================
-- Purpose: Check what tables actually exist and their structure
-- Database: impromptuindian_admin
-- =====================================================

-- =====================================================
-- STEP 1: LIST ALL TABLES IN THE DATABASE
-- =====================================================

-- Show all tables in impromptuindian_admin
SELECT 
    table_name,
    table_rows,
    ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb,
    create_time,
    update_time
FROM information_schema.tables
WHERE table_schema = 'impromptuindian_admin'
ORDER BY table_name;

-- =====================================================
-- STEP 2: CHECK THREADS TABLE STRUCTURE
-- =====================================================

-- Check if threads table exists and show its structure
SELECT 
    'threads' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'threads'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌'
    END as status;

-- Show threads table columns (if it exists)
SELECT 
    column_name,
    data_type,
    is_nullable,
    column_default
FROM information_schema.columns
WHERE table_schema = 'impromptuindian_admin'
    AND table_name = 'threads'
ORDER BY ordinal_position;

-- Check threads table data (using correct column names)
-- First, let's see what columns actually exist
SHOW COLUMNS FROM impromptuindian_admin.threads;

-- =====================================================
-- STEP 3: CHECK MISSING ESSENTIAL TABLES
-- =====================================================

-- Check which essential tables are missing
SELECT 
    'support_tickets' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_tickets'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - NEEDS TO BE CREATED'
    END as status
UNION ALL
SELECT 
    'support_users' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_users'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - NEEDS TO BE CREATED'
    END as status
UNION ALL
SELECT 
    'support_auto_assignment' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_auto_assignment'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - NEEDS TO BE CREATED'
    END as status
UNION ALL
SELECT 
    'threads' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'threads'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - NEEDS TO BE CREATED'
    END as status
UNION ALL
SELECT 
    'support_order_flows' as table_name,
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'support_order_flows'
        ) THEN 'EXISTS ✅'
        ELSE 'MISSING ❌ - NEEDS TO BE CREATED'
    END as status;

-- =====================================================
-- STEP 4: CHECK SUPPORT_ORDER_FLOWS (This one exists!)
-- =====================================================

-- Verify support_order_flows structure
SHOW COLUMNS FROM impromptuindian_admin.support_order_flows;

-- Check support_order_flows data
SELECT 
    order_status,
    COUNT(*) as flow_count,
    GROUP_CONCAT(
        CONCAT(issue_key, ':', LEFT(issue_title, 30)) 
        SEPARATOR ' | '
    ) as flows_list
FROM impromptuindian_admin.support_order_flows
GROUP BY order_status
ORDER BY order_status;

-- =====================================================
-- STEP 5: CHECK VIEWS
-- =====================================================

-- List all views in the database
SELECT 
    table_name as view_name,
    view_definition
FROM information_schema.views
WHERE table_schema = 'impromptuindian_admin'
ORDER BY table_name;

-- =====================================================
-- STEP 6: CHECK THREADS TABLE DATA (Fixed Query)
-- =====================================================

-- First, get the actual column names
SELECT 
    column_name
FROM information_schema.columns
WHERE table_schema = 'impromptuindian_admin'
    AND table_name = 'threads'
ORDER BY ordinal_position;

-- Then check data using actual column names
-- (This will be different based on your actual schema)
-- Common column names: ticket_id, support_ticket_id, thread_ticket_id, etc.

-- Try common variations:
-- Option 1: If column is named 'support_ticket_id'
SELECT 
    'threads' as table_name,
    COUNT(*) as total_messages,
    COUNT(DISTINCT support_ticket_id) as tickets_with_messages
FROM impromptuindian_admin.threads;

-- Option 2: If column is named 'thread_ticket_id'
SELECT 
    'threads' as table_name,
    COUNT(*) as total_messages,
    COUNT(DISTINCT thread_ticket_id) as tickets_with_messages
FROM impromptuindian_admin.threads;

-- Option 3: If column is named 'ticket_id' (standard)
SELECT 
    'threads' as table_name,
    COUNT(*) as total_messages,
    COUNT(DISTINCT ticket_id) as tickets_with_messages
FROM impromptuindian_admin.threads;

-- =====================================================
-- STEP 7: FIND TABLES IN OTHER DATABASES
-- =====================================================

-- Check if support tables are in a different database
SELECT 
    table_schema,
    table_name,
    table_rows
FROM information_schema.tables
WHERE table_name IN (
    'support_tickets',
    'support_users',
    'support_auto_assignment',
    'threads',
    'support_order_flows'
)
ORDER BY table_schema, table_name;

-- =====================================================
-- STEP 8: SUMMARY
-- =====================================================

SELECT 
    '=== DATABASE DIAGNOSTIC SUMMARY ===' as summary
UNION ALL
SELECT CONCAT('Tables in impromptuindian_admin: ',
    (SELECT COUNT(*) FROM information_schema.tables 
     WHERE table_schema = 'impromptuindian_admin'))
) as summary
UNION ALL
SELECT CONCAT('support_order_flows rows: ',
    (SELECT COUNT(*) FROM impromptuindian_admin.support_order_flows))
) as summary
UNION ALL
SELECT CONCAT('threads table exists: ',
    CASE 
        WHEN EXISTS (
            SELECT 1 FROM information_schema.tables 
            WHERE table_schema = 'impromptuindian_admin' 
            AND table_name = 'threads'
        ) THEN 'YES'
        ELSE 'NO'
    END
) as summary
UNION ALL
SELECT '=== RUN SHOW COLUMNS TO CHECK STRUCTURE ===' as summary;

-- =====================================================
-- END OF DIAGNOSTIC QUERIES
-- =====================================================
