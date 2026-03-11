-- =====================================================
-- IMPROMPTUINDIAN SUPPORT DATABASE VERIFICATION (SAFE)
-- =====================================================
-- Purpose: Verify all essential tables are working correctly (NO WRONG DB ASSUMPTIONS)
--
-- ✅ Correct database split (based on your diagnostic):
-- - impromptuindian_admin:   support_order_flows
-- - impromptuindian_support: support_tickets, threads, support_users, support_auto_assignment, views v_*
--
-- Notes:
-- - This script avoids referencing non-existent tables/columns.
-- - For any query that depends on an optional table (like orders), we first locate it.
-- =====================================================

-- =====================================================
-- 0) QUICK MAP: WHERE TABLES LIVE
-- =====================================================
SELECT
  table_schema,
  table_name,
  table_rows
FROM information_schema.tables
WHERE table_schema IN ('impromptuindian_admin', 'impromptuindian_support')
  AND table_name IN (
    'support_order_flows',
    'support_tickets',
    'threads',
    'support_users',
    'support_auto_assignment',
    'orders'
  )
ORDER BY table_schema, table_name;

-- =====================================================
-- 1) VERIFY SUPPORT_ORDER_FLOWS (Primary AI Source) - ADMIN DB
-- =====================================================
SELECT
  order_status,
  COUNT(*) AS flow_count,
  GROUP_CONCAT(CONCAT(issue_key, ' (', LEFT(issue_title, 60), ')') SEPARATOR ' | ') AS available_flows
FROM impromptuindian_admin.support_order_flows
GROUP BY order_status
ORDER BY order_status;

SELECT
  id,
  order_status,
  issue_key,
  issue_title,
  CASE
    WHEN ai_reply IS NULL THEN 'NULL'
    WHEN ai_reply = '' THEN 'EMPTY'
    ELSE 'OK'
  END AS reply_status,
  LENGTH(ai_reply) AS reply_length,
  auto_resolve,
  escalate_if_selected
FROM impromptuindian_admin.support_order_flows
WHERE ai_reply IS NULL OR ai_reply = ''
ORDER BY order_status, issue_key;

-- =====================================================
-- 2) VERIFY THREADS TABLE (Message Storage) - SUPPORT DB
-- =====================================================
SELECT
  'Total Messages' AS metric,
  COUNT(*) AS value
FROM impromptuindian_support.threads
UNION ALL
SELECT
  'Tickets with Messages' AS metric,
  COUNT(DISTINCT ticket_id) AS value
FROM impromptuindian_support.threads
UNION ALL
SELECT
  'Unique Senders' AS metric,
  COUNT(DISTINCT user_id) AS value
FROM impromptuindian_support.threads
UNION ALL
SELECT
  'Messages Today' AS metric,
  COUNT(*) AS value
FROM impromptuindian_support.threads
WHERE DATE(created_at) = CURDATE()
UNION ALL
SELECT
  'Messages This Week' AS metric,
  COUNT(*) AS value
FROM impromptuindian_support.threads
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
UNION ALL
SELECT
  'Messages This Month' AS metric,
  COUNT(*) AS value
FROM impromptuindian_support.threads
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY);

-- Recent messages activity
SELECT
  th.id,
  th.ticket_id,
  t.ticket_number,
  LEFT(th.content, 80) AS message_preview,
  th.user_id,
  th.created_at,
  TIMESTAMPDIFF(MINUTE, th.created_at, NOW()) AS minutes_ago
FROM impromptuindian_support.threads th
JOIN impromptuindian_support.support_tickets t ON t.id = th.ticket_id
ORDER BY th.created_at DESC
LIMIT 20;

-- Message count per ticket (last 7 days)
SELECT
  t.ticket_number,
  t.subject,
  t.status,
  COUNT(th.id) AS message_count,
  MAX(th.created_at) AS last_message_at,
  TIMESTAMPDIFF(HOUR, MAX(th.created_at), NOW()) AS hours_since_last_message
FROM impromptuindian_support.support_tickets t
LEFT JOIN impromptuindian_support.threads th ON th.ticket_id = t.id
WHERE t.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY t.id, t.ticket_number, t.subject, t.status
ORDER BY last_message_at DESC;

-- =====================================================
-- 3) VERIFY SUPPORT_TICKETS TABLE - SUPPORT DB
-- =====================================================
SELECT
  status,
  COUNT(*) AS count,
  ROUND(COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM impromptuindian_support.support_tickets), 0), 2) AS percentage,
  ROUND(AVG(TIMESTAMPDIFF(HOUR, created_at, COALESCE(resolved_at, NOW()))), 2) AS avg_hours_open
FROM impromptuindian_support.support_tickets
GROUP BY status
ORDER BY count DESC;

SELECT
  priority,
  COUNT(*) AS count,
  ROUND(AVG(TIMESTAMPDIFF(HOUR, created_at, COALESCE(resolved_at, NOW()))), 2) AS avg_hours_open,
  MIN(created_at) AS oldest_ticket,
  MAX(created_at) AS newest_ticket
FROM impromptuindian_support.support_tickets
GROUP BY priority
ORDER BY
  CASE priority
    WHEN 'high' THEN 1
    WHEN 'medium' THEN 2
    WHEN 'low' THEN 3
    ELSE 4
  END;

-- Tickets without assigned support user (column is assigned_to in your model)
SELECT
  id,
  ticket_number,
  subject,
  status,
  priority,
  assigned_to,
  created_at,
  TIMESTAMPDIFF(HOUR, created_at, NOW()) AS hours_since_creation
FROM impromptuindian_support.support_tickets
WHERE status = 'open'
  AND assigned_to IS NULL
  AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
ORDER BY created_at DESC;

-- =====================================================
-- 4) VERIFY SUPPORT_USERS TABLE (Agents) - SUPPORT DB
-- =====================================================
-- Note: column is `name` (not username) in your model/table.
SELECT
  id,
  name,
  email,
  role,
  is_active,
  created_at,
  last_login_at,
  TIMESTAMPDIFF(DAY, COALESCE(last_login_at, created_at), NOW()) AS days_since_last_login
FROM impromptuindian_support.support_users
ORDER BY is_active DESC, role, name;

-- Support user assignment stats (uses assigned_to on support_tickets)
SELECT
  su.id,
  su.name,
  su.role,
  su.is_active,
  COUNT(DISTINCT st.id) AS assigned_tickets,
  COUNT(DISTINCT CASE WHEN st.status = 'open' THEN st.id END) AS open_tickets,
  COUNT(DISTINCT CASE WHEN st.status = 'assigned' THEN st.id END) AS assigned_tickets_count,
  COUNT(DISTINCT CASE WHEN st.status = 'resolved' THEN st.id END) AS resolved_tickets,
  ROUND(AVG(TIMESTAMPDIFF(MINUTE, st.created_at, st.first_response_at)), 2) AS avg_first_response_minutes
FROM impromptuindian_support.support_users su
LEFT JOIN impromptuindian_support.support_tickets st ON st.assigned_to = su.id
GROUP BY su.id, su.name, su.role, su.is_active
ORDER BY assigned_tickets DESC, su.name;

-- =====================================================
-- 5) VERIFY SUPPORT_AUTO_ASSIGNMENT TABLE - SUPPORT DB
-- =====================================================
-- Note: column is `is_enabled` in your model/table (not is_active).
SELECT
  id,
  assignment_method,
  is_enabled,
  created_at,
  updated_at,
  CASE WHEN is_enabled = 1 THEN 'ENABLED ✅' ELSE 'DISABLED ❌' END AS status
FROM impromptuindian_support.support_auto_assignment
ORDER BY is_enabled DESC, id;

-- =====================================================
-- 6) VERIFY VIEWS (Performance Metrics) - SUPPORT DB
-- =====================================================
-- First list which of the expected views exist:
SELECT
  table_name AS view_name,
  'EXISTS ✅' AS status
FROM information_schema.views
WHERE table_schema = 'impromptuindian_support'
  AND table_name IN ('v_agent_performance', 'v_ai_performance', 'v_support_health', 'v_vendor_issues')
ORDER BY table_name;

-- If the views exist, these will work:
-- SELECT 'v_agent_performance' AS view_name, COUNT(*) AS row_count FROM impromptuindian_support.v_agent_performance;
-- SELECT * FROM impromptuindian_support.v_agent_performance ORDER BY total_tickets DESC LIMIT 10;
-- SELECT 'v_ai_performance' AS view_name, COUNT(*) AS row_count FROM impromptuindian_support.v_ai_performance;
-- SELECT 'v_support_health' AS view_name, COUNT(*) AS row_count FROM impromptuindian_support.v_support_health;
-- SELECT * FROM impromptuindian_support.v_support_health;
-- SELECT 'v_vendor_issues' AS view_name, COUNT(*) AS row_count FROM impromptuindian_support.v_vendor_issues;
-- SELECT * FROM impromptuindian_support.v_vendor_issues ORDER BY issue_count DESC LIMIT 10;

-- =====================================================
-- 7) DATA INTEGRITY CHECKS - SUPPORT DB
-- =====================================================
-- Orphaned threads: threads.ticket_id exists but ticket missing
SELECT
  'Orphaned threads' AS check_type,
  COUNT(*) AS count
FROM impromptuindian_support.threads th
LEFT JOIN impromptuindian_support.support_tickets t ON t.id = th.ticket_id
WHERE th.ticket_id IS NOT NULL
  AND t.id IS NULL;

-- Tickets with messages but no first response recorded (possible bug)
SELECT
  'Tickets without first response' AS check_type,
  COUNT(DISTINCT t.id) AS count
FROM impromptuindian_support.support_tickets t
JOIN impromptuindian_support.threads th ON th.ticket_id = t.id
WHERE t.status != 'resolved'
  AND t.first_response_at IS NULL
  AND th.created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR);

-- =====================================================
-- 8) ORDER STATUS FLOW COVERAGE (optional)
-- =====================================================
-- Your earlier diagnostic showed impromptuindian_support.orders does NOT exist.
-- Use this locator to find where `orders` actually lives:
SELECT
  table_schema,
  table_name,
  table_rows
FROM information_schema.tables
WHERE table_name = 'orders'
  AND table_schema LIKE 'impromptuindian%'
ORDER BY table_schema;

-- After you find the correct DB for orders (example: impromptuindian_admin.orders),
-- run this by replacing <ORDERS_DB>:
-- SELECT
--   'Order statuses needing flows' AS check_type,
--   COUNT(DISTINCT o.status) AS count,
--   GROUP_CONCAT(DISTINCT o.status SEPARATOR ', ') AS missing_statuses
-- FROM <ORDERS_DB>.orders o
-- LEFT JOIN impromptuindian_admin.support_order_flows sof ON sof.order_status = o.status
-- WHERE sof.id IS NULL
--   AND o.status IS NOT NULL
--   AND o.status NOT IN ('completed', 'completed_with_penalty', 'cancelled')
--   AND o.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY);

-- =====================================================
-- 9) REAL-TIME VERIFICATION - SUPPORT DB
-- =====================================================
SELECT
  'Threads table activity' AS check_type,
  COUNT(*) AS messages_last_hour,
  COUNT(DISTINCT ticket_id) AS active_tickets,
  MAX(created_at) AS last_message_time,
  TIMESTAMPDIFF(MINUTE, MAX(created_at), NOW()) AS minutes_since_last_message
FROM impromptuindian_support.threads
WHERE created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR);

SELECT
  DATE(t.created_at) AS date,
  COUNT(DISTINCT t.id) AS tickets_created,
  COUNT(DISTINCT th.id) AS messages_sent,
  ROUND(COUNT(DISTINCT th.id) / NULLIF(COUNT(DISTINCT t.id), 0), 2) AS avg_messages_per_ticket
FROM impromptuindian_support.support_tickets t
LEFT JOIN impromptuindian_support.threads th ON th.ticket_id = t.id
WHERE t.created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY DATE(t.created_at)
ORDER BY date DESC;

