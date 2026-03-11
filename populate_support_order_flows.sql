-- =====================================================
-- POPULATE SUPPORT_ORDER_FLOWS TABLE
-- =====================================================
-- Purpose: Insert Flipkart-style status-based support questions
-- Database: impromptuindian_admin
-- 
-- This makes your support system 100% database-driven:
-- - Add new questions by inserting rows (no code changes needed)
-- - Change AI responses by updating rows (no server restart needed)
-- - Remove questions by deleting rows
-- =====================================================

USE impromptuindian_admin;

-- Option 1: Clear existing data and insert fresh (RECOMMENDED for clean setup)
-- Uncomment the line below if you want to start fresh
-- TRUNCATE TABLE support_order_flows;

-- Option 2: Update existing rows or insert new ones (SAFE - No duplicate errors)
-- This script uses INSERT ... ON DUPLICATE KEY UPDATE
-- - If row exists: Updates it with new values
-- - If row doesn't exist: Inserts it
-- You can run this script multiple times without errors!

-- =====================================================
-- INSERT FLIPKART-STYLE SUPPORT QUESTIONS
-- =====================================================

-- pending_admin_review status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('pending_admin_review', 'when_confirmed', 'When will my order be confirmed?', 'Our team is reviewing your design. Confirmation usually takes 2-4 hours. You\'ll receive an email notification once it\'s confirmed.', 1, 0),
('pending_admin_review', 'cancel_order', 'Cancel my order', 'I can help with that. Connecting you to a cancellation specialist who will process your request.', 0, 1),
('pending_admin_review', 'modify_design', 'I want to modify my design', 'I understand you\'d like to make changes. Let me connect you with our design team who can assist with modifications.', 0, 1)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- vendor_assigned status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('vendor_assigned', 'vendor_info', 'Who is my vendor?', 'Your order has been assigned to a verified vendor. You can view vendor details in your order page.', 1, 0),
('vendor_assigned', 'start_production', 'When will production start?', 'Production typically begins within 24-48 hours after vendor assignment. You\'ll receive updates as production progresses.', 1, 0)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- material_prep status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('material_prep', 'print_time', 'How much longer will printing take?', 'We\'re currently preparing materials for your order. Printing involves multi-stage processing and quality checks. Expect another 24-48 hours before printing begins.', 1, 0),
('material_prep', 'change_specifications', 'Change order specifications', 'I understand you need to change specifications. Let me connect you with our production team who can assist with modifications.', 0, 1)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- printing status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('printing', 'print_time', 'How much longer will printing take?', 'Printing is currently in progress. We ensure every detail is perfect! This typically takes 1-2 days depending on your order size.', 1, 0),
('printing', 'quality_concern', 'I have quality concerns', 'I understand your concern. Our quality control team monitors every step. Let me connect you with a specialist who can address your concerns.', 0, 1)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- printing_completed status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('printing_completed', 'next_steps', 'What happens after printing?', 'Great news! Your order has completed printing. It\'s now undergoing quality checks and will be packed for dispatch soon.', 1, 0),
('printing_completed', 'quality_issue', 'I want to report a quality issue', 'I\'m sorry to hear that. Let me connect you with our quality assurance team who will investigate and resolve this immediately.', 0, 1)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- quality_check status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('quality_check', 'quality_time', 'Why quality check required?', 'Quality checks ensure your order meets our high standards. This typically takes 4-6 hours. Your order will be dispatched once approved.', 1, 0),
('quality_check', 'quality_issue', 'I want to report a quality issue', 'I\'m sorry to hear that. Let me connect you with our quality assurance team who will investigate and resolve this immediately.', 0, 1)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- packed_ready status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('packed_ready', 'dispatch_time', 'When will order ship?', 'Your order is packed and ready! It will be dispatched within 24 hours. You\'ll receive tracking details via email once it ships.', 1, 0),
('packed_ready', 'change_address', 'Change delivery address', 'I can help update your delivery address. Let me connect you with our logistics team who can make this change.', 0, 1)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- rider_assigned status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('rider_assigned', 'track_order', 'Track my order', 'Your order has been assigned to a delivery rider. You can view live tracking in the "My Orders" tab. The rider will reach you soon!', 1, 0),
('rider_assigned', 'change_address', 'Change delivery address', 'I can help update your delivery address. Let me connect you with our logistics team who can make this change before delivery.', 0, 1)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- picked_up status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('picked_up', 'track_live', 'Track my order', 'Your order is with our rider and on the way! You can view live tracking in the "My Orders" tab. Estimated delivery time will be shown there.', 1, 0),
('picked_up', 'delivery_delay', 'Delivery delayed', 'I apologize for any delay. Our rider is navigating traffic. You can track their live location in your orders page.', 1, 0)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- out_for_delivery status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('out_for_delivery', 'track_live', 'Track my order', 'Your order is out for delivery! You can view live tracking in the "My Orders" tab. The rider should reach you shortly.', 1, 0),
('out_for_delivery', 'delay_warn', 'Delivery delayed', 'I apologize for the delay. Let me check with the delivery team and connect you to the delivery manager if needed.', 0, 1)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- delivered status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('delivered', 'not_rec', 'I haven\'t received the items', 'I\'m sorry to hear that. Let me check with the delivery team immediately. Connecting you to our delivery dispute team who will resolve this.', 0, 1),
('delivered', 'damaged', 'Items are damaged/missing', 'We are very sorry! Please upload a photo of the damaged items, and I will immediately initiate a replacement or refund process.', 0, 1),
('delivered', 'return_request', 'I want to return this order', 'I can help with your return request. Let me connect you with our returns team who will guide you through the process.', 0, 1)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- completed status
INSERT INTO support_order_flows (order_status, issue_key, issue_title, ai_reply, auto_resolve, escalate_if_selected) VALUES
('completed', 'refund_request', 'I want a refund', 'I can help with your refund request. Let me connect you with our refunds team who will process your request according to our policy.', 0, 1),
('completed', 'rating_feedback', 'How to rate my order?', 'Thank you for your order! You can rate and review your order from the "My Orders" page. Your feedback helps us improve!', 1, 0)
ON DUPLICATE KEY UPDATE
    issue_title = VALUES(issue_title),
    ai_reply = VALUES(ai_reply),
    auto_resolve = VALUES(auto_resolve),
    escalate_if_selected = VALUES(escalate_if_selected),
    updated_at = CURRENT_TIMESTAMP;

-- =====================================================
-- VERIFICATION QUERIES
-- =====================================================

-- Check total flows inserted
SELECT 
    'Total Flows' as metric,
    COUNT(*) as value
FROM support_order_flows;

-- Check flows by order status
SELECT 
    order_status,
    COUNT(*) as flow_count,
    GROUP_CONCAT(issue_key SEPARATOR ', ') as available_issues
FROM support_order_flows
GROUP BY order_status
ORDER BY order_status;

-- Check for flows with missing AI replies
SELECT 
    'Flows without AI replies' as check_type,
    COUNT(*) as count,
    GROUP_CONCAT(CONCAT(order_status, ':', issue_key) SEPARATOR ', ') as missing_replies
FROM support_order_flows
WHERE ai_reply IS NULL OR ai_reply = '';

-- =====================================================
-- END OF POPULATION SCRIPT
-- =====================================================
-- 
-- NEXT STEPS:
-- 1. ✅ Run this script to populate support_order_flows
-- 2. ✅ Verify all flows are inserted correctly
-- 3. ✅ Test the support chat to see Flipkart-style buttons
-- 4. ✅ Add more questions by inserting new rows (no code changes needed!)
-- =====================================================
