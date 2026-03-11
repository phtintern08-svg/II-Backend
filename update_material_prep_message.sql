-- =====================================================
-- UPDATE MATERIAL PREP MESSAGE
-- =====================================================
-- Purpose: Fix "1224 hours" to "12 - 24 hours" in the AI reply
-- Database: impromptuindian_admin
-- =====================================================

-- Update the material_prep production_delay message
UPDATE impromptuindian_admin.support_order_flows
SET ai_reply = 'We are sourcing high-quality materials for your order. This stage typically takes 12 - 24 hours.',
    updated_at = CURRENT_TIMESTAMP
WHERE order_status = 'material_prep' 
  AND issue_key = 'production_delay';

-- Verify the update
SELECT 
    order_status,
    issue_key,
    issue_title,
    ai_reply,
    updated_at
FROM impromptuindian_admin.support_order_flows
WHERE order_status = 'material_prep' 
  AND issue_key = 'production_delay';

-- =====================================================
-- END OF UPDATE QUERY
-- =====================================================
