-- ============================================================================
-- ImpromptuIndian Support Database - Complete Table Creation Script
-- Database: impromptuindian_support
-- ============================================================================
-- Run this SQL script in phpMyAdmin or MySQL CLI to create all support tables
-- 
-- How to Run:
--   1. phpMyAdmin: Select database → SQL tab → Paste this script → Go
--   2. MySQL CLI: mysql -u impromptuindian -p impromptuindian_support < create_support_tables.sql
--   3. After running: Restart app (touch ~/backend/tmp/restart.txt)
-- ============================================================================
-- Tables Created (in dependency order):
--   1. support_users → Support agents (admin-managed credentials)
--   2. support_ticket_categories → Category configuration
--   3. support_tickets → Main ticket entity
--   4. threads → Conversations (messages/threads) - references tickets and categories
--   5. comments → Conversation messages (replies to threads)
--   6. support_priority_rules → SLA rules
--   7. support_escalation_rules → Escalation configuration
--   8. support_auto_assignment → Auto-assignment configuration
-- ============================================================================

USE impromptuindian_support;

-- ============================================================================
-- Table 1: support_users
-- Support agents managed by admin panel
-- ============================================================================
CREATE TABLE IF NOT EXISTS `support_users` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(120) NOT NULL,
    `password_hash` VARCHAR(255) NOT NULL,
    `phone` VARCHAR(20) NULL,
    `role` VARCHAR(50) NOT NULL DEFAULT 'support',
    `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
    `last_login_at` DATETIME NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `email` (`email`),
    UNIQUE KEY `phone` (`phone`),
    INDEX `idx_role` (`role`),
    INDEX `idx_is_active` (`is_active`),
    INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Table 2: support_ticket_categories
-- Category configuration (admin-managed)
-- Must be created before threads and support_tickets
-- ============================================================================
CREATE TABLE IF NOT EXISTS `support_ticket_categories` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(100) NOT NULL,
    `description` TEXT NULL,
    `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `name` (`name`),
    INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Table 3: support_tickets
-- Main ticket entity (production-ready version)
-- Must be created before threads (threads references this)
-- ============================================================================
CREATE TABLE IF NOT EXISTS `support_tickets` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `ticket_number` VARCHAR(20) NULL COMMENT 'Format: TCK-YYYY-NNNNN',
    
    `user_id` INT NOT NULL COMMENT 'ID of the user (customer/vendor/rider)',
    `user_type` ENUM('customer', 'vendor', 'rider') NOT NULL,
    
    `category_id` INT NULL COMMENT 'Reference to support_ticket_categories.id',
    `priority` VARCHAR(20) NOT NULL DEFAULT 'medium' COMMENT 'low, medium, high, critical',
    
    `subject` VARCHAR(255) NOT NULL,
    `description` TEXT NOT NULL,
    
    `status` ENUM('open', 'assigned', 'in_progress', 'escalated', 'resolved', 'closed') 
        NOT NULL DEFAULT 'open',
    
    `assigned_to` INT NULL COMMENT 'Reference to support_users.id',
    
    `sla_deadline` DATETIME NULL COMMENT 'SLA deadline for resolution',
    
    `attachment_image` LONGBLOB NULL COMMENT 'Legacy - consider moving to separate table',
    `attachment_filename` VARCHAR(255) NULL,
    
    `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `resolved_at` DATETIME NULL,
    
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_ticket_number` (`ticket_number`),
    INDEX `idx_status` (`status`),
    INDEX `idx_assigned_to` (`assigned_to`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_user_type` (`user_type`),
    INDEX `idx_category_id` (`category_id`),
    INDEX `idx_priority` (`priority`),
    INDEX `idx_sla_deadline` (`sla_deadline`),
    INDEX `idx_created_at` (`created_at`),
    
    FOREIGN KEY (`category_id`) REFERENCES `support_ticket_categories` (`id`) ON DELETE SET NULL,
    FOREIGN KEY (`assigned_to`) REFERENCES `support_users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Table 4: threads
-- Conversations/threads (messages)
-- References support_tickets and support_ticket_categories
-- ============================================================================
CREATE TABLE IF NOT EXISTS `threads` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `title` VARCHAR(255) NOT NULL,
    `content` TEXT NOT NULL,
    `user_id` INT NOT NULL COMMENT 'Cross-schema: references customer/vendor/rider ID',
    `ticket_id` INT NULL COMMENT 'Reference to support_tickets.id (ticket messages)',
    `category_id` INT NULL COMMENT 'Reference to support_ticket_categories.id',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_ticket_id` (`ticket_id`),
    INDEX `idx_category_id` (`category_id`),
    INDEX `idx_created_at` (`created_at`),
    FOREIGN KEY (`ticket_id`) REFERENCES `support_tickets` (`id`) ON DELETE CASCADE,
    FOREIGN KEY (`category_id`) REFERENCES `support_ticket_categories` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Table 5: comments
-- Conversation messages (replies to threads)
-- References threads
-- ============================================================================
CREATE TABLE IF NOT EXISTS `comments` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `content` TEXT NOT NULL,
    `user_id` INT NOT NULL COMMENT 'Cross-schema: references customer/vendor/rider ID',
    `thread_id` INT NOT NULL,
    `parent_comment_id` INT NULL COMMENT 'For nested replies',
    `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_user_id` (`user_id`),
    INDEX `idx_thread_id` (`thread_id`),
    INDEX `idx_parent_comment_id` (`parent_comment_id`),
    INDEX `idx_created_at` (`created_at`),
    FOREIGN KEY (`thread_id`) REFERENCES `threads` (`id`) ON DELETE CASCADE,
    FOREIGN KEY (`parent_comment_id`) REFERENCES `comments` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- Table 6: support_priority_rules
-- SLA rules (priority levels with SLA times)
-- ============================================================================
CREATE TABLE IF NOT EXISTS `support_priority_rules` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `priority_level` VARCHAR(20) NOT NULL COMMENT 'low, medium, high, critical',
    `sla_hours` INT NOT NULL COMMENT 'SLA in hours',
    `description` TEXT NULL,
    `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `priority_level` (`priority_level`),
    INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default priority rules
INSERT INTO `support_priority_rules` (`priority_level`, `sla_hours`, `description`, `is_active`) VALUES
('low', 24, 'Low priority tickets - 24 hour SLA', TRUE),
('medium', 12, 'Medium priority tickets - 12 hour SLA', TRUE),
('high', 6, 'High priority tickets - 6 hour SLA', TRUE),
('critical', 2, 'Critical priority tickets - 2 hour SLA', TRUE)
ON DUPLICATE KEY UPDATE 
    `sla_hours` = VALUES(`sla_hours`),
    `description` = VALUES(`description`),
    `is_active` = VALUES(`is_active`);

-- ============================================================================
-- Table 7: support_escalation_rules
-- Escalation configuration (automatic escalation rules)
-- ============================================================================
CREATE TABLE IF NOT EXISTS `support_escalation_rules` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `hours_threshold` INT NOT NULL COMMENT 'Hours before escalation',
    `escalate_to_role` VARCHAR(50) NOT NULL COMMENT 'senior_support, manager, admin',
    `notify_admin` BOOLEAN NOT NULL DEFAULT FALSE,
    `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_hours_threshold` (`hours_threshold`),
    INDEX `idx_is_active` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default escalation rules
INSERT INTO `support_escalation_rules` (`hours_threshold`, `escalate_to_role`, `notify_admin`, `is_active`) VALUES
(12, 'senior_support', FALSE, TRUE),
(24, 'manager', TRUE, TRUE),
(48, 'admin', TRUE, TRUE)
ON DUPLICATE KEY UPDATE 
    `hours_threshold` = VALUES(`hours_threshold`),
    `escalate_to_role` = VALUES(`escalate_to_role`),
    `notify_admin` = VALUES(`notify_admin`),
    `is_active` = VALUES(`is_active`);

-- ============================================================================
-- Table 8: support_auto_assignment
-- Assignment configuration (auto-assignment methods)
-- ============================================================================
CREATE TABLE IF NOT EXISTS `support_auto_assignment` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `assignment_method` VARCHAR(50) NOT NULL COMMENT 'round_robin, workload, category, manual',
    `is_enabled` BOOLEAN NOT NULL DEFAULT FALSE,
    `config_json` JSON NULL COMMENT 'Additional configuration as JSON',
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `assignment_method` (`assignment_method`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default assignment methods (all disabled except manual)
INSERT INTO `support_auto_assignment` (`assignment_method`, `is_enabled`) VALUES
('round_robin', FALSE),
('workload', FALSE),
('category', FALSE),
('manual', TRUE)
ON DUPLICATE KEY UPDATE `is_enabled` = VALUES(`is_enabled`);

-- ============================================================================
-- Verification Query (Run this to verify tables were created)
-- ============================================================================
SELECT 
    'support_users' AS table_name, 
    COUNT(*) AS record_count 
FROM support_users
UNION ALL
SELECT 'support_ticket_categories', COUNT(*) FROM support_ticket_categories
UNION ALL
SELECT 'support_tickets', COUNT(*) FROM support_tickets
UNION ALL
SELECT 'threads', COUNT(*) FROM threads
UNION ALL
SELECT 'comments', COUNT(*) FROM comments
UNION ALL
SELECT 'support_priority_rules', COUNT(*) FROM support_priority_rules
UNION ALL
SELECT 'support_escalation_rules', COUNT(*) FROM support_escalation_rules
UNION ALL
SELECT 'support_auto_assignment', COUNT(*) FROM support_auto_assignment;

-- ============================================================================
-- SUCCESS: All support tables created!
-- Next step: Restart your Flask app
--   touch ~/backend/tmp/restart.txt
-- ============================================================================

-- ============================================================================
-- STANDALONE FIX: If support_tickets failed earlier (ERROR 1061 duplicate key)
-- Run ONLY this block to create the missing table:
-- ============================================================================
-- USE impromptuindian_support;
--
-- CREATE TABLE IF NOT EXISTS `support_tickets` (
--     `id` INT NOT NULL AUTO_INCREMENT,
--     `ticket_number` VARCHAR(20) NULL COMMENT 'Format: TCK-YYYY-NNNNN',
--     `user_id` INT NOT NULL,
--     `user_type` ENUM('customer', 'vendor', 'rider') NOT NULL,
--     `category_id` INT NULL,
--     `priority` VARCHAR(20) NOT NULL DEFAULT 'medium',
--     `subject` VARCHAR(255) NOT NULL,
--     `description` TEXT NOT NULL,
--     `status` ENUM('open', 'assigned', 'in_progress', 'escalated', 'resolved', 'closed') NOT NULL DEFAULT 'open',
--     `assigned_to` INT NULL,
--     `sla_deadline` DATETIME NULL,
--     `attachment_image` LONGBLOB NULL,
--     `attachment_filename` VARCHAR(255) NULL,
--     `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
--     `resolved_at` DATETIME NULL,
--     PRIMARY KEY (`id`),
--     UNIQUE KEY `uk_ticket_number` (`ticket_number`),
--     INDEX `idx_status` (`status`),
--     INDEX `idx_assigned_to` (`assigned_to`),
--     INDEX `idx_user_id` (`user_id`),
--     INDEX `idx_user_type` (`user_type`),
--     INDEX `idx_category_id` (`category_id`),
--     INDEX `idx_priority` (`priority`),
--     INDEX `idx_sla_deadline` (`sla_deadline`),
--     INDEX `idx_created_at` (`created_at`),
--     FOREIGN KEY (`category_id`) REFERENCES `support_ticket_categories` (`id`) ON DELETE SET NULL,
--     FOREIGN KEY (`assigned_to`) REFERENCES `support_users` (`id`) ON DELETE SET NULL
-- ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
-- ============================================================================
