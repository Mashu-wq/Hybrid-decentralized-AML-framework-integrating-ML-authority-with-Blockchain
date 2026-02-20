SET search_path TO iam_schema;

-- Insert system roles
INSERT INTO roles (name, description, is_system_role) VALUES
('super_admin', 'Full system administrator', true),
('admin', 'System administrator', true),
('compliance_officer', 'KYC/AML compliance officer', true),
('investigator', 'Fraud investigator', true),
('client', 'Regular client user', true)
ON CONFLICT (name) DO NOTHING;

-- Insert permissions (sample)
INSERT INTO permissions (name, description) VALUES
('VIEW_KYC', 'View KYC documents'),
('APPROVE_KYC', 'Approve KYC requests'),
('VIEW_ALERTS', 'View fraud alerts'),
('INVESTIGATE_ALERTS', 'Investigate fraud alerts'),
('MANAGE_USERS', 'Manage system users'),
('VIEW_AUDIT_LOGS', 'View audit logs'),
('MANAGE_ROLES', 'Manage user roles and permissions')
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to roles
WITH role_ids AS (
    SELECT id, name FROM roles
), perm_ids AS (
    SELECT id, name FROM permissions
)
INSERT INTO role_permissions (role_id, permission_id)
SELECT 
    r.id, 
    p.id
FROM role_ids r
CROSS JOIN perm_ids p
WHERE 
    (r.name = 'super_admin') OR
    (r.name = 'admin' AND p.name IN ('VIEW_KYC', 'VIEW_ALERTS', 'MANAGE_USERS', 'VIEW_AUDIT_LOGS')) OR
    (r.name = 'compliance_officer' AND p.name IN ('VIEW_KYC', 'APPROVE_KYC')) OR
    (r.name = 'investigator' AND p.name IN ('VIEW_ALERTS', 'INVESTIGATE_ALERTS'))
ON CONFLICT DO NOTHING;

-- Create default admin user (password: Admin@123)
-- This should be changed immediately after first login
INSERT INTO users (email, password_hash, role, is_active) VALUES
(
    'admin@kyc-aml.com',
    -- BCrypt hash for 'Admin@123' (use online BCrypt generator or your code)
    '$2a$12$zX6sJfqyQYQYQYQYQYQYQYQYQYQYQYQYQYQYQYQYQYQYQYQYQYQY',
    'super_admin',
    true
)
ON CONFLICT (email) DO NOTHING;

-- Assign role to admin user
WITH admin_user AS (
    SELECT id FROM users WHERE email = 'admin@kyc-aml.com'
), admin_role AS (
    SELECT id FROM roles WHERE name = 'super_admin'
)
INSERT INTO user_roles (user_id, role_id)
SELECT au.id, ar.id FROM admin_user au, admin_role ar
ON CONFLICT DO NOTHING;