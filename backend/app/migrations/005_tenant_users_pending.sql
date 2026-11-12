-- Cấp quyền đọc trạng thái kích hoạt (pending) cho vai trò websigner_tenant (SPEC §3).
-- Bảo toàn nguyên tắc đặc quyền tối thiểu (Finding #4): không lộ password_hash cho websigner_tenant.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS pending boolean GENERATED ALWAYS AS (password_hash IS NULL) STORED;

GRANT SELECT (pending) ON users TO websigner_tenant;
