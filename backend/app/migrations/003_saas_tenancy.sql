-- Đa tổ chức SaaS (multi-tenancy) cách ly bằng PostgreSQL RLS (SPEC §1-3, §5).
--
-- 1. Vai trò phân quyền websigner_tenant (NOLOGIN NOBYPASSRLS).
-- 2. Đối tác nền tảng (partners) và liên kết tổ chức con.
-- 3. Thành viên (memberships) tách rời khỏi danh tính người dùng (users).
-- 4. org_id denormalized trên mọi bảng con (revisions, recipients, recipient_logos,
--    events, webhook_deliveries) kèm khoá ngoại kép (composite FK).
-- 5. Mã hoá secret lưu trữ qua KEK (AES-256-GCM) và chính sách RLS.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'websigner_tenant') THEN
        CREATE ROLE websigner_tenant NOLOGIN NOBYPASSRLS;
    END IF;
END
$$;

GRANT websigner_tenant TO CURRENT_USER;

-- -----------------------------------------------------------------------------
-- 1. Bảng đối tác (partners) và mở rộng organizations
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS partners (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    prefix      text NOT NULL,
    key_hash    bytea NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS partner_id text REFERENCES partners(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS external_id text,
    ADD COLUMN IF NOT EXISTS settings jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS signing_key_ciphertext bytea,
    ADD COLUMN IF NOT EXISTS signing_key_kek_id text,
    ADD COLUMN IF NOT EXISTS signing_key_scheme text NOT NULL DEFAULT 'legacy';

CREATE UNIQUE INDEX IF NOT EXISTS organizations_partner_external_idx
    ON organizations (partner_id, external_id)
    WHERE external_id IS NOT NULL;

-- -----------------------------------------------------------------------------
-- 2. Thành viên (memberships) & người dùng (users) & phiên (sessions)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS memberships (
    user_id     text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role        text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, org_id)
);
CREATE INDEX IF NOT EXISTS memberships_org ON memberships (org_id);

-- Chuyển dữ liệu người dùng cũ sang bảng memberships
INSERT INTO memberships (user_id, org_id, role, created_at)
SELECT id, org_id, role, created_at FROM users
ON CONFLICT (user_id, org_id) DO NOTHING;

-- Cho phép users.org_id và users.role NULL vì vai trò gắn theo từng tổ chức
ALTER TABLE users ALTER COLUMN org_id DROP NOT NULL;
ALTER TABLE users ALTER COLUMN role DROP NOT NULL;

-- Sessions gắn với tổ chức đang kích hoạt
ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS org_id text REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE sessions s
SET org_id = m.org_id
FROM memberships m
WHERE s.user_id = m.user_id AND s.org_id IS NULL;

-- Nếu còn session nào chưa có org_id (hiếm), xoá để bảo đảm NOT NULL
DELETE FROM sessions WHERE org_id IS NULL;
ALTER TABLE sessions ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS sessions_org ON sessions (org_id);

-- -----------------------------------------------------------------------------
-- 3. org_id trên các bảng con & Composite Foreign Keys
-- -----------------------------------------------------------------------------

-- Ràng buộc (org_id, id) trên documents để bảng con tham chiếu khoá ngoại kép
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'documents_org_id_id_key'
    ) THEN
        ALTER TABLE documents ADD CONSTRAINT documents_org_id_id_key UNIQUE (org_id, id);
    END IF;
END
$$;

-- revisions
ALTER TABLE revisions ADD COLUMN IF NOT EXISTS org_id text;
UPDATE revisions r SET org_id = d.org_id FROM documents d WHERE r.document_id = d.id AND r.org_id IS NULL;
ALTER TABLE revisions ALTER COLUMN org_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE revisions DROP CONSTRAINT IF EXISTS revisions_document_id_fkey;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'revisions_org_document_fkey') THEN
        ALTER TABLE revisions ADD CONSTRAINT revisions_org_document_fkey
            FOREIGN KEY (org_id, document_id) REFERENCES documents (org_id, id) ON DELETE CASCADE;
    END IF;
END
$$;
CREATE INDEX IF NOT EXISTS revisions_org ON revisions (org_id);

-- recipients
ALTER TABLE recipients ADD COLUMN IF NOT EXISTS org_id text;
UPDATE recipients r SET org_id = d.org_id FROM documents d WHERE r.document_id = d.id AND r.org_id IS NULL;
ALTER TABLE recipients ALTER COLUMN org_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE recipients DROP CONSTRAINT IF EXISTS recipients_document_id_fkey;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'recipients_org_document_fkey') THEN
        ALTER TABLE recipients ADD CONSTRAINT recipients_org_document_fkey
            FOREIGN KEY (org_id, document_id) REFERENCES documents (org_id, id) ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'recipients_org_id_id_key') THEN
        ALTER TABLE recipients ADD CONSTRAINT recipients_org_id_id_key UNIQUE (org_id, id);
    END IF;
END
$$;
CREATE INDEX IF NOT EXISTS recipients_org ON recipients (org_id);

-- recipient_logos
ALTER TABLE recipient_logos ADD COLUMN IF NOT EXISTS org_id text;
UPDATE recipient_logos l SET org_id = r.org_id FROM recipients r WHERE l.recipient_id = r.id AND l.org_id IS NULL;
ALTER TABLE recipient_logos ALTER COLUMN org_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE recipient_logos DROP CONSTRAINT IF EXISTS recipient_logos_recipient_id_fkey;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'recipient_logos_org_recipient_fkey') THEN
        ALTER TABLE recipient_logos ADD CONSTRAINT recipient_logos_org_recipient_fkey
            FOREIGN KEY (org_id, recipient_id) REFERENCES recipients (org_id, id) ON DELETE CASCADE;
    END IF;
END
$$;
CREATE INDEX IF NOT EXISTS recipient_logos_org ON recipient_logos (org_id);

-- events (audit)
ALTER TABLE events ADD COLUMN IF NOT EXISTS org_id text;
UPDATE events e SET org_id = d.org_id FROM documents d WHERE e.document_id = d.id AND e.org_id IS NULL;
ALTER TABLE events ALTER COLUMN org_id SET NOT NULL;

DO $$
BEGIN
    ALTER TABLE events DROP CONSTRAINT IF EXISTS events_document_id_fkey;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'events_org_document_fkey') THEN
        ALTER TABLE events ADD CONSTRAINT events_org_document_fkey
            FOREIGN KEY (org_id, document_id) REFERENCES documents (org_id, id) ON DELETE CASCADE;
    END IF;
END
$$;
CREATE INDEX IF NOT EXISTS events_org ON events (org_id);

-- webhook_endpoints: cột bí mật KEK & composite key
ALTER TABLE webhook_endpoints
    ADD COLUMN IF NOT EXISTS secret_scheme text NOT NULL DEFAULT 'legacy',
    ADD COLUMN IF NOT EXISTS secret_ciphertext bytea,
    ADD COLUMN IF NOT EXISTS kek_id text,
    ADD COLUMN IF NOT EXISTS prev_secret_ciphertext bytea;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'webhook_endpoints_org_id_id_key') THEN
        ALTER TABLE webhook_endpoints ADD CONSTRAINT webhook_endpoints_org_id_id_key UNIQUE (org_id, id);
    END IF;
END
$$;

-- webhook_deliveries
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS org_id text;
ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS seq bigserial;
UPDATE webhook_deliveries d SET org_id = e.org_id FROM webhook_endpoints e WHERE d.endpoint_id = e.id AND d.org_id IS NULL;
ALTER TABLE webhook_deliveries ALTER COLUMN org_id SET NOT NULL;
DO $$
BEGIN
    ALTER TABLE webhook_deliveries DROP CONSTRAINT IF EXISTS webhook_deliveries_endpoint_id_fkey;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'webhook_deliveries_org_endpoint_fkey') THEN
        ALTER TABLE webhook_deliveries ADD CONSTRAINT webhook_deliveries_org_endpoint_fkey
            FOREIGN KEY (org_id, endpoint_id) REFERENCES webhook_endpoints (org_id, id) ON DELETE CASCADE;
    END IF;
END
$$;
CREATE INDEX IF NOT EXISTS webhook_deliveries_org ON webhook_deliveries (org_id);

-- emails
ALTER TABLE emails ADD COLUMN IF NOT EXISTS org_id text;

-- -----------------------------------------------------------------------------
-- 4. Bật Row Level Security (RLS) và tạo Policy
-- -----------------------------------------------------------------------------

-- organizations
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS org_tenant ON organizations;
CREATE POLICY org_tenant ON organizations
    USING (id = current_setting('app.tenant_id', true))
    WITH CHECK (id = current_setting('app.tenant_id', true));

-- memberships
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS memberships_tenant ON memberships;
CREATE POLICY memberships_tenant ON memberships
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- api_keys
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_keys_tenant ON api_keys;
CREATE POLICY api_keys_tenant ON api_keys
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- documents
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS documents_tenant ON documents;
CREATE POLICY documents_tenant ON documents
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- revisions
ALTER TABLE revisions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS revisions_tenant ON revisions;
CREATE POLICY revisions_tenant ON revisions
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- recipients
ALTER TABLE recipients ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recipients_tenant ON recipients;
CREATE POLICY recipients_tenant ON recipients
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- recipient_logos
ALTER TABLE recipient_logos ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS recipient_logos_tenant ON recipient_logos;
CREATE POLICY recipient_logos_tenant ON recipient_logos
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- events
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS events_tenant ON events;
CREATE POLICY events_tenant ON events
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- webhook_endpoints
ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webhook_endpoints_tenant ON webhook_endpoints;
CREATE POLICY webhook_endpoints_tenant ON webhook_endpoints
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- webhook_deliveries
ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS webhook_deliveries_tenant ON webhook_deliveries;
CREATE POLICY webhook_deliveries_tenant ON webhook_deliveries
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- usage_counters
ALTER TABLE usage_counters ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS usage_counters_tenant ON usage_counters;
CREATE POLICY usage_counters_tenant ON usage_counters
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- idempotency_keys
ALTER TABLE idempotency_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS idempotency_keys_tenant ON idempotency_keys;
CREATE POLICY idempotency_keys_tenant ON idempotency_keys
    USING (org_id = current_setting('app.tenant_id', true))
    WITH CHECK (org_id = current_setting('app.tenant_id', true));

-- -----------------------------------------------------------------------------
-- 5. Cấp quyền DML cho websigner_tenant
-- -----------------------------------------------------------------------------

GRANT USAGE ON SCHEMA public TO websigner_tenant;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    organizations,
    memberships,
    users,
    sessions,
    user_tokens,
    api_keys,
    documents,
    revisions,
    recipients,
    recipient_logos,
    events,
    webhook_endpoints,
    webhook_deliveries,
    usage_counters,
    idempotency_keys,
    emails
TO websigner_tenant;

GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO websigner_tenant;
