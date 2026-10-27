-- Nền tảng ký số nhiều tổ chức: tài khoản, khoá API, tài liệu, người nhận,
-- nhật ký kiểm toán dạng chuỗi băm, webhook, email, hạn mức, thiết bị agent.
--
-- Mọi token bí mật (phiên, khoá API, liên kết ký, thiết bị) chỉ lưu SHA-256.

CREATE TABLE organizations (
    id          text PRIMARY KEY,
    name        text NOT NULL,
    plan        text NOT NULL DEFAULT 'free',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             text PRIMARY KEY,
    org_id         text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email          text NOT NULL,
    name           text NOT NULL,
    role           text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    password_hash  text,               -- NULL khi lời mời chưa được nhận
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_key ON users (lower(email));
CREATE INDEX users_org ON users (org_id);

CREATE TABLE sessions (
    token_hash  bytea PRIMARY KEY,
    user_id     text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    ip          text,
    user_agent  text
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expiry ON sessions (expires_at);

-- Lời mời thành viên và đặt lại mật khẩu: dùng một lần, có hạn.
CREATE TABLE user_tokens (
    token_hash  bytea PRIMARY KEY,
    user_id     text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     text NOT NULL CHECK (purpose IN ('invite', 'reset')),
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_tokens_user ON user_tokens (user_id, purpose);

CREATE TABLE api_keys (
    id            text PRIMARY KEY,
    org_id        text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name          text NOT NULL,
    prefix        text NOT NULL,       -- phần đầu hiển thị được: wsk_live_AbCdEf
    key_hash      bytea NOT NULL UNIQUE,
    created_by    text REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz
);
CREATE INDEX api_keys_org ON api_keys (org_id, created_at DESC);

CREATE TABLE documents (
    id               text PRIMARY KEY,
    org_id           text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title            text NOT NULL,
    filename         text NOT NULL,
    status           text NOT NULL CHECK (status IN
                       ('draft', 'in_progress', 'completed', 'declined', 'voided', 'expired')),
    revision         integer NOT NULL DEFAULT 0,
    page_count       integer NOT NULL,
    external_ref     text,
    metadata         jsonb NOT NULL DEFAULT '{}'::jsonb,
    message          text,
    created_by_user  text REFERENCES users(id) ON DELETE SET NULL,
    created_by_key   text REFERENCES api_keys(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz,
    completed_at     timestamptz,
    expires_at       timestamptz,
    void_reason      text
);
CREATE INDEX documents_org_created ON documents (org_id, created_at DESC, id DESC);
CREATE INDEX documents_org_status ON documents (org_id, status, created_at DESC, id DESC);
CREATE INDEX documents_org_ref ON documents (org_id, external_ref) WHERE external_ref IS NOT NULL;
CREATE INDEX documents_due_expiry ON documents (expires_at) WHERE status = 'in_progress';

-- Mỗi lần ký là một revision (incremental update). Revision 0 là bản gốc.
CREATE TABLE revisions (
    document_id    text NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    revision       integer NOT NULL,
    sha256         bytea NOT NULL,
    size           integer NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    -- Kết quả xác thực chỉ phụ thuộc nội dung tệp + trust store -> cache được.
    verify_report  jsonb,
    verify_trust   text,
    PRIMARY KEY (document_id, revision)
);

CREATE TABLE recipients (
    id               text PRIMARY KEY,
    document_id      text NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    position         integer NOT NULL,     -- thứ tự khai báo, để hiển thị ổn định
    routing_order    integer NOT NULL,     -- cùng số = ký song song
    role             text NOT NULL CHECK (role IN ('signer', 'approver')),
    name             text NOT NULL,
    email            text,
    tax_code         text,
    field_page       integer,
    field_box        double precision[],
    token_version    integer NOT NULL DEFAULT 1,
    token_hash       bytea NOT NULL UNIQUE,
    status           text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'signed', 'approved', 'declined')),
    notified_at      timestamptz,
    viewed_at        timestamptz,
    acted_at         timestamptz,
    decline_reason   text,
    -- Chữ ký thật: lấy từ chứng thư, không phải từ tên khai báo.
    signed_by        text,
    signer_tax_code  text,
    cert_serial      text,
    cert_issuer      text,
    sig_field        text,
    sig_page         integer,
    sig_profile      text,
    sig_revision     integer
);
CREATE INDEX recipients_document ON recipients (document_id, position);

CREATE TABLE recipient_logos (
    recipient_id  text PRIMARY KEY REFERENCES recipients(id) ON DELETE CASCADE,
    data          bytea NOT NULL,
    format        text NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Nhật ký kiểm toán: mỗi tài liệu một chuỗi băm. ``canonical`` là đúng chuỗi
-- JSON đã băm, nên kiểm lại không phụ thuộc cách jsonb chuẩn hoá số/khoá.
CREATE TABLE events (
    id           bigserial PRIMARY KEY,
    document_id  text NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    seq          integer NOT NULL,
    type         text NOT NULL,
    created_at   timestamptz NOT NULL,
    canonical    text NOT NULL,
    prev_hash    bytea,
    hash         bytea NOT NULL,
    UNIQUE (document_id, seq)
);

CREATE TABLE webhook_endpoints (
    id              text PRIMARY KEY,
    org_id          text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    url             text NOT NULL,
    description     text,
    events          text[] NOT NULL,
    secret_version  integer NOT NULL DEFAULT 1,
    enabled         boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX webhook_endpoints_org ON webhook_endpoints (org_id);

-- Hàng đợi outbox: ghi cùng transaction với thay đổi nghiệp vụ, gửi sau.
CREATE TABLE webhook_deliveries (
    id                text PRIMARY KEY,
    endpoint_id       text NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_id          text NOT NULL,
    event_type        text NOT NULL,
    payload           jsonb NOT NULL,
    status            text NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'succeeded', 'failed')),
    attempts          integer NOT NULL DEFAULT 0,
    next_attempt_at   timestamptz NOT NULL DEFAULT now(),
    last_status_code  integer,
    last_error        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    delivered_at      timestamptz
);
CREATE INDEX webhook_deliveries_due ON webhook_deliveries (next_attempt_at) WHERE status = 'pending';
CREATE INDEX webhook_deliveries_endpoint ON webhook_deliveries (endpoint_id, created_at DESC);

CREATE TABLE emails (
    id               bigserial PRIMARY KEY,
    to_addr          text NOT NULL,
    subject          text NOT NULL,
    body             text NOT NULL,
    status           text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'sent', 'failed')),
    attempts         integer NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz
);
CREATE INDEX emails_due ON emails (next_attempt_at) WHERE status = 'pending';

CREATE TABLE usage_counters (
    org_id      text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    period      text NOT NULL,           -- 'YYYY-MM' theo giờ Việt Nam
    documents   integer NOT NULL DEFAULT 0,
    signatures  integer NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, period)
);

CREATE TABLE idempotency_keys (
    org_id           text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key              text NOT NULL,
    fingerprint      bytea NOT NULL,
    response_status  integer,           -- NULL: request đầu tiên còn đang chạy
    response_body    jsonb,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, key)
);
CREATE INDEX idempotency_keys_created ON idempotency_keys (created_at);

-- Máy đã cài agent và trình duyệt đã kích hoạt theo máy đó.
CREATE TABLE devices (
    id          text PRIMARY KEY,
    token_hash  bytea NOT NULL UNIQUE,
    name        text NOT NULL,
    platform    text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE device_browsers (
    token_hash    bytea PRIMARY KEY,
    device_id     text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    activated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_browsers_device ON device_browsers (device_id);
