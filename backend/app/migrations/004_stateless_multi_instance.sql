-- Hỗ trợ vận hành backend đa tiến trình (multi-instance / horizontal scaling)
-- chia sẻ trạng thái qua PostgreSQL (SPEC §10, không dùng Redis).
--
-- 1. activation_tickets: Vé một lần kích hoạt trình duyệt thay thế dict RAM.
-- 2. agent_sessions: Phiên agent và mã ghép cặp lưu trữ tập trung, định tuyến WebSocket.
-- 3. agent_relay_requests: Hàng đợi bản tin chuyển tiếp giữa các tiến trình qua LISTEN/NOTIFY.
-- 4. rate_limits & take_rate_limit: Token bucket giới hạn tần suất phân tán trong PostgreSQL.

-- -----------------------------------------------------------------------------
-- 1. Vé kích hoạt trình duyệt (activation_tickets)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS activation_tickets (
    ticket      text PRIMARY KEY,
    device_id   text NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    expires_at  timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS activation_tickets_expires_at_idx ON activation_tickets (expires_at);

-- -----------------------------------------------------------------------------
-- 2. Phiên kết nối agent và mã ghép cặp (agent_sessions)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agent_sessions (
    id              text PRIMARY KEY,
    code            text NOT NULL,
    device_id       text REFERENCES devices(id) ON DELETE CASCADE,
    name            text NOT NULL,
    platform        text NOT NULL,
    instance_id     text NOT NULL,
    certificates    jsonb NOT NULL DEFAULT '{}'::jsonb,
    connected_at    timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_sessions_code_idx ON agent_sessions (code);
CREATE UNIQUE INDEX IF NOT EXISTS agent_sessions_device_id_idx ON agent_sessions (device_id) WHERE device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS agent_sessions_expires_at_idx ON agent_sessions (expires_at);

-- -----------------------------------------------------------------------------
-- 3. Yêu cầu chuyển tiếp agent relay giữa các tiến trình (agent_relay_requests)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS agent_relay_requests (
    id              text PRIMARY KEY,
    session_id      text NOT NULL,
    target_instance text NOT NULL,
    kind            text NOT NULL,
    payload         jsonb NOT NULL,
    response        jsonb,
    error           text,
    status          text NOT NULL DEFAULT 'pending',
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS agent_relay_requests_expires_at_idx ON agent_relay_requests (expires_at);
CREATE INDEX IF NOT EXISTS agent_relay_requests_status_target_idx ON agent_relay_requests (status, target_instance);

-- -----------------------------------------------------------------------------
-- 4. Giới hạn tần suất phân tán (rate_limits)
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS rate_limits (
    key         text PRIMARY KEY,
    tokens      double precision NOT NULL,
    updated_at  timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS rate_limits_expires_at_idx ON rate_limits (expires_at);

CREATE OR REPLACE FUNCTION take_rate_limit(
    p_key text,
    p_per_minute integer,
    p_burst integer DEFAULT NULL
)
RETURNS double precision
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_capacity double precision := COALESCE(p_burst, p_per_minute)::double precision;
    v_rate double precision := p_per_minute::double precision / 60.0;
    v_now timestamptz := clock_timestamp();
    v_tokens double precision;
    v_updated timestamptz;
    v_elapsed double precision;
    v_wait double precision;
    v_inserted boolean := false;
BEGIN
    -- 1. Bảo đảm dòng tồn tại (nguyên tử qua ON CONFLICT DO NOTHING)
    INSERT INTO public.rate_limits (key, tokens, updated_at, expires_at)
    VALUES (p_key, v_capacity, v_now, v_now + interval '10 minutes')
    ON CONFLICT (key) DO NOTHING
    RETURNING true INTO v_inserted;

    -- 2. Khoá dòng đó để tuần tự hoá mọi yêu cầu đồng thời
    SELECT tokens, updated_at INTO v_tokens, v_updated
    FROM public.rate_limits
    WHERE key = p_key
    FOR UPDATE;

    IF v_inserted IS TRUE THEN
        -- Nếu vừa tạo mới, bắt đầu từ v_capacity
        v_tokens := v_capacity;
    ELSE
        -- Nếu đã tồn tại từ trước, bù token theo thời gian trôi qua
        v_elapsed := EXTRACT(EPOCH FROM (v_now - v_updated));
        v_tokens := LEAST(v_capacity, v_tokens + v_elapsed * v_rate);
    END IF;

    -- 3. Trừ 1 token nếu còn đủ, ngược lại tính thời gian phải chờ
    IF v_tokens >= 1.0 THEN
        UPDATE public.rate_limits
        SET tokens = v_tokens - 1.0,
            updated_at = v_now,
            expires_at = v_now + interval '10 minutes'
        WHERE key = p_key;
        RETURN 0.0;
    ELSE
        UPDATE public.rate_limits
        SET tokens = v_tokens,
            updated_at = v_now,
            expires_at = v_now + interval '10 minutes'
        WHERE key = p_key;
        v_wait := (1.0 - v_tokens) / v_rate;
        RETURN v_wait;
    END IF;
END;
$$;

-- -----------------------------------------------------------------------------
-- 5. Thu hồi quyền truy cập từ websigner_tenant (Finding #2 & #11)
-- -----------------------------------------------------------------------------

REVOKE ALL ON activation_tickets, agent_sessions, agent_relay_requests, rate_limits FROM websigner_tenant;
REVOKE ALL ON FUNCTION take_rate_limit(text, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION take_rate_limit(text, integer, integer) FROM websigner_tenant;
