-- Chữ ký tay (không token) và nhúng trang ký vào iframe của đối tác.

ALTER TABLE recipients
    ADD COLUMN method text NOT NULL DEFAULT 'digital'
        CHECK (method IN ('digital', 'handwritten'));

-- Origin (https://erp.doitac.vn) được phép nhúng /s/<token> của tổ chức này.
ALTER TABLE organizations
    ADD COLUMN embed_origins text[] NOT NULL DEFAULT '{}';
