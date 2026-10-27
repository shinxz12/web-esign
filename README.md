# Web Signer

Nền tảng ký số hợp đồng điện tử (eContract) bằng USB token, bán cho doanh
nghiệp dưới dạng dịch vụ: hệ thống của khách (ERP, CRM, phần mềm bán hàng…)
gọi API bằng **khoá bí mật** để tạo tài liệu, khai người ký/người duyệt theo
thứ tự, nhận webhook khi từng người ký xong; người ký mở liên kết riêng, cắm
token, bấm ký. Kết quả là PDF có chữ ký PAdES mà Adobe Reader xác thực được.

- Nhiều tổ chức (tenant), mỗi tổ chức có thành viên, vai trò, khoá API,
  webhook, gói dịch vụ và hạn mức theo tháng.
- Luồng ký: người ký + người duyệt, thứ tự tuần tự hoặc song song, ô ký đặt
  sẵn, từ chối, huỷ, hết hạn, nhắc lại, cấp lại liên kết.
- Nhật ký kiểm toán dạng chuỗi băm cho từng tài liệu; xác thực chữ ký tích hợp.
- Đóng dấu thời gian (TSA) và lưu trữ dài hạn (LTV): PAdES B-B / B-T / B-LT / B-LTA.

## Nguyên lý: hash-then-sign

Chữ ký số trong PDF không phải cái hình. File được chèn một ô trống, phần còn
lại (`ByteRange`) được băm SHA-256, chữ ký của bản băm đó được nhét vào ô trống.

**USB token chỉ cần vài trăm byte, không cần file PDF.** Nên tài liệu ở lại
server, agent trên máy người dùng cực mỏng.

```
Browser                 Backend                    Agent              Token
   │  vị trí khung ký ──▶ │                           │                  │
   │                      │ chèn ô trống + hình ký    │                  │
   │                      │ băm ByteRange             │                  │
   │                      │ lấy CRL/OCSP (B-LT)       │                  │
   │                      │ dựng signed attributes    │                  │
   │                      │ ── 236 byte ────────────▶ │                  │
   │                      │                           │ ─ SHA-256 ─────▶ │
   │                      │                           │ ◀── 256 byte ─── │
   │                      │ ◀── 256 byte ──────────── │                  │
   │                      │ dựng CMS + dấu thời gian  │                  │
   │                      │ ghi DSS (B-LT)            │                  │
   │ ◀── PDF đã ký ────── │                           │                  │
```

Mỗi lần ký là một *incremental update*, nên ký nhiều người tuần tự không làm
hỏng chữ ký trước. Token chỉ ký đúng một lần cho mỗi chữ ký — dấu thời gian và
dữ liệu thu hồi được server thêm vào sau, không cần hỏi lại token.

## Vì sao agent nối ra server thay vì mở cổng localhost

Plugin ký số truyền thống mở web server ở `127.0.0.1` cho trang web gọi vào.
Cách đó đang hỏng dần:

- Chrome 142 (10/2025) đặt mọi request từ trang public tới loopback sau một
  permission prompt (Local Network Access).
- Safari chặn thẳng `http://127.0.0.1` và `ws://127.0.0.1` từ trang HTTPS
  (WebKit #171934, #173161 — chưa fix).
- Cert TLS cho domain trỏ về 127.0.0.1 phải nhúng private key vào installer.

Ở đây agent **chủ động** mở WebSocket ra backend và giữ kết nối. Browser không
bao giờ gọi vào máy người dùng → không dính cả ba vấn đề trên.

## Ghép trình duyệt với máy: cookie thiết bị

Agent thuộc về **máy**, không thuộc tài khoản nào — đúng mô hình plugin mà
người dùng VN đã quen. Ba bí mật, ba vai:

| Giữ ở | Bí mật | Trả lời câu hỏi |
|---|---|---|
| `~/.websigner/agent.json` | `device_token` | tôi là máy nào |
| thanh địa chỉ, 2 phút, một lần | `ticket` | vé đổi lấy cookie |
| cookie `ws_device` | `browser_token` | trình duyệt này đã được máy đó xác nhận |

Luồng: agent khởi động → `POST /api/devices` ghi danh máy → mở trình duyệt mặc
định tới `/activate?t=<ticket>` → server set cookie `ws_device` → `GET
/api/agents` trả thẳng agent và chứng thư của máy đó. Trang web không gõ gì.

Trình duyệt khác (hoặc đã xoá cookie): bấm **Kích hoạt trình duyệt** trong cửa
sổ agent — nó mở vé mới. Không dùng được đường đó thì còn **mã ghép cặp 6 số**
làm dự phòng, nằm trong phần thu gọn ở bước 1.

Thu hồi: nút “Quên máy này” trên web gỡ cookie của đúng trình duyệt đang dùng;
xoá hẳn thiết bị (bảng `devices` trong PostgreSQL) thì mọi trình duyệt đã kích hoạt
theo nó mất hiệu lực cùng lúc.

Vì mọi trình duyệt đã kích hoạt đều dùng được token, **lớp chặn thật là hộp
thoại xác nhận trên agent + PIN của token** — không phải mã ghép cặp.

## Mô hình nền tảng

```mermaid
flowchart LR
  ERP["Hệ thống của khách<br/>(khoá API)"] -- "/v1 REST" --> BE
  ADM["Quản trị viên tổ chức<br/>(giao diện /)"] -- "cookie phiên + CSRF" --> BE
  SGN["Người ký / người duyệt<br/>(/s/&lt;token&gt;)"] -- "/api/sign" --> BE
  AG["Agent + USB token<br/>(máy người ký)"] -- "WebSocket ra ngoài" --> BE
  BE["Backend FastAPI"] --- PG[("PostgreSQL")]
  BE --- FS[("PDF theo revision<br/>/data/documents")]
  BE -- "webhook ký HMAC" --> ERP
  BE -- "email mời / hoàn tất" --> SGN
```

| Ai | Xác thực | Làm được gì |
|---|---|---|
| Hệ thống tích hợp | `Authorization: Bearer wsk_live_…` | API tài liệu `/v1`, lượt dùng |
| Thành viên tổ chức | cookie `ws_session` + header `X-CSRF-Token` | như trên, qua giao diện |
| Quản trị tổ chức (owner/admin) | phiên đăng nhập | + khoá API, webhook, thành viên |
| Người nhận | liên kết `/s/<token>` riêng từng người | xem, ký/duyệt/từ chối đúng lượt |
| Agent | `device_token` / mã ghép cặp | ký 32 byte bản băm, có hộp thoại xác nhận |

Khoá API cố ý **không** gọi được nhóm quản trị: lộ khoá không kéo theo việc kẻ
gian tự cấp khoá mới, đổi webhook hay mời người vào tổ chức.

Danh tính người ký vẫn **là chứng thư số**: khai MST thì MST trên chứng thư
phải khớp, không khai thì so tên đã bỏ dấu (kể cả `Đ`). Có liên kết mà cầm
token của người khác thì bị chặn (403 `wrong_signer`) trước khi token ký.

### Vòng đời tài liệu

```mermaid
stateDiagram-v2
  [*] --> draft: POST /v1/documents
  draft --> in_progress: send
  in_progress --> completed: mọi người nhận xong
  in_progress --> declined: một người từ chối
  in_progress --> expired: quá expires_at
  draft --> voided: void
  in_progress --> voided: void
```

Người nhận có `order`: nhóm số nhỏ nhất còn người chưa xong là nhóm đang tới
lượt; **cùng số thì ký song song**. Người duyệt (`approver`) bấm duyệt, không
cần token. Email mời chỉ gửi cho nhóm đang tới lượt.

Hai người cùng nhóm ký một lúc không ghi đè nhau: mỗi tài liệu có khoá giữ suốt
prepare → token → finalize → ghi; người đến sau nhận 409
`signing_in_progress`. Khi ghi, revision còn được so lại trong transaction.

## API cho hệ thống tích hợp

Tài liệu đầy đủ (OpenAPI) ở `/docs`. Lỗi luôn có dạng
`{"detail": "<thông điệp>", "code": "<mã ổn định>"}` — rẽ nhánh theo `code`.

```bash
KEY=wsk_live_...   # tạo ở mục Nhà phát triển trên giao diện, chỉ hiện một lần

# Tạo và gửi luôn: người duyệt trước, rồi hai bên ký song song, ô ký đặt sẵn
curl -H "Authorization: Bearer $KEY" -H "Idempotency-Key: order-1001" \
  -F file=@hop-dong.pdf \
  -F 'data={"title":"HĐ 1001","external_ref":"ORDER-1001","expires_in_days":14,"send":true,
     "recipients":[
       {"name":"Kế toán trưởng","email":"kt@a.vn","role":"approver","order":1},
       {"name":"Nguyễn Văn A","email":"a@a.vn","tax_code":"0101234567","order":2,
        "field":{"page":1,"box":[65,383,230,473]}},
       {"name":"Trần Thị Bích","email":"b@b.vn","tax_code":"0107654321","order":2}]}' \
  https://ky.example.vn/v1/documents
```

Phản hồi có `recipients[].signing_url` — gửi email (máy chủ có SMTP thì tự
gửi) hoặc nhúng thẳng vào hệ thống của bạn. Toạ độ ô ký theo điểm PDF, gốc
dưới-trái, `page` đếm từ 0.

| Endpoint | Việc |
|---|---|
| `POST /v1/documents` | tải PDF + `data` JSON; `send:false` để giữ bản nháp |
| `GET /v1/documents?status=&q=&external_ref=&cursor=` | danh sách, phân trang con trỏ |
| `GET /v1/documents/{id}` | chi tiết, kèm `signing_url` của người còn chờ |
| `PATCH /v1/documents/{id}` · `PUT …/recipients` · `POST …/send` | sửa nháp, gửi |
| `POST …/void` · `DELETE /v1/documents/{id}` | huỷ, xoá (không xoá khi đang ký) |
| `GET …/file?revision=&download=true` | PDF bản mới nhất hoặc revision bất kỳ |
| `GET …/verify` | xác thực chữ ký (cache theo revision + trust store) |
| `GET …/audit` | nhật ký chuỗi băm: `chain_valid`, `head` |
| `POST …/recipients/{rid}/remind` · `…/rotate-link` | nhắc lại, thu hồi liên kết cũ |
| `GET /v1/usage` | gói, hạn mức, lượt dùng 12 tháng |

`Idempotency-Key` (24 giờ): gọi lại cùng khoá trả đúng tài liệu cũ kèm
`Idempotent-Replayed: true`; cùng khoá khác nội dung là 422.

### Webhook

Sự kiện: `document.sent|completed|declined|voided|expired`,
`recipient.viewed|signed|approved|declined`. Thân là
`{"id","type","created_at","data":{"document":…,"recipient":…}}` — không
bao giờ chứa liên kết ký. Kiểm chữ ký trước khi tin:

```python
import hashlib, hmac

def verify(secret: str, header: str, raw_body: bytes) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))  # WebSigner-Signature
    expected = hmac.new(secret.encode(), parts["t"].encode() + b"." + raw_body,
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts["v1"])  # và từ chối nếu t quá cũ
```

Sự kiện được ghi vào hàng đợi **cùng transaction** với thay đổi nghiệp vụ,
gửi lại giãn dần 10 giây → 12 giờ (8 lần, ~21 giờ), rồi đánh dấu thất bại —
bấm “Gửi lại” trên giao diện. Webhook chỉ gọi HTTPS tới địa chỉ công cộng; IP
được kiểm **lúc kết nối** nên DNS rebinding không lọt vào mạng nội bộ.

### Gói dịch vụ

| Gói | Tài liệu/tháng | API/phút | Tệp tối đa | Người nhận/tài liệu | Thành viên | Khoá API | Webhook |
|---|---|---|---|---|---|---|---|
| `free` | 20 | 60 | 10 MB | 5 | 3 | 2 | 1 |
| `business` | 1000 | 600 | 25 MB | 20 | 25 | 10 | 5 |
| `enterprise` | không giới hạn | 3000 | 50 MB | 50 | không giới hạn | 50 | 20 |

Hạn mức tài liệu trừ nguyên tử lúc tạo, theo tháng giờ Việt Nam; vượt là 402
`quota_exceeded`. Chưa nối cổng thanh toán: người vận hành đổi gói bằng CLI.

### Quản trị nền tảng (CLI)

```bash
cd backend
../.venv/bin/python -m app.admin orgs                                   # tổ chức, gói, lượt dùng
../.venv/bin/python -m app.admin create-org "Công ty A" a@a.vn "Nguyễn Văn A" --plan business
../.venv/bin/python -m app.admin set-plan org_1234abcd5678ef90 enterprise
../.venv/bin/python -m app.admin import-legacy org_1234abcd5678ef90    # tài liệu của bản lưu bằng tệp
```

Nâng cấp từ bản lưu bằng tệp: `devices.json` tự chuyển vào cơ sở dữ liệu lần
khởi động đầu (agent đã cài nối lại được ngay). Tài liệu cũ thuộc cookie ẩn
danh nên không tự có chủ — `import-legacy` đưa chúng vào tổ chức được chọn;
liên kết mời cũ hết hiệu lực, lấy liên kết mới từ API.

## Bảo mật và hiệu năng

| Mối lo | Cách xử lý |
|---|---|
| Lộ cơ sở dữ liệu | Chỉ lưu SHA-256 của phiên, khoá API, liên kết ký, token thiết bị; mật khẩu scrypt. Liên kết ký và secret webhook là HMAC(khoá server, id, phiên bản) — tính lại được, không lưu bản rõ |
| Lẫn dữ liệu giữa tổ chức | Mọi truy vấn lọc `org_id`; sai tổ chức trả 404 như không tồn tại |
| CSRF | Cookie `SameSite=Lax` + `X-CSRF-Token` bắt buộc cho mọi request thay đổi dữ liệu bằng cookie |
| Dò mật khẩu / mã ghép cặp | Giới hạn tần suất theo IP + email; băm giả khi email không tồn tại để thời gian phản hồi như nhau |
| SSRF qua webhook | Chỉ HTTPS công cộng, resolver chặn IP nội bộ lúc kết nối, không theo redirect |
| Sửa lịch sử | Nhật ký chuỗi băm; hệ thống tích hợp giữ `head` để phát hiện cả việc viết lại toàn bộ |
| Script bên thứ ba | pdf.js đóng gói tại `web/vendor`, CSP `script-src 'self'`, `frame-ancestors 'none'` |
| Token trong URL | `Referrer-Policy: no-referrer`; access log che `/s/…`, `/api/sign/…`, `?t=…` |
| Request khổng lồ | Chặn theo `Content-Length` trước khi multipart ghi ra đĩa; trần theo gói |

Hiệu năng: truy vấn có chỉ mục cho mọi đường nóng (danh sách theo tổ chức +
trạng thái, tra liên kết ký theo băm), danh sách nạp người nhận bằng một truy
vấn `ANY()` (không N+1), phân trang con trỏ. PDF phục vụ thẳng từ đĩa. Xác
thực chữ ký chạy ngoài event loop và cache theo revision + trust store; trust
store chỉ đọc lại khi thư mục đổi. Webhook/email gửi nền, song song, lấy việc
bằng `FOR UPDATE SKIP LOCKED`.

## Chạy thử

```bash
# 1. Môi trường
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt
createdb websigner                       # PostgreSQL 14+

# 2. Chứng thư test + CRL + PDF mẫu
./scripts/make_test_certs.sh
mkdir -p data/samples && .venv/bin/python scripts/make_sample_pdf.py data/samples/hop-dong-mau.pdf

# 3. TSA test (bỏ qua nếu dùng TSA thật)
.venv/bin/python scripts/tsa_server.py --port 8080

# 4. Backend — bảng tự tạo lần chạy đầu (backend/app/migrations)
cd backend && WEBSIGNER_DATABASE_URL=postgresql://127.0.0.1:5432/websigner \
  WEBSIGNER_TSA_URL=http://127.0.0.1:8080/tsa \
  ../.venv/bin/python -m uvicorn app.main:app --port 8000

# 5. Agent (cửa sổ khác) — mặc định agent trỏ về wss://web-signer.btngoc.io.vn,
#    nên chạy local phải chỉ rõ --server
.venv/bin/python agent/agent.py --server ws://127.0.0.1:8000/ws/agent \
  --pfx data/certs/signer-a.pfx --password 123456
```

Mở http://127.0.0.1:8000 → đăng ký tổ chức → tải PDF lên, thêm người nhận,
đặt ô ký, gửi → mở liên kết ký của người nhận. Agent đã kích hoạt trình duyệt
thì trang ký **tự thấy token đang cắm** — không nhập mã, không bấm “Kết nối”.

Ký một phát qua API để kiểm tra nhanh:

```bash
WEBSIGNER_API_KEY=wsk_live_... ./scripts/smoke.sh <mã-ghép-cặp>
```

Test:

```bash
.venv/bin/python -m pytest -q                  # tất cả (~30s)
.venv/bin/python -m pytest -q -m "not e2e"     # chỉ bất biến, không cần server/DB
.venv/bin/python -m pytest tests/test_e2e.py -v
```

Nhóm `e2e` tự dựng môi trường riêng: cơ sở dữ liệu PostgreSQL tạm (tạo qua
`WEBSIGNER_TEST_ADMIN_DSN`, mặc định `postgresql://127.0.0.1:5432/postgres`,
xoá khi xong), CA mới, CRL, TSA, hộp thư SMTP và người nhận webhook trong tiến
trình test, backend và agent thật, USB token ảo SoftHSM2 — rồi ký, xác thực và
thử phá. Không mock gì, không đụng vào `data/` của bạn.

### Agent có giao diện (.exe cho người dùng cuối)

`agent/gui.py` là cùng lõi với `agent.py`, khác ở chỗ mọi tuỳ chọn nằm trong
cửa sổ và mỗi lần ký hiện hộp thoại xác nhận kèm tên tài liệu + hash.

```bash
.venv/bin/python agent/gui.py              # chạy từ mã nguồn
.venv/bin/python agent/gui.py --autoconnect
```

Trong cửa sổ có: server (mặc định `wss://web-signer.btngoc.io.vn/ws/agent`,
sửa được), nguồn khoá (USB token PKCS#11 · Windows Certificate Store · tệp
PFX), nút **Dò driver** PKCS#11, nhãn token khi cắm nhiều thiết bị, PIN (tuỳ
chọn nhớ lại), store CNG và lọc "chỉ khoá trên token", **Xem chứng thư**,
**Kích hoạt trình duyệt**, và ô **Chạy khi khởi động máy**. Cấu hình lưu ở
`~/.websigner/agent.json` (quyền 600) — PIN chỉ chạm đĩa khi tích "Nhớ PIN".

Tự khởi động chạy trong phiên đăng nhập của người dùng, không phải service —
service không đọc được token cắm ở phiên người dùng và không hiện được hộp
thoại xác nhận:

| Hệ | Nơi ghi |
|---|---|
| Windows | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WebSignerAgent` |
| macOS | `~/Library/LaunchAgents/vn.websigner.agent.plist` |
| Linux | `~/.config/autostart/websigner-agent.desktop` |

Đóng gói một tệp chạy thẳng (PyInstaller không cross-build — muốn `.exe` thì
phải build **trên Windows**):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-agent.ps1   # -> dist\WebSignerAgent.exe
powershell -ExecutionPolicy Bypass -File scripts\install-agent.ps1 # cài vào máy + tạo shortcut + tự khởi động
```

```bash
.venv/bin/python -m PyInstaller --noconfirm scripts/websigner-agent.spec
```

Nên ký `signtool` lên `.exe` bằng chứng thư code signing, nếu không SmartScreen
sẽ chặn ở máy khách (lệnh mẫu ở cuối `scripts/build-agent.ps1`).

### Ký bằng USB token thật (Windows)

Phần mềm ký của CA — I-CA, Viettel-CA, VNPT-CA, FPT-CA, BKAV, Nacencomm… —
luôn đăng ký token vào Windows Certificate Store `MY` qua CSP/minidriver. Agent
đọc thẳng từ đó, không cần biết của CA nào:

```powershell
.\scripts\windows-agent.ps1
.\scripts\windows-agent.ps1 -Server wss://web-signer.btngoc.io.vn/ws/agent
.\scripts\windows-agent.ps1 -ListOnly      # chỉ xem token đọc được những gì
```

Script tự tạo môi trường Python và cài 3 gói agent cần. Gọi tay cũng được:

```powershell
py agent\agent.py --cng
py agent\agent.py --cng --hardware-only    # bỏ chứng thư khoá mềm trong store
py agent\agent.py --list                   # chẩn đoán: in chứng thư rồi thoát
```

Phần mềm của CA thường cài kèm cả DLL PKCS#11. Dùng đường đó khi cần:

```powershell
py agent\agent.py --find-drivers           # dò DLL đã cài trong System32
py agent\agent.py --pkcs11 auto            # dùng DLL đầu tiên tìm thấy
```

### Nhiều token, nhiều công ty

Người ký thường giữ token của vài công ty và rút ra cắm vào liên tục. Agent
**không bám vào token nào cả**: mỗi lần liệt kê hay ký đều dò lại slot.

- Cắm nhiều token cùng lúc: thấy hết chứng thư của mọi token.
- Rút token A cắm token B: bấm **Kết nối** lại trên web là thấy chứng thư mới,
  không phải khởi động lại agent.
- Chưa cắm token lúc khởi động cũng không sao — cắm sau rồi bấm Kết nối.
- Mỗi token một PIN: agent hỏi PIN theo số sê-ri và nhớ riêng từng token.
- Ký bằng chứng thư nào thì agent mở đúng token giữ chứng thư đó, không phải
  token dò thấy đầu tiên. Nếu token đã bị rút, lỗi nói thẳng ra.
- Server khởi động lại (deploy, mạng chớp) thì agent tự nối lại, giãn dần
  1s → 30s, và **giữ nguyên mã ghép cặp** — không phải nhập lại trên web.

### macOS/Linux

```bash
.venv/bin/python agent/agent.py --pkcs11 /đường/dẫn/driver.so
```

| Token | Thư viện PKCS#11 |
|---|---|
| SafeNet eToken | `libeToken.dylib` / `eTPKCS11.dll` |
| Feitian ePass2003 | `libcastle.dylib` / `eps2003csp11.dll` |
| Gemalto / Thales | `libgclib.dylib` / `gclib.dll` |

Lưu ý: nhiều token VN được format theo chuẩn **minidriver của Windows**
(`mscp`) chứ không phải PKCS#15, nên OpenSC trên macOS/Linux sẽ báo
`CKR_TOKEN_NOT_RECOGNIZED` dù nhận được đầu đọc. Phải dùng middleware của
hãng, hoặc ký trên Windows.

### Thử đường PKCS#11 khi chưa có token

SoftHSM2 là token PKCS#11 ảo, chạy đúng code path của token thật:

```bash
brew install softhsm                                              # hoặc apt install softhsm2
./scripts/make_softhsm_token.sh data/certs/signer-a.pfx TOKEN-RSA
./scripts/make_softhsm_token.sh data/certs/signer-ec.pfx TOKEN-EC

export SOFTHSM2_CONF=$PWD/data/softhsm/softhsm2.conf
.venv/bin/python agent/agent.py \
  --pkcs11 /opt/homebrew/lib/softhsm/libsofthsm2.so \
  --token-label TOKEN-RSA --pin 123456
```

## Hình chữ ký

Theo mẫu quen thuộc của chữ ký số VN: logo/con dấu bên trái, chữ song ngữ bên
phải, dấu tích xanh lá **chìm** phía dưới phần chữ.

- Ô ký có **cỡ cố định** chọn từ giao diện (140×76, 165×90, 190×104, 220×120
  pt; mặc định 165×90) — đặt bằng một cú bấm, kéo để chỉnh vị trí. Kéo tự do
  cho ra ô méo, chữ bị co giãn mỗi lần một khác.
- Ba dòng: `Ký bởi` (CN chứng thư), `MST` (nếu chứng thư có OU `MST:…`) và
  `Ngày ký`. Không còn lý do/nơi ký: chúng cũng không được ghi vào `/Reason`
  `/Location` nữa, nên bảng thuộc tính của Adobe cũng sạch theo.
- Dòng nào dài hơn bề rộng ô thì **tự xuống dòng** — tên tổ chức, và cả ngày
  ký khi ô hẹp. Chỉ khi ô hẹp tới mức một mình ngày cũng không vừa thì định
  dạng mới rút gọn dần (`%d/%m/%Y %H:%M:%S %z` → `%d/%m/%Y`).
- Dấu tích vẽ bằng nét vector, độ mờ 38%, nằm **dưới** chữ nên không che nội
  dung; tắt được bằng ô “Dấu tích chìm”.

## Thuật toán ký

Server chọn theo khoá công khai trong chứng thư rồi **gửi kèm tham số** cho
agent; agent không được tự chọn.

| Khoá | Thuật toán | Cơ chế PKCS#11 |
|---|---|---|
| RSA | `rsa_pkcs1v15_sha256` (mặc định) | `CKM_SHA256_RSA_PKCS` |
| RSA, bật `WEBSIGNER_PREFER_PSS` | `rsa_pss_sha256` | `CKM_SHA256_RSA_PKCS_PSS` |
| EC P-256 | `ecdsa_sha256` | `CKM_ECDSA_SHA256`, fallback `CKM_ECDSA` |

Hai điểm dễ sai, đã xử lý:

- **RSA-PSS**: pyHanko khai salt dài tối đa (`k − hLen − 2` = 222 byte với khoá
  2048), không phải 32. Server gửi `salt_length` xuống agent; thiếu thì agent
  từ chối ký thay vì đoán.
- **ECDSA**: token trả `r‖s`, CMS cần `SEQUENCE{r,s}` dạng DER — agent chuyển
  bằng `ecdsa_raw_to_der()`.

## Cấu trúc

| Đường dẫn | Vai trò |
|---|---|
| `backend/app/signing.py` | lõi hai pha: `prepare` (băm) / `finalize` (CMS, TSA, DSS) |
| `backend/app/signflow.py` | một lượt ký: khoá theo tài liệu, pha 1 → agent → pha 2 → ghi |
| `backend/app/documents.py` | tài liệu, người nhận, lượt ký, chuyển trạng thái, xác thực có cache |
| `backend/app/audit.py` | nhật ký kiểm toán chuỗi băm |
| `backend/app/accounts.py` · `auth.py` | tổ chức, người dùng, phiên, thành viên, khoá API; ai đang gọi |
| `backend/app/webhooks.py` · `mailer.py` · `worker.py` | outbox webhook/email, chống SSRF, việc nền |
| `backend/app/plans.py` | gói dịch vụ, hạn mức, đếm lượt dùng |
| `backend/app/api_*.py` · `main.py` | HTTP: `/v1`, `/api` quản trị, `/api/sign`, agent; middleware bảo mật |
| `backend/app/db.py` · `migrations/` | pool PostgreSQL, migration SQL thuần |
| `backend/app/storage.py` | PDF theo revision trên đĩa |
| `backend/app/admin.py` | CLI quản trị nền tảng |
| `backend/app/verify.py` | xác thực chữ ký, LTV, phân tích thay đổi sau khi ký |
| `backend/app/trust.py` | trust anchor và ngữ cảnh kiểm tra thu hồi |
| `backend/app/relay.py` | hub WebSocket, tìm agent theo thiết bị hoặc mã 6 số |
| `backend/app/devices.py` | thiết bị đã cài agent + trình duyệt đã kích hoạt |
| `agent/keysource.py` | giao kèo chung cho mọi nguồn khoá |
| `agent/agent.py` | client relay (CLI), nguồn khoá PKCS#11 / PFX |
| `agent/gui.py` | cửa sổ agent cho người dùng cuối, đóng gói thành .exe |
| `agent/config.py` | `~/.websigner/agent.json`: danh tính máy + tuỳ chọn |
| `agent/autostart.py` | chạy cùng hệ điều hành (Run key / LaunchAgent / XDG) |
| `agent/cng.py` | nguồn khoá Windows Certificate Store (CNG + CSP) |
| `web/index.html` · `dashboard.js` | giao diện quản trị tổ chức: tài liệu, đặt ô ký, nhà phát triển, thành viên, gói |
| `web/sign.html` · `sign.js` | trang ký của người nhận: viewer pdf.js, ký/duyệt/từ chối, xác thực |
| `web/vendor/pdfjs` | pdf.js 4.10.38 đóng gói sẵn (không tải từ CDN) |
| `scripts/` | chứng thư test, PDF mẫu, TSA test, SoftHSM2, build .exe |
| `tests/` | bất biến + e2e (tự dựng CA, CRL, TSA, backend, agent, token ảo) |
| `Dockerfile` · `compose.yaml` | ảnh triển khai backend + giao diện; kèm PostgreSQL |

## Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `WEBSIGNER_DATABASE_URL` | `postgresql://127.0.0.1:5432/websigner` | PostgreSQL 14+ |
| `WEBSIGNER_SECRET_KEY` | sinh vào `<data>/secret.key` | ≥ 32 ký tự; sinh liên kết ký và secret webhook — **đổi là mọi liên kết cũ chết** |
| `WEBSIGNER_DATA` | `<repo>/data` | thư mục dữ liệu (PDF, font cache) |
| `WEBSIGNER_TRUST_DIR` | `<data>/trust` | **chỉ chứa chứng thư CA** |
| `WEBSIGNER_TSA_URL` | — | URL TSA RFC 3161; chưa đặt thì chỉ ký được B-B |
| `WEBSIGNER_PROFILE` | `B-LT` nếu có TSA, nếu không `B-B` | `B-B`/`B-T`/`B-LT`/`B-LTA` |
| `WEBSIGNER_PREFER_PSS` | tắt | dùng RSA-PSS thay PKCS#1 v1.5 |
| `WEBSIGNER_FONT` | tự dò | font TTF cho hình chữ ký (cần glyph tiếng Việt) |
| `WEBSIGNER_PUBLIC_URL` | suy từ request | gốc URL đặt vào liên kết ký, email, kích hoạt thiết bị |
| `WEBSIGNER_SMTP_URL` | — | `smtp://host:25`, `smtp+starttls://user:pass@host:587`, `smtps://…:465`; chưa đặt thì không gửi email |
| `WEBSIGNER_MAIL_FROM` | `Web Signer <no-reply@localhost>` | người gửi email |
| `WEBSIGNER_ALLOW_SIGNUP` | bật | tắt thì chỉ tạo tổ chức bằng CLI |
| `WEBSIGNER_WEBHOOK_ALLOW_PRIVATE` | tắt | cho webhook gọi http/IP nội bộ — **chỉ dùng khi phát triển** |
| `WEBSIGNER_FRAME_ANCESTORS` | — | origin được nhúng trang ký `/s/…` vào iframe |
| `WEBSIGNER_DB_POOL_SIZE` | 10 | số kết nối tối đa tới PostgreSQL |
| `CLOUDFLARE_R2_BUCKET` | — | đặt thì PDF lưu trên R2 thay vì `<data>/documents` |
| `CLOUDFLARE_R2_ACCOUNT_ID` · `…_ACCESS_KEY_ID` · `…_SECRET_ACCESS_KEY` | — | thông tin truy cập R2 |
| `WEBSIGNER_R2_PREFIX` | `web-signer/` | tiền tố khoá trong bucket (bucket dùng chung được) |
| `WEBSIGNER_AGENT_HOME` | `~/.websigner` | thư mục cấu hình phía agent |

Hai cái bẫy đã gặp, ghi lại để đừng vấp lại:

- **Trust store chỉ được chứa CA.** Để một chứng thư người ký lọt vào đó thì nó
  tự làm trust anchor cho chính mình: chuỗi dài 1, không ai kiểm tra thu hồi,
  và chữ ký bằng chứng thư đã thu hồi vẫn báo hợp lệ. `load_trust_roots()` lọc
  theo `basicConstraints: CA:TRUE` và cảnh báo khi bỏ qua.
- **Font phải có `unitsPerEm = 1000`.** pyHanko xuất mảng `/W` của CIDFont theo
  đơn vị gốc của font, nên font 2048 upem (Arial Unicode MS, DejaVu Sans) bị
  giãn chữ và tràn khung. Font được tự động scale về 1000 upem và cache lại.

## Triển khai

`Dockerfile` chỉ đóng gói backend + giao diện. Agent chạy trên máy người ký,
không bao giờ nằm trong container. `compose.yaml` dựng kèm PostgreSQL:

```bash
WEBSIGNER_SECRET_KEY=$(openssl rand -hex 32) docker compose up -d
```

Sao lưu **cả ba**: cơ sở dữ liệu, nơi chứa PDF (R2 hoặc volume `/data`) và
`WEBSIGNER_SECRET_KEY`.

Ảnh cài sẵn DejaVu Sans để hình chữ ký có dấu tiếng Việt, chạy bằng user
không phải root, và ghi mọi thứ vào `/data` (volume duy nhất cần gắn).

Sau khi dựng, **bắt buộc** làm hai việc thì mới ký được mức B-LT:

1. Chép chứng thư root của các CA công cộng vào `/data/trust/*.crt`. Trust
   store rỗng thì mọi chữ ký báo “chưa được tin cậy”, và hồ sơ B-LT sẽ từ chối
   ký vì không dựng được chuỗi.
2. Đặt `WEBSIGNER_TSA_URL` trỏ tới TSA của CA. Chưa đặt thì hệ thống tự hạ
   xuống B-B (không dấu thời gian, không LTV).

Chạy sau reverse proxy (Traefik của Coolify, Cloudflare…) thì thêm hai thứ,
nếu không liên kết kích hoạt thiết bị sẽ mang scheme/host sai và cookie
`ws_device` không được gắn cờ `Secure`:

1. Env `WEBSIGNER_PUBLIC_URL=https://<domain>` — gốc URL đặt vào `activate_url`.
2. Uvicorn chạy kèm `--proxy-headers --forwarded-allow-ips '*'` (đã có sẵn
   trong `CMD` của `Dockerfile`).

Auto deploy trên Coolify khi repo gắn kiểu *public repository*: Coolify không
tự tạo webhook, phải thêm tay trên GitHub một webhook `push` trỏ tới
`https://<coolify>/webhooks/source/github/events/manual` với secret lấy ở
`manual_webhook_secret_github` của ứng dụng. Thiếu webhook thì push bao nhiêu
lần cũng không có gì chạy.

Backend phải chạy **một tiến trình**: relay agent và trạng thái pha 1 nằm
trong bộ nhớ (xem phần Giới hạn). Hàng đợi webhook/email và mọi dữ liệu khác
đã ở PostgreSQL.

## Giới hạn hiện tại

- `agent/cng.py` **chưa chạy thử trên Windows thật** — không có máy Windows
  trong môi trường phát triển. Phần PKCS#11 (kể cả nhiều token cùng lúc), PFX,
  luồng ký, TSA, LTV đều đã chạy end-to-end.
- Băm cố định SHA-256; chưa có SHA-384/512 hay EdDSA.
- Hai pha ký và relay agent phải nằm trong cùng một tiến trình backend
  (`PreparedSignature` giữ luồng ghi của pyHanko; agent nối WebSocket vào một
  tiến trình cụ thể). Muốn chạy nhiều bản thì phải định tuyến agent qua kênh
  chung (ví dụ PostgreSQL `LISTEN/NOTIFY`) và chuyển trạng thái pha 1 ra ngoài.
  Giới hạn tần suất cũng nằm trong bộ nhớ tiến trình vì lý do đó.
- Chưa nối cổng thanh toán: đổi gói bằng `python -m app.admin set-plan`.
- Chưa có mẫu tài liệu (template) và đặt ô ký theo chữ neo trong PDF: hệ thống
  tích hợp gửi toạ độ ô ký.
- `data/certs/*.pfx` là chứng thư tự ký để chạy thử. Muốn Adobe báo hợp lệ phải
  import `data/trust/demo-ca.crt` làm trust anchor.
- Agent hiển thị tên tài liệu và hash để người ký xác nhận, nhưng không tự dựng
  lại được bản băm từ PDF — tức là không có WYSIWYS đầy đủ. Đây là đánh đổi cố
  hữu của hash-then-sign.
