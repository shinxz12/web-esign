# Web Signer

Ký số PDF bằng USB token qua trình duyệt: mở tài liệu, kéo một khung ở vị trí
muốn ký, chọn chứng thư trên token, bấm ký. Kết quả là PDF có chữ ký PAdES mà
Adobe Reader xác thực được.

Hỗ trợ ký nhiều người theo thứ tự, đóng dấu thời gian (TSA) và lưu trữ dài hạn
(LTV): PAdES B-B / B-T / B-LT / B-LTA.

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
bao giờ gọi vào máy người dùng → không dính cả ba vấn đề trên. Ghép cặp bằng mã
6 số agent in ra.

## Luồng ký và phân quyền

Không có bảng người dùng. Danh tính người ký **chính là chứng thư số**:

- chủ tài liệu giữ cookie `ws_owner`, chỉ thấy tài liệu của mình;
- chủ khai báo thứ tự người ký (tên + MST), hệ thống sinh cho mỗi người một
  liên kết `/s/<invite_token>`;
- server chỉ nhận chữ ký khi **đúng lượt** và **đúng chứng thư** — so MST khi
  có khai báo, so tên đã bỏ dấu khi không.

Tài liệu không khai luồng thì chủ tự ký tự do.

## Chạy thử

```bash
# 1. Môi trường
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements-dev.txt

# 2. Chứng thư test + CRL + PDF mẫu
./scripts/make_test_certs.sh
mkdir -p data/samples && .venv/bin/python scripts/make_sample_pdf.py data/samples/hop-dong-mau.pdf

# 3. TSA test (bỏ qua nếu dùng TSA thật)
.venv/bin/python scripts/tsa_server.py --port 8080

# 4. Backend
cd backend && WEBSIGNER_TSA_URL=http://127.0.0.1:8080/tsa \
  ../.venv/bin/python -m uvicorn app.main:app --port 8000

# 5. Agent (cửa sổ khác)
.venv/bin/python agent/agent.py --pfx data/certs/signer-a.pfx --password 123456
```

Mở http://127.0.0.1:8000 → tải PDF lên → nhập mã ghép cặp agent in ra → chọn
chứng thư → “Đặt chữ ký” rồi kéo khung trên trang → “Ký số”.

Ký một phát qua API để kiểm tra nhanh:

```bash
./scripts/smoke.sh <mã-ghép-cặp> "Lý do ký"
```

Test:

```bash
.venv/bin/python -m pytest -q                  # tất cả (~8s)
.venv/bin/python -m pytest -q -m "not e2e"     # chỉ bất biến, không cần server
.venv/bin/python -m pytest tests/test_e2e.py -v
```

Nhóm `e2e` tự dựng môi trường riêng trong thư mục tạm: cấp CA mới, phát hành
CRL, chạy TSA, chạy backend và agent thật, nạp USB token ảo SoftHSM2 — rồi ký,
xác thực và thử phá. Không mock gì, không đụng vào `data/` của bạn.

### Ký bằng USB token thật

```bash
# Windows: đọc thẳng Certificate Store, không cần biết driver của CA nào
.venv/bin/python agent/agent.py --cng

# macOS/Linux: qua driver PKCS#11 của nhà cung cấp token
.venv/bin/python agent/agent.py --pkcs11 /đường/dẫn/driver.so
```

| Token | Thư viện PKCS#11 |
|---|---|
| SafeNet eToken | `libeToken.dylib` / `eTPKCS11.dll` |
| Feitian ePass2003 | `libcastle.dylib` / `eps2003csp11.dll` |
| Gemalto / Thales | `libgclib.dylib` / `gclib.dll` |

`--cng` nên là lựa chọn mặc định trên Windows: mọi token VN (Viettel-CA,
VNPT-CA, FPT-CA, BKAV, Nacencomm/CA2…) đều cài sẵn CSP/minidriver vào store
`MY`, nên không phải dò đường dẫn driver theo từng CA. Mặc định chỉ nhận chứng
thư có khoá nằm trên thiết bị phần cứng; thêm `--allow-software-key` để nhận cả
khoá mềm.

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
| `backend/app/verify.py` | xác thực chữ ký, LTV, phân tích thay đổi sau khi ký |
| `backend/app/trust.py` | trust anchor và ngữ cảnh kiểm tra thu hồi |
| `backend/app/relay.py` | hub WebSocket, ghép cặp agent bằng mã 6 số |
| `backend/app/store.py` | tài liệu theo revision, luồng ký, quyền sở hữu |
| `backend/app/main.py` | HTTP API + phục vụ giao diện |
| `agent/keysource.py` | giao kèo chung cho mọi nguồn khoá |
| `agent/agent.py` | client relay, nguồn khoá PKCS#11 / PFX |
| `agent/cng.py` | nguồn khoá Windows Certificate Store (CNG + CSP) |
| `web/` | viewer pdf.js, kéo khung chữ ký, panel xác thực |
| `scripts/` | chứng thư test, PDF mẫu, TSA test, token SoftHSM2, smoke test |
| `tests/` | bất biến + e2e (tự dựng CA, CRL, TSA, backend, agent, token ảo) |

## Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `WEBSIGNER_DATA` | `<repo>/data` | thư mục dữ liệu |
| `WEBSIGNER_TRUST_DIR` | `<data>/trust` | **chỉ chứa chứng thư CA** |
| `WEBSIGNER_TSA_URL` | — | URL TSA RFC 3161; chưa đặt thì chỉ ký được B-B |
| `WEBSIGNER_PROFILE` | `B-LT` nếu có TSA, nếu không `B-B` | `B-B`/`B-T`/`B-LT`/`B-LTA` |
| `WEBSIGNER_PREFER_PSS` | tắt | dùng RSA-PSS thay PKCS#1 v1.5 |
| `WEBSIGNER_FONT` | tự dò | font TTF cho hình chữ ký (cần glyph tiếng Việt) |

Hai cái bẫy đã gặp, ghi lại để đừng vấp lại:

- **Trust store chỉ được chứa CA.** Để một chứng thư người ký lọt vào đó thì nó
  tự làm trust anchor cho chính mình: chuỗi dài 1, không ai kiểm tra thu hồi,
  và chữ ký bằng chứng thư đã thu hồi vẫn báo hợp lệ. `load_trust_roots()` lọc
  theo `basicConstraints: CA:TRUE` và cảnh báo khi bỏ qua.
- **Font phải có `unitsPerEm = 1000`.** pyHanko xuất mảng `/W` của CIDFont theo
  đơn vị gốc của font, nên font 2048 upem (Arial Unicode MS, DejaVu Sans) bị
  giãn chữ và tràn khung. Font được tự động scale về 1000 upem và cache lại.

## Giới hạn hiện tại

- `agent/cng.py` **chưa chạy thử trên Windows thật** — không có máy Windows
  trong môi trường phát triển. Phần PKCS#11, PFX, luồng ký, TSA, LTV đều đã
  chạy end-to-end.
- Băm cố định SHA-256; chưa có SHA-384/512 hay EdDSA.
- `find_by_invite()` quét toàn bộ thư mục tài liệu. Đủ ở quy mô này; lên cơ sở
  dữ liệu thì thay bằng chỉ mục.
- Hai pha ký phải nằm trong cùng một tiến trình backend (`PreparedSignature`
  giữ luồng ghi của pyHanko). Muốn chạy nhiều worker thì phải chuyển trạng thái
  pha 1 ra kho dùng chung.
- `data/certs/*.pfx` là chứng thư tự ký để chạy thử. Muốn Adobe báo hợp lệ phải
  import `data/trust/demo-ca.crt` làm trust anchor.
- Agent hiển thị tên tài liệu và hash để người ký xác nhận, nhưng không tự dựng
  lại được bản băm từ PDF — tức là không có WYSIWYS đầy đủ. Đây là đánh đổi cố
  hữu của hash-then-sign.
