# Chỉ đóng gói backend + giao diện. Agent chạy trên máy người ký, không ở đây.
# Cần thêm PostgreSQL (WEBSIGNER_DATABASE_URL) và WEBSIGNER_SECRET_KEY — xem
# compose.yaml để chạy cả hai cùng lúc.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    WEBSIGNER_DATA=/data \
    WEBSIGNER_TRUST_DIR=/data/trust \
    WEBSIGNER_FONT=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf \
    TZ=Asia/Ho_Chi_Minh

# DejaVu có đủ glyph tiếng Việt cho hình chữ ký. Font 2048 upem nên sẽ được
# scale về 1000 upem lần chạy đầu rồi cache lại trong /data/.fontcache.
# tzdata: thiếu nó thì giờ ký trên hình chữ ký hiện +0000 thay vì +07.
# DEBIAN_FRONTEND: thiếu nó thì tzdata bật hộp thoại chọn vùng giờ và
# apt-get đứng im vĩnh viễn trong lúc build.
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      fonts-dejavu-core curl tzdata \
 && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
 && echo "$TZ" > /etc/timezone \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY backend/ backend/
COPY web/ web/
# Chứng thư CA công khai của VN, nạp vào /data/trust lần chạy đầu
COPY trust/ trust/

# Khoá riêng của người ký không bao giờ tới đây, nhưng tài liệu thì có.
RUN useradd --system --uid 10001 websigner \
 && mkdir -p /data/trust /data/documents \
 && chown -R websigner:websigner /data
USER websigner

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1

WORKDIR /app/backend
# --proxy-headers: sau reverse proxy (Traefik/Cloudflare) thì không có nó
# request.url.scheme luôn là http -> liên kết kích hoạt thiết bị sai scheme và
# cookie không được gắn cờ Secure.
# Đúng một tiến trình: relay agent và pha 1 của lượt ký nằm trong bộ nhớ.
CMD ["python", "-m", "uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
