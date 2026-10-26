# Chỉ đóng gói backend + giao diện. Agent chạy trên máy người ký, không ở đây.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    WEBSIGNER_DATA=/data \
    WEBSIGNER_TRUST_DIR=/data/trust \
    WEBSIGNER_FONT=/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf

# DejaVu có đủ glyph tiếng Việt cho hình chữ ký. Font 2048 upem nên sẽ được
# scale về 1000 upem lần chạy đầu rồi cache lại trong /data/.fontcache.
RUN apt-get update \
 && apt-get install -y --no-install-recommends fonts-dejavu-core curl \
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
  CMD curl -fsS http://127.0.0.1:8000/api/session || exit 1

WORKDIR /app/backend
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
