#!/usr/bin/env bash
# Sinh bộ chứng thư test mô phỏng CA công cộng VN, kèm CRL và chứng thư TSA.
# KHÔNG dùng cho production — chỉ để chạy thử luồng ký khi chưa có USB token.
#
# Sinh ra:
#   ca.crt          root CA (trust anchor)
#   demo-ca.crl     CRL dạng DER, backend phục vụ tại /crl/demo-ca.crl
#   signer-a.pfx    NGUYỄN VĂN A        — RSA 2048
#   signer-b.pfx    TRẦN THỊ BÍCH       — RSA 2048
#   signer-ec.pfx   LÊ MINH CƯỜNG       — ECDSA P-256
#   signer-revoked.pfx  PHẠM THU HÀ     — RSA 2048, đã bị thu hồi
#   tsa.crt/tsa.key chứng thư cấp dấu thời gian cho scripts/tsa_server.py
set -euo pipefail

OUT="${1:-$(cd "$(dirname "$0")/.." && pwd)/data/certs}"
PASS="${PFX_PASSWORD:-123456}"
CRL_URL="${CRL_URL:-http://127.0.0.1:8000/crl/demo-ca.crl}"

rm -rf "$OUT"
mkdir -p "$OUT/ca/newcerts"
cd "$OUT"
: > ca/index.txt
echo 1000 > ca/serial
echo 1000 > ca/crlnumber

cat > openssl.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $OUT
database          = \$dir/ca/index.txt
serial            = \$dir/ca/serial
crlnumber         = \$dir/ca/crlnumber
new_certs_dir     = \$dir/ca/newcerts
certificate       = \$dir/ca.crt
private_key       = \$dir/ca.key
default_md        = sha256
default_days      = 730
default_crl_days  = 30
policy            = policy_any
unique_subject    = no
email_in_dn       = no

[ policy_any ]
countryName            = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied

[ req ]
distinguished_name = req_dn
[ req_dn ]

[ v3_signer ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature,nonRepudiation
extendedKeyUsage       = emailProtection,1.3.6.1.4.1.311.10.3.12
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints  = URI:$CRL_URL

[ v3_tsa ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature,nonRepudiation
extendedKeyUsage       = critical,timeStamping
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints  = URI:$CRL_URL
EOF

echo "==> Root CA"
openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/C=VN/O=DEMO-CA/CN=DEMO-CA Root (TEST ONLY)" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" 2>/dev/null

# issue <tên tệp> <CN> <O> <MST> <rsa|ec> <v3_signer|v3_tsa>
issue() {
  local name="$1" cn="$2" org="$3" mst="$4" kind="$5" ext="$6"

  if [ "$kind" = "ec" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "$name.key" 2>/dev/null
  else
    openssl genrsa -out "$name.key" 2048 2>/dev/null
  fi

  openssl req -new -key "$name.key" -sha256 -out "$name.csr" \
    -subj "/C=VN/O=$org/OU=MST:$mst/CN=$cn" 2>/dev/null

  openssl ca -batch -config openssl.cnf -extensions "$ext" \
    -in "$name.csr" -out "$name.crt" -notext 2>/dev/null

  openssl pkcs12 -export -out "$name.pfx" -inkey "$name.key" -in "$name.crt" \
    -certfile ca.crt -name "$cn" -passout "pass:$PASS"

  rm -f "$name.csr"
  echo "    $cn ($kind)"
}

echo "==> Người ký"
issue signer-a       "NGUYEN VAN A"    "CONG TY TNHH DEMO"      0101234567 rsa v3_signer
issue signer-b       "TRAN THI BICH"   "CONG TY CP THU NGHIEM"  0107654321 rsa v3_signer
issue signer-ec      "LE MINH CUONG"   "CONG TY TNHH EC"        0109999999 ec  v3_signer
issue signer-revoked "PHAM THU HA"     "CONG TY DA DONG CUA"    0100000000 rsa v3_signer

echo "==> Chứng thư cấp dấu thời gian (TSA)"
issue tsa "DEMO-CA Timestamping Authority" "DEMO-CA" 0100000001 rsa v3_tsa

echo "==> Thu hồi signer-revoked và phát hành CRL"
openssl ca -batch -config openssl.cnf -revoke signer-revoked.crt \
  -crl_reason keyCompromise 2>/dev/null
# `openssl ca -gencrl` chỉ xuất PEM, phải chuyển sang DER cho trình xác thực
openssl ca -batch -config openssl.cnf -gencrl -out demo-ca.crl.pem 2>/dev/null
openssl crl -in demo-ca.crl.pem -outform DER -out demo-ca.crl
rm -f demo-ca.crl.pem

# Trust store chỉ chứa CA. Để leaf lọt vào đây là nó tự làm anchor cho chính
# mình: chuỗi dài 1, không kiểm tra thu hồi, chữ ký đã thu hồi vẫn báo hợp lệ.
TRUST_DIR="$(dirname "$OUT")/trust"
mkdir -p "$TRUST_DIR"
cp ca.crt "$TRUST_DIR/demo-ca.crt"

cat <<EOF

Xong. Thư mục: $OUT
  ca.crt             root CA (bản gốc)
  demo-ca.crl        CRL (DER), backend phục vụ tại $CRL_URL
  signer-*.pfx       giả lập token, mật khẩu: $PASS
  tsa.crt / tsa.key  dùng cho scripts/tsa_server.py

Trust store: $TRUST_DIR
  demo-ca.crt        trust anchor — cũng cần import vào Adobe
EOF
