#!/usr/bin/env bash
# Dựng token PKCS#11 ảo bằng SoftHSM2 để thử đúng đường ký của USB token thật
# (CKM_SHA256_RSA_PKCS, CKM_SHA256_RSA_PKCS_PSS, CKM_ECDSA*) khi trong tay
# chưa có token.
#
# Cần: brew install softhsm   (hoặc apt install softhsm2)
#
#   scripts/make_softhsm_token.sh [đường/dẫn.pfx] [nhãn token]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PFX="${1:-$ROOT/data/certs/signer-a.pfx}"
LABEL="${2:-${TOKEN_LABEL:-TOKEN-TEST}}"
PFX_PASSWORD="${PFX_PASSWORD:-123456}"
PIN="${TOKEN_PIN:-123456}"
PY="$ROOT/.venv/bin/python"

for candidate in \
  /opt/homebrew/lib/softhsm/libsofthsm2.so \
  /usr/local/lib/softhsm/libsofthsm2.so \
  /usr/lib/softhsm/libsofthsm2.so; do
  [ -f "$candidate" ] && MODULE="$candidate" && break
done
: "${MODULE:?Không tìm thấy libsofthsm2.so — cài softhsm trước}"

DATA="${WEBSIGNER_DATA:-$ROOT/data}"
export SOFTHSM2_CONF="$DATA/softhsm/softhsm2.conf"
mkdir -p "$DATA/softhsm/tokens"
cat > "$SOFTHSM2_CONF" <<EOF
directories.tokendir = $DATA/softhsm/tokens
objectstore.backend = file
log.level = ERROR
EOF

echo "==> Khởi tạo token '$LABEL'"
softhsm2-util --init-token --free --label "$LABEL" --pin "$PIN" --so-pin "$(( ${PIN} + 531111 ))" >/dev/null

echo "==> Nạp khoá riêng"
KEY_TMP="$(mktemp -t websigner-key)"
trap 'rm -f "$KEY_TMP"' EXIT
openssl pkcs12 -in "$PFX" -nocerts -nodes -passin "pass:$PFX_PASSWORD" -out "$KEY_TMP" 2>/dev/null
softhsm2-util --import "$KEY_TMP" --token "$LABEL" --label signer --id A1 --pin "$PIN" >/dev/null

echo "==> Nạp chứng thư (softhsm2-util không làm được việc này)"
PKCS11_MODULE="$MODULE" TOKEN_LABEL="$LABEL" TOKEN_PIN="$PIN" \
PFX_PATH="$PFX" PFX_PASSWORD="$PFX_PASSWORD" "$PY" - <<'PY'
import os
import pkcs11
from pkcs11 import Attribute, CertificateType, ObjectClass
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12

_, cert, extra = pkcs12.load_key_and_certificates(
    open(os.environ["PFX_PATH"], "rb").read(), os.environ["PFX_PASSWORD"].encode()
)
lib = pkcs11.lib(os.environ["PKCS11_MODULE"])
token = next(iter(lib.get_tokens(token_label=os.environ["TOKEN_LABEL"])))
with token.open(user_pin=os.environ["TOKEN_PIN"], rw=True) as session:
    entries = [(cert, "signer", b"\xa1")]
    entries += [(c, f"ca{i}", bytes([0xB0 + i])) for i, c in enumerate(extra or [])]
    for obj, label, key_id in entries:
        session.create_object({
            Attribute.CLASS: ObjectClass.CERTIFICATE,
            Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
            Attribute.TOKEN: True,
            Attribute.LABEL: label,
            Attribute.ID: key_id,
            Attribute.SUBJECT: obj.subject.public_bytes(),
            Attribute.VALUE: obj.public_bytes(Encoding.DER),
        })
        print(f"    + {label}")
PY

cat <<EOF

Xong. Chạy agent trên token ảo:

  export SOFTHSM2_CONF=$SOFTHSM2_CONF
  .venv/bin/python agent/agent.py --pkcs11 $MODULE --token-label $LABEL --pin $PIN
EOF
