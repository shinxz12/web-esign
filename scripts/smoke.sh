#!/usr/bin/env bash
# Chạy một lượt ký trọn vẹn qua API tích hợp và in báo cáo xác thực.
#   WEBSIGNER_API_KEY=wsk_live_… scripts/smoke.sh <mã agent>
# Người nhận được khai đúng theo chứng thư đầu tiên agent đang cầm.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
BASE="${WEBSIGNER_URL:-http://127.0.0.1:8000}"
KEY="${WEBSIGNER_API_KEY:?cần WEBSIGNER_API_KEY (tạo ở mục Nhà phát triển)}"
CODE="${1:?cần mã ghép cặp của agent}"
BOX="${2:-[65,390,230,480]}"   # ô ký chuẩn 165×90 pt

cert_json=$(curl -sf "$BASE/api/agents/$CODE/certificates")
cert=$(printf '%s' "$cert_json" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["certificates"][0]["id"])')
data=$(printf '%s' "$cert_json" | "$PY" -c '
import sys, json
c = json.load(sys.stdin)["certificates"][0]
print(json.dumps({"title": "Smoke test", "send": True,
                  "recipients": [{"name": c["subject"], "tax_code": c.get("tax_code")}]}))')

doc_json=$(curl -sf -H "Authorization: Bearer $KEY" \
  -F "file=@$ROOT/data/samples/hop-dong-mau.pdf" -F "data=$data" "$BASE/v1/documents")
doc=$(printf '%s' "$doc_json" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["id"])')
token=$(printf '%s' "$doc_json" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["recipients"][0]["signing_url"].rsplit("/s/",1)[1])')

echo "tài liệu $doc, chứng thư $cert"
curl -s -X POST "$BASE/api/sign/$token/sign" \
  -H 'Content-Type: application/json' \
  -d "{\"agent_code\":\"$CODE\",\"cert_id\":\"$cert\",\"page\":1,\"box\":$BOX}" \
  | "$PY" -c 'import sys,json;d=json.load(sys.stdin);print("HTTP lỗi:",d["detail"]) if "detail" in d else print("đã ký, trạng thái",d["document"]["status"])'

curl -s -H "Authorization: Bearer $KEY" "$BASE/v1/documents/$doc/verify" | "$PY" -c '
import sys, json
for r in json.load(sys.stdin):
    print("  {field_name} | {signer} | {profile} | TSA={timestamped} LTV={ltv} | {summary}".format(**r))
    for p in r["problems"]:
        print("      ! " + p)
    for n in r["notes"]:
        print("      · " + n)
'
echo "$doc"
