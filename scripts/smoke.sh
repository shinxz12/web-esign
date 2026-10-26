#!/usr/bin/env bash
# Chạy một lượt ký qua API và in báo cáo xác thực.
#   scripts/smoke.sh <mã agent> [lý do]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
BASE="${WEBSIGNER_URL:-http://127.0.0.1:8000}"
CODE="${1:?cần mã ghép cặp của agent}"
REASON="${2:-Phê duyệt tài liệu}"
JAR="$(mktemp -t websigner-cookies)"

doc=$(curl -s -c "$JAR" -b "$JAR" -F "file=@$ROOT/data/samples/hop-dong-mau.pdf" \
  "$BASE/api/documents" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["id"])')

cert=$(curl -s -b "$JAR" "$BASE/api/agents/$CODE/certificates" \
  | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["certificates"][0]["id"])')

echo "tài liệu $doc, chứng thư $cert"
curl -s -b "$JAR" -X POST "$BASE/api/documents/$doc/sign" \
  -H 'Content-Type: application/json' \
  -d "{\"agent_code\":\"$CODE\",\"cert_id\":\"$cert\",\"page\":1,\"box\":[65,383,238,484],\"reason\":\"$REASON\"}" \
  | "$PY" -c 'import sys,json;d=json.load(sys.stdin);print("HTTP lỗi:",d["detail"]) if "detail" in d else print("đã ký, revision",d["revision"])'

curl -s -b "$JAR" "$BASE/api/documents/$doc/verify" | "$PY" -c '
import sys, json
for r in json.load(sys.stdin):
    print("  {field_name} | {signer} | {profile} | TSA={timestamped} LTV={ltv} | {summary}".format(**r))
    for p in r["problems"]:
        print("      ! " + p)
    for n in r["notes"]:
        print("      · " + n)
'
echo "$doc"
rm -f "$JAR"
