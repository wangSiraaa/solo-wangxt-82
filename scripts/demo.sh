#!/usr/bin/env bash
# 端到端演示脚本：对 6 类向量逐一核验并打印独立结论。
# 用法: scripts/demo.sh [服务BASE_URL]
set -u
BASE="${1:-http://127.0.0.1:8080}"
GO="${GO:-go}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

A="demo/artifacts/payments-api-1.4.2.tar.gz"
T="demo/artifacts/payments-api-1.4.2.tampered.tar.gz"
N="payments-api-1.4.2.tar.gz"

run() {
  local title="$1" file="$2" att="$3" want="$4"
  echo "----------------------------------------------------------------"
  echo "▶ $title"
  "$GO" run ./cmd/verifyctl -url "$BASE" -name "$N" -file "$file" "$att" \
    | python3 -c '
import json,sys
d=json.load(sys.stdin)
r=d.get("results",[{}])[0]
print("  signature.valid =", r.get("signature",{}).get("valid"))
print("  issuer.trusted  =", r.get("issuer",{}).get("trusted"))
print("  policy.allowed  =", r.get("policy",{}).get("allowed"))
print("  digest.matched  =", r.get("digest",{}).get("matched"),
      " hardReject =", r.get("digest",{}).get("hardReject", False))
if r.get("policy",{}).get("violations"):
    for v in r["policy"]["violations"]: print("    policy violation:", v)
print("  DECISION        =", d.get("decision"), "-", d.get("decisionReason"))
'
  echo "  (期望: $want)"
}

run "1 正常向量"                 "$A" demo/attestations/01-valid.attestation.json             "allow"
run "2 被改过的文件（硬拒绝）"   "$T" demo/attestations/02-tampered-file.attestation.json    "deny"
run "3 不受信任构建者"           "$A" demo/attestations/03-untrusted-builder.attestation.json "deny"
run "5 源码不在允许列表"         "$A" demo/attestations/05-wrong-source.attestation.json     "deny"
run "6 字段齐全但摘要伪造"       "$A" demo/attestations/06-digest-field-mismatch.attestation.json "deny"

echo "----------------------------------------------------------------"
echo "▶ 4 过期策略（需要用过期策略启动的服务，见脚本结尾说明）"
echo "  当前服务上 04 向量的签名/信任仍成立；策略过期需："
echo "    go run ./cmd/server -trust-root demo/trustroot.json \\"
echo "      -policy demo/policies/trust_policy.expired.rego -addr :8081"
echo "  然后: scripts/demo.sh http://127.0.0.1:8081  # 04 将显示 policy.allowed=false"

echo "----------------------------------------------------------------"
echo "▶ 7 冲突证据（两份同时提交）"
"$GO" run ./cmd/verifyctl -url "$BASE" -name "$N" -file "$A" \
  demo/attestations/01-valid.attestation.json \
  demo/attestations/07-conflicting-commit.attestation.json \
  | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("  DECISION =", d.get("decision"))
print("  冲突分组(结果下标) =", d.get("conflictingEvidence"))
print(" ", d.get("decisionReason"))
'
echo "  (期望: needs_review，两份证据都已留库)"
