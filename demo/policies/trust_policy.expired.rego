# 过期策略版本：仅用于验证“过期策略拒绝”路径。
package scbverify

import future.keywords.if
import future.keywords.in
import future.keywords.contains

policy_meta := {
	"policy_id": "scb-provenance-policy",
	"policy_version": "2025.06",
}

allowed_builders := {
	"https://build.example.com/builder/primary",
}
allowed_sources := {
	"git+https://git.example.com/scm/payments/api",
}
required_predicate_type := "https://slsa.dev/provenance/v1"
not_before := "2025-01-01T00:00:00Z"
expires_at := "2026-06-01T00:00:00Z"

default allow := false

allow if {
	count(violation) == 0
}

violation contains msg if {
	not input.policy.signature_valid
	msg := "密码学签名未通过（签名有效性是前置条件）"
}
violation contains msg if {
	not input.policy.issuer_trusted
	msg := "签发者不在信任根或身份错配（签发者可信是前置条件）"
}
violation contains msg if {
	not input.policy.digest_match
	msg := "声明摘要与实际产物字节不一致（硬拒绝）"
}
violation contains msg if {
	not input.policy.payload_type_correct
	msg := "DSSE 载荷类型不是 in-toto Statement v1"
}
violation contains msg if {
	input.statement.predicate_type != required_predicate_type
	msg := sprintf("谓词类型 %q 不是受支持的 SLSA Provenance v1", [input.statement.predicate_type])
}
violation contains msg if {
	not builder_allowed
	msg := sprintf("构建者 %q 不在允许列表", [input.statement.builder_id])
}
violation contains msg if {
	not source_allowed
	msg := "源码仓库不在允许列表"
}
violation contains msg if {
	source_allowed
	not commit_pinned
	msg := "源码未固定到 commit 摘要"
}
violation contains msg if {
	not window_active
	msg := sprintf("策略已过期或尚未生效（生效窗口 %s 至 %s，评估时间 %s）",
		[not_before, expires_at, input.now])
}
builder_allowed if {
	input.statement.builder_id in allowed_builders
}
source_allowed if {
	input.statement.source.uri in allowed_sources
}
commit_pinned if {
	some alg in ["sha1", "gitCommit"]
	input.statement.source.digest[alg] != ""
}
window_active if {
	t_now := time.parse_rfc3339_ns(input.now)
	t_lo := time.parse_rfc3339_ns(not_before)
	t_hi := time.parse_rfc3339_ns(expires_at)
	t_now >= t_lo
	t_now < t_hi
}
