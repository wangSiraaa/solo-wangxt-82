# OPA 信任策略（Rego）
#
# 该策略只负责第三件独立的事：“声明内容是否符合明确写出的信任策略”。
# 签名是否有效、签发者是否受信任，已经由 Go 侧分别完成，其布尔结论也
# 作为输入传入（policy.signature_valid / policy.issuer_trusted），
# 策略采用默认拒绝（default allow=false）：任何条件不满足都不允许下载。
#
# 策略自带版本与生效窗口；过期策略必须拒绝（见 not_expired 规则）。

package scbverify

import future.keywords.if
import future.keywords.in
import future.keywords.contains

# 策略元数据：判定记录中保存 policy_id / policy_version。
policy_meta := {
	"policy_id": "scb-provenance-policy",
	"policy_version": "2026.09",
}

# 显式允许的构建者身份（必须与信任根中密钥绑定的 issuer 一致）。
allowed_builders := {
	"https://build.example.com/builder/primary",
}

# 显式允许的源码仓库（精确匹配，不做前缀猜测）。
allowed_sources := {
	"git+https://git.example.com/scm/payments/api",
}

# 要求的谓词类型与来源提交必须固定到 commit 摘要。
required_predicate_type := "https://slsa.dev/provenance/v1"

# 策略生效窗口（UTC）。expires 之后 evaluate_time 仍调用 => 过期拒绝。
not_before := "2026-01-01T00:00:00Z"
expires_at := "2027-01-01T00:00:00Z"

default allow := false

allow if {
	count(violation) == 0
}

# violations 枚举所有不满足项，便于复核与失败路径覆盖。
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
	msg := "源码未固定到 commit 摘要（缺少 sha1 或 gitCommit 摘要）"
}

violation contains msg if {
	not window_active
	msg := sprintf("策略已过期或尚未生效（生效窗口 %s 至 %s，评估时间 %s）",
		[not_before, expires_at, input.now])
}

source_allowed if {
	input.statement.source.uri in allowed_sources
}

builder_allowed if {
	input.statement.builder_id in allowed_builders
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
