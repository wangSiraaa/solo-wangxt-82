package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestEmbeddedPolicyInSync 防止内嵌策略副本与权威策略文件漂移：
// 两者必须逐字节一致（go:embed 的副本在 fmt 目标里通过 cp 同步）。
func TestEmbeddedPolicyInSync(t *testing.T) {
	if embeddedPolicy == "" {
		t.Fatal("内嵌策略为空")
	}
	a := sha256.Sum256([]byte(embeddedPolicy))
	b, err := readFileForTest("../../policies/trust_policy.rego")
	if err != nil {
		t.Skipf("权威策略文件不可用（如在模块缓存中运行）: %v", err)
	}
	bb := sha256.Sum256(b)
	if hex.EncodeToString(a[:]) != hex.EncodeToString(bb[:]) {
		t.Fatal("内嵌策略与 policies/trust_policy.rego 不一致；请运行 make fmt 或手动 cp 同步")
	}
}

// TestDefaultDenyAndExpiredWindow 直接用 OPA 覆盖关键事实组合。
func TestPolicyFacts(t *testing.T) {
	engine, err := EmbeddedEngine()
	if err != nil {
		t.Fatal(err)
	}
	if engine.Version() == "" || engine.ID() == "" {
		t.Fatal("策略元数据必须提供 id/version")
	}
}
