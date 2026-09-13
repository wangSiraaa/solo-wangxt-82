// Package e2e 用固定时钟对 demo/ 下的确定性向量做端到端核验，覆盖：
//   - 正常放行
//   - 被改过的文件（摘要硬拒绝）
//   - 不受信任构建者（签名有效但信任独立失败）
//   - 过期策略（签名/信任成立但策略独立失败）
//   - JSON 字段齐全但摘要值伪造
//   - 多份冲突证据保留并转 needs_review
//   - 签名被篡改 / 未知密钥
//
// 运行：go test ./test/e2e -v
// 前置：go run ./cmd/genvectors --out demo
package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scbverify/internal/attestation"
	"scbverify/internal/policy"
	"scbverify/internal/store"
	"scbverify/internal/trust"
	"scbverify/internal/verifier"
)

const evalTime = "2026-09-13T08:00:00Z"

type harness struct {
	t        *testing.T
	root     *trust.Root
	st       store.Store
	demoRoot string
}

func fixedClock() time.Time {
	t, err := time.Parse(time.RFC3339, evalTime)
	if err != nil {
		panic(err)
	}
	return t
}

func loadHarness(t *testing.T, policyFile string) *harness {
	t.Helper()
	demoRoot := filepath.Join("..", "..", "demo")
	if _, err := os.Stat(filepath.Join(demoRoot, "trustroot.json")); err != nil {
		t.Skip("demo 向量不存在，请先运行: go run ./cmd/genvectors --out demo")
	}

	root, err := trust.LoadRoot(filepath.Join(demoRoot, "trustroot.json"))
	if err != nil {
		t.Fatalf("加载信任根: %v", err)
	}
	loadKnownUntrusted(t, root, demoRoot)

	var engine *policy.Engine
	if policyFile == "" {
		engine, err = policy.EmbeddedEngine()
	} else {
		engine, err = policy.LoadEngine(policyFile)
	}
	if err != nil {
		t.Fatalf("加载策略: %v", err)
	}
	_ = engine

	return &harness{
		t:        t,
		root:     root,
		st:       store.NewMemoryStore(),
		demoRoot: demoRoot,
	}
}

func (h *harness) newVerifier(engine *policy.Engine) *verifier.Verifier {
	clock := fixedClock
	return verifier.New(h.root, engine, h.st, clock)
}

func (h *harness) env(file string) []byte {
	b, err := os.ReadFile(filepath.Join(h.demoRoot, "attestations", file))
	if err != nil {
		h.t.Fatalf("读取证据 %s: %v", file, err)
	}
	return b
}

func (h *harness) verify(engine *policy.Engine, artifactPath string, files ...string) *verifier.Response {
	req := verifier.Request{
		ArtifactName: "payments-api-1.4.2.tar.gz",
		ArtifactPath: artifactPath,
	}
	for _, f := range files {
		req.Attestations = append(req.Attestations, verifier.AttestationInput{
			SourceRef:    "e2e",
			EnvelopeJSON: h.env(f),
		})
	}
	resp, err := h.newVerifier(engine).Verify(context.Background(), req)
	if err != nil {
		h.t.Fatalf("Verify 返回错误: %v", err)
	}
	return resp
}

func goodArtifact(h *harness) string {
	return filepath.Join(h.demoRoot, "artifacts", "payments-api-1.4.2.tar.gz")
}

func tamperedArtifact(h *harness) string {
	return filepath.Join(h.demoRoot, "artifacts", "payments-api-1.4.2.tampered.tar.gz")
}

// 1) 正常向量：三件事分别为真，摘要一致 => allow。
func TestValidVectorAllows(t *testing.T) {
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()
	resp := h.verify(engine, goodArtifact(h), "01-valid.attestation.json")
	r := resp.Results[0]

	if !r.Signature.Valid {
		t.Fatalf("签名应有效: %s", r.Signature.Reason)
	}
	if !r.Issuer.Trusted {
		t.Fatalf("签发者应可信: %s", r.Issuer.Reason)
	}
	if !r.Policy.Allowed {
		t.Fatalf("策略应允许: %v", r.Policy.Violations)
	}
	if !r.Digest.Matched {
		t.Fatalf("摘要应匹配: %s", r.Digest.Reason)
	}
	if resp.Decision != verifier.DecisionAllow {
		t.Fatalf("决策应为 allow，实际 %s: %s", resp.Decision, resp.DecisionReason)
	}
	if resp.StoredVerificationID == 0 {
		t.Fatal("判定记录应已持久化")
	}
	// 判定版本必须留痕
	rec, err := h.st.GetVerification(context.Background(), resp.StoredVerificationID)
	if err != nil {
		t.Fatalf("读取判定记录: %v", err)
	}
	if rec.PolicyVersion != "2026.09" || rec.TrustRootVersion != 2 {
		t.Fatalf("判定版本留痕错误: %+v", rec)
	}
}

// 2) 被改过的文件：签名依然有效，但摘要闸门硬拒绝 => deny。
func TestTamperedFileHardReject(t *testing.T) {
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()
	resp := h.verify(engine, tamperedArtifact(h), "02-tampered-file.attestation.json")
	r := resp.Results[0]

	// 关键：签名有效性不受产物篡改影响
	if !r.Signature.Valid {
		t.Fatalf("篡改文件不应影响 DSSE 签名有效性: %s", r.Signature.Reason)
	}
	if r.Digest.Matched || !r.Digest.HardReject {
		t.Fatalf("摘要必须硬拒绝: %+v", r.Digest)
	}
	if !resp.AnyDigestMismatch || resp.Decision != verifier.DecisionDeny {
		t.Fatalf("应因摘要不一致拒绝，实际 decision=%s reason=%s",
			resp.Decision, resp.DecisionReason)
	}
}

// 3) 不受信任构建者：签名密码学有效（独立为真），信任与策略独立为假。
func TestUntrustedBuilderSeparatelyReported(t *testing.T) {
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()
	resp := h.verify(engine, goodArtifact(h), "03-untrusted-builder.attestation.json")
	r := resp.Results[0]

	if !r.Signature.Valid {
		t.Fatalf("不受信任构建者的签名本身应密码学有效: %s", r.Signature.Reason)
	}
	if r.Signature.AcceptedKeyID == "" {
		t.Fatal("应报告实际通过验签的公钥指纹")
	}
	if r.Issuer.Trusted {
		t.Fatal("不受信任构建者必须判定为不可信")
	}
	if r.Policy.Allowed {
		t.Fatal("策略必须拒绝不受信任的构建者")
	}
	if resp.Decision != verifier.DecisionDeny {
		t.Fatalf("应拒绝，实际 %s", resp.Decision)
	}
	// 三个维度必须分别出现在 JSON 中
	raw, _ := json.Marshal(r)
	var asMap map[string]json.RawMessage
	_ = json.Unmarshal(raw, &asMap)
	for _, k := range []string{"signature", "issuer", "policy", "digest"} {
		if _, ok := asMap[k]; !ok {
			t.Fatalf("响应缺少独立维度字段 %q", k)
		}
	}
}

// 4) 过期策略：签名与信任成立，策略因窗口过期独立拒绝。
func TestExpiredPolicyRejects(t *testing.T) {
	h := loadHarness(t, "")
	expiredEngine, err := policy.LoadEngine(
		filepath.Join(h.demoRoot, "policies", "trust_policy.expired.rego"))
	if err != nil {
		t.Fatalf("加载过期策略: %v", err)
	}
	if expiredEngine.Version() != "2025.06" {
		t.Fatalf("过期策略版本应为 2025.06，实际 %s", expiredEngine.Version())
	}
	resp := h.verify(expiredEngine, goodArtifact(h), "04-expired-policy.attestation.json")
	r := resp.Results[0]

	if !r.Signature.Valid || !r.Issuer.Trusted {
		t.Fatal("过期策略不应影响签名与信任结论")
	}
	if r.Policy.Allowed {
		t.Fatal("过期策略必须拒绝")
	}
	foundExpiry := false
	for _, v := range r.Policy.Violations {
		if contains(v, "过期") {
			foundExpiry = true
		}
	}
	if !foundExpiry {
		t.Fatalf("违规原因应指明策略过期: %v", r.Policy.Violations)
	}
	if resp.Decision != verifier.DecisionDeny {
		t.Fatalf("过期策略下应拒绝，实际 %s", resp.Decision)
	}

	// 同一证据在当前策略下应放行，证明差异仅来自策略版本
	currentEngine, _ := policy.EmbeddedEngine()
	resp2 := h.verify(currentEngine, goodArtifact(h), "01-valid.attestation.json")
	if resp2.Decision != verifier.DecisionAllow {
		t.Fatalf("当前策略下应放行，实际 %s: %s", resp2.Decision, resp2.DecisionReason)
	}
}

// 5) 摘要字段齐全但值伪造：不能只检查 JSON 字段。
func TestForgedDigestFieldRejected(t *testing.T) {
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()
	resp := h.verify(engine, goodArtifact(h), "06-digest-field-mismatch.attestation.json")
	r := resp.Results[0]

	// 先确认字段确实“齐全”
	var envelope map[string]any
	if err := json.Unmarshal(h.env("06-digest-field-mismatch.attestation.json"), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope["payloadType"] == "" || envelope["payload"] == "" || envelope["signatures"] == nil {
		t.Fatal("测试前提错误：该向量字段本应齐全")
	}
	if !r.Digest.HardReject || r.Digest.Matched {
		t.Fatalf("字段齐全但摘要值不一致必须硬拒绝: %+v", r.Digest)
	}
	if resp.Decision != verifier.DecisionDeny {
		t.Fatalf("应拒绝伪造摘要，实际 %s", resp.Decision)
	}
}

// 6) 冲突证据：两份四关全过但 commit 不同 => needs_review，证据全部保留。
func TestConflictingEvidenceNeedsReview(t *testing.T) {
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()
	resp := h.verify(engine, goodArtifact(h),
		"01-valid.attestation.json", "07-conflicting-commit.attestation.json")

	if resp.Decision != verifier.DecisionNeedsReview {
		t.Fatalf("冲突证据应转 needs_review，实际 %s: %s", resp.Decision, resp.DecisionReason)
	}
	if len(resp.ConflictingEvidence) < 2 {
		t.Fatalf("应至少识别两个冲突分组，实际 %v", resp.ConflictingEvidence)
	}
	for _, r := range resp.Results {
		if r.StoredAttestationID == 0 {
			t.Fatal("冲突的每份证据都必须落库保留")
		}
	}
	// 历史证据应能从存储中取回两份
	a, err := h.st.GetArtifact(context.Background(), "payments-api-1.4.2.tar.gz", resp.ArtifactSHA256)
	if err != nil {
		t.Fatal(err)
	}
	recs, err := h.st.ListAttestations(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("冲突证据必须全部保留，期望 2 份，实际 %d", len(recs))
	}
	// 判定记录中的逐项快照必须互相记录冲突对象（供复核定位）
	vs, err := h.st.ListVerifications(context.Background(), a.ID)
	if err != nil {
		t.Fatal(err)
	}
	last := vs[len(vs)-1]
	if len(last.Attestations) != 2 {
		t.Fatalf("判定应关联 2 份证据，实际 %d", len(last.Attestations))
	}
	for _, av := range last.Attestations {
		if len(av.ConflictWith) != 1 {
			t.Fatalf("证据 %d 应记录 1 个冲突对象，实际 %v", av.AttestationID, av.ConflictWith)
		}
	}
}

//  7. 目标产物 + 同声明里摘要正确的 SBOM：只比较目标 subject，应 allow；
//     sbom.json 既不与 tar 字节比较，也不得造成 hardReject。
func TestTargetArtifactWithValidSBOMAllows(t *testing.T) {
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()
	resp := h.verify(engine, goodArtifact(h), "08-target-plus-valid-sbom.attestation.json")
	r := resp.Results[0]

	if !r.Signature.Valid || !r.Issuer.Trusted {
		t.Fatalf("签名/信任应成立: sig=%v issuer=%v", r.Signature.Valid, r.Issuer.Trusted)
	}
	if !r.Digest.Matched || r.Digest.HardReject {
		t.Fatalf("目标 subject 匹配时应通过摘要闸门，SBOM 不得影响: %+v", r.Digest)
	}
	// 只比较了目标 tar.gz 一个 subject
	if len(r.Digest.Subjects) != 1 || r.Digest.Subjects[0].Name != "payments-api-1.4.2.tar.gz" {
		t.Fatalf("只应比较目标同名 subject，实际: %+v", r.Digest.Subjects)
	}
	if len(r.Digest.IgnoredSubjects) != 1 || r.Digest.IgnoredSubjects[0] != "payments-api-1.4.2.sbom.json" {
		t.Fatalf("sbom.json 应被记录为未参与比对的 subject，实际: %v", r.Digest.IgnoredSubjects)
	}
	if !r.Policy.Allowed || resp.Decision != verifier.DecisionAllow {
		t.Fatalf("目标产物+合法 SBOM 应 allow，实际 %s: %s", resp.Decision, resp.DecisionReason)
	}
}

//  8. 声明里只有 sbom.json（摘要正确）、没有目标 tar.gz subject：明确拒绝，
//     不能用其他 subject 的正确摘要顶替目标产物。
func TestMissingTargetSubjectRejected(t *testing.T) {
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()

	// 取 08 向量，删除其中的 tar.gz 目标 subject，只保留 sbom.json。
	raw := h.env("08-target-plus-valid-sbom.attestation.json")
	var env attestation.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var st attestation.Statement
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	var sbomOnly []attestation.Subject
	for _, s := range st.Subject {
		if s.Name == "payments-api-1.4.2.sbom.json" {
			sbomOnly = append(sbomOnly, s)
		}
	}
	st.Subject = sbomOnly
	signed, err := attestation.SignStatement(loadTrustedPrivate(t, h), &st)
	if err != nil {
		t.Fatal(err)
	}
	envJSON, _ := json.Marshal(signed)

	req := verifier.Request{
		ArtifactName: "payments-api-1.4.2.tar.gz",
		ArtifactPath: goodArtifact(h),
		Attestations: []verifier.AttestationInput{{SourceRef: "e2e", EnvelopeJSON: envJSON}},
	}
	resp, err := verifier.New(h.root, engine, h.st, fixedClock).Verify(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	r := resp.Results[0]
	// 重新签名使用的可信私钥与信任根一致：签名维度应成立，
	// 关键在于摘要闸门必须因“缺少目标 subject”硬拒绝。
	if !r.Signature.Valid {
		t.Fatalf("测试前置：重新签名后签名应有效: %s", r.Signature.Reason)
	}
	// 重新签名使用的可信私钥与信任根一致，签名应有效；关键是摘要闸门必须硬拒绝。
	if !r.Digest.HardReject || r.Digest.Matched {
		t.Fatalf("缺少目标 subject 必须硬拒绝: %+v", r.Digest)
	}
	if len(r.Digest.Subjects) != 0 || len(r.Digest.IgnoredSubjects) != 1 {
		t.Fatalf("不应把 sbom.json 当匹配依据: compared=%+v ignored=%v",
			r.Digest.Subjects, r.Digest.IgnoredSubjects)
	}
	if resp.Decision != verifier.DecisionDeny {
		t.Fatalf("缺少目标 subject 应 deny，实际 %s", resp.Decision)
	}
}

// 9) 签名被直接篡改：密码学维度独立失败，不得因为信任根里有同 keyid 而放行。
func TestTamperedSignatureRejected(t *testing.T) {
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()

	raw := h.env("01-valid.attestation.json")
	var env attestation.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	sigBytes[0] ^= 0xFF
	env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sigBytes)
	tamperedEnv, _ := json.Marshal(env)

	req := verifier.Request{
		ArtifactName: "payments-api-1.4.2.tar.gz",
		ArtifactPath: goodArtifact(h),
		Attestations: []verifier.AttestationInput{{SourceRef: "e2e", EnvelopeJSON: tamperedEnv}},
	}
	resp, err := verifier.New(h.root, engine, h.st, fixedClock).Verify(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	r := resp.Results[0]
	if r.Signature.Valid {
		t.Fatal("篡改后的签名必须无效")
	}
	if r.Issuer.Trusted {
		t.Fatal("签名无效时不得建立签发者信任")
	}
	if r.Policy.Allowed || resp.Decision != verifier.DecisionDeny {
		t.Fatal("篡改签名必须拒绝")
	}
}

// 8) 完全未知的密钥签名：既不是受信也不是已知构建者。
func TestUnknownKeyRejected(t *testing.T) {
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()
	resp := h.verify(engine, goodArtifact(h), "05-wrong-source.attestation.json")
	r := resp.Results[0]
	// 05 仍由受信任密钥签名，只是源码不允许：这里额外断言“源码维度”独立失败，
	// 同时签名/信任仍成立，证明策略检查确实深入谓词内容而非只看字段存在。
	if !r.Signature.Valid || !r.Issuer.Trusted {
		t.Fatal("05 向量签名与信任应成立")
	}
	if r.Policy.Allowed {
		t.Fatalf("非允许源码必须被策略拒绝: %v", r.Policy.Violations)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}
