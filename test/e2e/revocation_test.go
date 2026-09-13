// Package e2e 密钥撤销 / 历史复核 / 依赖链传播 / 离线包端到端测试。
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scbverify/internal/offline"
	"scbverify/internal/policy"
	"scbverify/internal/review"
	"scbverify/internal/revocation"
	"scbverify/internal/timestampevidence"
	"scbverify/internal/verifier"
)

type revFixture struct {
	h        *harness
	scenario map[string]any
	feed     *revocation.List
	now      time.Time
}

func loadRevocationFixture(t *testing.T) *revFixture {
	t.Helper()
	h := loadHarness(t, "")
	dir := filepath.Join(h.demoRoot, "revocation")
	if _, err := os.Stat(filepath.Join(dir, "revocation-scenario.json")); err != nil {
		t.Skip("撤销场景不存在，请先运行 genvectors")
	}
	feed, err := revocation.LoadFeed(filepath.Join(dir, "revocation-feed.json"))
	if err != nil {
		t.Fatal(err)
	}
	scRaw, err := os.ReadFile(filepath.Join(dir, "revocation-scenario.json"))
	if err != nil {
		t.Fatal(err)
	}
	var scenario map[string]any
	if err := json.Unmarshal(scRaw, &scenario); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, evalTime)
	if err != nil {
		t.Fatal(err)
	}
	return &revFixture{h: h, scenario: scenario, feed: feed, now: now}
}

type revEvidence struct {
	ArtifactName string   `json:"artifactName"`
	Attestation  string   `json:"attestation"`
	Timestamps   []string `json:"timestamps"`
}

// seedRevocationStore 把场景中的产物/证据/时间证据/依赖链灌入存储：
// 每个产物走一次真实 gate 核验（带撤销清单），触发依赖边持久化；
// 再把 TSA 时间证据入库（除了名字指定跳过的）。
func (f *revFixture) seedRevocationStore(t *testing.T, skipTS map[string]bool) {
	t.Helper()
	ctx := context.Background()
	v := verifier.NewWithRevocation(f.h.root, mustEmbeddedEngine(t), f.h.st, f.feed, fixedClock)

	rawList, _ := json.Marshal(f.scenario["evidence"])
	var refs []revEvidence
	if err := json.Unmarshal(rawList, &refs); err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		attPath := filepath.Join(f.h.demoRoot, r.Attestation)
		envJSON := mustReadFile(t, attPath)
		artPath := filepath.Join(f.h.demoRoot, "revocation", "artifacts", r.ArtifactName)
		req := verifier.Request{
			ArtifactName: r.ArtifactName,
			ArtifactPath: artPath,
			Attestations: []verifier.AttestationInput{{SourceRef: "rev-ci", EnvelopeJSON: envJSON}},
		}
		if _, err := v.Verify(ctx, req); err != nil {
			t.Fatalf("gate 核验 %s 失败: %v", r.ArtifactName, err)
		}
		if skipTS[r.ArtifactName] {
			continue
		}
		// 计算信封摘要并把每条 TSA 证据入库。
		envSHA := canonicalEnvSHA(envJSON)
		for _, tsRel := range r.Timestamps {
			tsPath := filepath.Join(f.h.demoRoot, tsRel)
			ev, err := timestampevidence.LoadEvidenceFile(tsPath)
			if err != nil {
				t.Fatal(err)
			}
			svc := review.NewService(f.h.st, f.h.root, mustEmbeddedEngine(t), f.feed, fixedClock)
			if _, err := svc.IngestTimeEvidence(ctx, envSHA, ev); err != nil {
				t.Fatalf("补入时间证据失败 %s: %v", tsRel, err)
			}
		}
	}
}

func mustEmbeddedEngine(t *testing.T) *policy.Engine {
	t.Helper()
	e, err := policy.EmbeddedEngine()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (f *revFixture) expectedClass(name string) string {
	m := f.scenario["expectedClassification"].(map[string]any)
	return m[name].(string)
}

// 1) 根产物三分类 + 多级引用传播。
func TestRevocationRootClassifications(t *testing.T) {
	f := loadRevocationFixture(t)
	f.seedRevocationStore(t, nil)
	ctx := context.Background()

	rootGoodSHA := sha256Hex(mustReadFile(t,
		filepath.Join(f.h.demoRoot, "revocation", "artifacts", "root-good-1.0.tar.gz")))
	svc := review.NewService(f.h.st, f.h.root, mustEmbeddedEngine(t), f.feed, fixedClock)
	report, err := svc.Review(ctx, "root-good-1.0.tar.gz", rootGoodSHA)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, a := range report.Artifacts {
		got[a.Name] = a.Classification
	}
	// 从 root-good 出发：只沿其固定依赖链向上、沿“谁引用了我”向下。
	// root-good 被 downstream-once -> twice-a -> twice-b 三级引用，全部 unaffected。
	// root-orphan/insufficient 与该闭包没有边，不应出现。
	cases := map[string]string{
		"root-good-1.0.tar.gz":          "unaffected",
		"downstream-once-1.0.tar.gz":    "unaffected",
		"downstream-twice-a-1.0.tar.gz": "unaffected",
		"downstream-twice-b-1.0.tar.gz": "unaffected",
	}
	for name, want := range cases {
		if got[name] != want {
			t.Errorf("%s: got=%s want=%s", name, got[name], want)
		}
	}
	for name := range got {
		switch name {
		case "root-good-1.0.tar.gz", "downstream-once-1.0.tar.gz",
			"downstream-twice-a-1.0.tar.gz", "downstream-twice-b-1.0.tar.gz":
		default:
			t.Errorf("root-good 闭包不应包含 %s", name)
		}
	}

	// 从 affected 的 root-orphan 出发：污染传播到所有固定引用它的下游。
	rootOrphanSHA := sha256Hex(mustReadFile(t,
		filepath.Join(f.h.demoRoot, "revocation", "artifacts", "root-orphan-1.0.tar.gz")))
	reportOrphan, err := svc.Review(ctx, "root-orphan-1.0.tar.gz", rootOrphanSHA)
	if err != nil {
		t.Fatal(err)
	}
	gotOrphan := map[string]string{}
	for _, a := range reportOrphan.Artifacts {
		gotOrphan[a.Name] = a.Classification
	}
	for name, want := range map[string]string{
		"root-orphan-1.0.tar.gz":            "affected",
		"downstream-propagated-1.0.tar.gz":  "affected",
		"downstream-of-affected-1.0.tar.gz": "affected",
	} {
		if gotOrphan[name] != want {
			t.Errorf("orphan 闭包 %s: got=%s want=%s", name, gotOrphan[name], want)
		}
	}

	// root-insufficient 独立复核：无 TSA 证据 => insufficient（自报时间不算）。
	insSHA := sha256Hex(mustReadFile(t,
		filepath.Join(f.h.demoRoot, "revocation", "artifacts", "root-insufficient-1.0.tar.gz")))
	reportIns, err := svc.Review(ctx, "root-insufficient-1.0.tar.gz", insSHA)
	if err != nil {
		t.Fatal(err)
	}
	if classOf(reportIns, "root-insufficient-1.0.tar.gz") != "insufficient" {
		t.Fatalf("root-insufficient 应 insufficient，实际 %s",
			classOf(reportIns, "root-insufficient-1.0.tar.gz"))
	}
	ar := attestationIn(reportIns, "root-insufficient-1.0.tar.gz")
	if ar.SelfReportedTime == "" || !ar.SelfReportedTimeUntrusted {
		t.Fatal("自报时间必须留证并标注不可信，且不得用于洗白")
	}
	// 独立产物在另一组件上，只有从它自己复核时出现（这里不强求被根闭包包含）。
	if report.RealTimeValid {
		t.Fatal("复核报告不得声称实时有效")
	}
	if report.RevocationCutoff.IsZero() {
		t.Fatal("复核报告必须标注撤销信息更新截止")
	}
}

// 2) 独立产物（未撤销密钥）单独复核为 unaffected。
func TestRevocationIndependentUnaffected(t *testing.T) {
	f := loadRevocationFixture(t)
	f.seedRevocationStore(t, nil)
	ctx := context.Background()
	sha := sha256Hex(mustReadFile(t,
		filepath.Join(f.h.demoRoot, "revocation", "artifacts", "independent-1.0.tar.gz")))
	svc := review.NewService(f.h.st, f.h.root, mustEmbeddedEngine(t), f.feed, fixedClock)
	report, err := svc.Review(ctx, "independent-1.0.tar.gz", sha)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range report.Artifacts {
		if a.Name == "independent-1.0.tar.gz" {
			found = true
			if a.Classification != "unaffected" {
				t.Fatalf("独立产物应 unaffected，实际 %s", a.Classification)
			}
		}
	}
	if !found {
		t.Fatal("复核结果缺少独立产物")
	}
}

// 3) 实时下载闸门：撤销密钥签名一律 deny，时间证据不放行。
func TestRevocationGateFailsClosed(t *testing.T) {
	f := loadRevocationFixture(t)
	f.seedRevocationStore(t, nil)
	ctx := context.Background()
	v := verifier.NewWithRevocation(f.h.root, mustEmbeddedEngine(t), f.h.st, f.feed, fixedClock)

	for _, name := range []string{"root-good-1.0.tar.gz", "root-orphan-1.0.tar.gz",
		"downstream-twice-b-1.0.tar.gz"} {
		attPath := filepath.Join(f.h.demoRoot, "revocation", "attestations", "att-"+name+".json")
		envJSON := mustReadFile(t, attPath)
		artPath := filepath.Join(f.h.demoRoot, "revocation", "artifacts", name)
		resp, err := v.Verify(ctx, verifier.Request{
			ArtifactName: name, ArtifactPath: artPath,
			Attestations: []verifier.AttestationInput{{SourceRef: "gate", EnvelopeJSON: envJSON}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.Decision != verifier.DecisionDeny {
			t.Fatalf("%s: 撤销密钥实时闸门必须 deny，实际 %s", name, resp.Decision)
		}
		r := resp.Results[0]
		if r.Revocation == nil || !r.Revocation.Revoked {
			t.Fatalf("%s: 应记录撤销闸门命中", name)
		}
		if !r.Signature.Valid {
			t.Fatalf("%s: 签名本身仍应密码学有效", name)
		}
	}
}

// 4) 未撤销的第二构建者不受撤销影响，实时闸门仍 allow。
func TestRevocationGateAllowsUnrevokedKey(t *testing.T) {
	f := loadRevocationFixture(t)
	f.seedRevocationStore(t, nil)
	ctx := context.Background()
	v := verifier.NewWithRevocation(f.h.root, mustEmbeddedEngine(t), f.h.st, f.feed, fixedClock)
	name := "independent-1.0.tar.gz"
	envJSON := mustReadFile(t, filepath.Join(f.h.demoRoot, "revocation", "attestations", "att-"+name+".json"))
	resp, err := v.Verify(ctx, verifier.Request{
		ArtifactName: name,
		ArtifactPath: filepath.Join(f.h.demoRoot, "revocation", "artifacts", name),
		Attestations: []verifier.AttestationInput{{SourceRef: "gate", EnvelopeJSON: envJSON}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != verifier.DecisionAllow {
		t.Fatalf("未撤销密钥应 allow，实际 %s: %s", resp.Decision, resp.DecisionReason)
	}
}

//  5. 撤销后补入可信时间证据：原本 insufficient 的产物，补一个撤销后的 TSA 戳，
//     必须判 affected（补盖不能洗白）；而撤销前的 TSA 戳判 unaffected。
func TestRetroactiveTimeEvidenceCannotWhitewash(t *testing.T) {
	f := loadRevocationFixture(t)
	// 初始不灌入 root-orphan 的时间证据之外，对 root-insufficient 始终先无证据。
	f.seedRevocationStore(t, map[string]bool{"root-insufficient-1.0.tar.gz": true})
	ctx := context.Background()
	svc := review.NewService(f.h.st, f.h.root, mustEmbeddedEngine(t), f.feed, fixedClock)

	insufficientSHA := sha256Hex(mustReadFile(t,
		filepath.Join(f.h.demoRoot, "revocation", "artifacts", "root-insufficient-1.0.tar.gz")))
	attEnv := mustReadFile(t, filepath.Join(f.h.demoRoot, "revocation",
		"attestations", "att-root-insufficient-1.0.tar.gz.json"))

	// 第一次复核：没有任何时间证据 => insufficient。
	r1, err := svc.Review(ctx, "root-insufficient-1.0.tar.gz", insufficientSHA)
	if err != nil {
		t.Fatal(err)
	}
	if classOf(r1, "root-insufficient-1.0.tar.gz") != "insufficient" {
		t.Fatalf("无时间证据应 insufficient，实际 %s", classOf(r1, "root-insufficient-1.0.tar.gz"))
	}

	// 撤销后补盖一个 TSA 戳（2026-04-02，晚于 compromised 2026-03-05）。
	late := time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)
	lateEv, err := buildTSAEvidence(t, f, attEnv, late)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestTimeEvidence(ctx, canonicalEnvSHA(attEnv), lateEv); err != nil {
		t.Fatal(err)
	}
	r2, err := svc.Review(ctx, "root-insufficient-1.0.tar.gz", insufficientSHA)
	if err != nil {
		t.Fatal(err)
	}
	if got := classOf(r2, "root-insufficient-1.0.tar.gz"); got != "affected" {
		t.Fatalf("撤销后补盖时间证据应判 affected，实际 %s", got)
	}
	ar := attestationIn(r2, "root-insufficient-1.0.tar.gz")
	if ar.SelfReportedTime == "" || !ar.SelfReportedTimeUntrusted {
		t.Fatal("自报时间必须留证且显式标注不可信")
	}
	if ar.EarliestTrusted == nil {
		t.Fatal("应记录用于判定的最早可信时间")
	}

	// 再补一个撤销前的 TSA 戳（2026-02-10）：取最早可信时间 => unaffected。
	early := time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)
	earlyEv, err := buildTSAEvidence(t, f, attEnv, early)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestTimeEvidence(ctx, canonicalEnvSHA(attEnv), earlyEv); err != nil {
		t.Fatal(err)
	}
	r3, err := svc.Review(ctx, "root-insufficient-1.0.tar.gz", insufficientSHA)
	if err != nil {
		t.Fatal(err)
	}
	if got := classOf(r3, "root-insufficient-1.0.tar.gz"); got != "unaffected" {
		t.Fatalf("补入撤销前 TSA 证据后应按最早可信时间判 unaffected，实际 %s", got)
	}
}

// 6) 历史可回看：多次复核产生多条 review 记录；原始 gate 记录与信封不被覆盖。
func TestReviewHistoryAppendOnly(t *testing.T) {
	f := loadRevocationFixture(t)
	f.seedRevocationStore(t, map[string]bool{"root-insufficient-1.0.tar.gz": true})
	ctx := context.Background()
	svc := review.NewService(f.h.st, f.h.root, mustEmbeddedEngine(t), f.feed, fixedClock)
	sha := sha256Hex(mustReadFile(t,
		filepath.Join(f.h.demoRoot, "revocation", "artifacts", "root-good-1.0.tar.gz")))

	if _, err := svc.Review(ctx, "root-good-1.0.tar.gz", sha); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Review(ctx, "root-good-1.0.tar.gz", sha); err != nil {
		t.Fatal(err)
	}
	a, err := f.h.st.GetArtifact(ctx, "root-good-1.0.tar.gz", sha)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := f.h.st.ListVerifications(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	var gateCount, reviewCount int
	for _, v := range vs {
		switch v.ReviewKind {
		case "gate":
			gateCount++
		case "review":
			reviewCount++
			if v.Classification == "" {
				t.Fatal("review 记录必须带分类")
			}
		}
	}
	if gateCount == 0 {
		t.Fatal("原始 gate 判定记录必须保留")
	}
	if reviewCount != 2 {
		t.Fatalf("两次复核应新增 2 条 review 记录（不覆盖），实际 %d", reviewCount)
	}
	// 原始信封仍只有 seed 时的那一份，且内容摘要未变。
	recs, err := f.h.st.ListAttestations(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("复核不得新增/覆盖信封，期望 1 份，实际 %d", len(recs))
	}
	envSHA := canonicalEnvSHA(mustReadFile(t, filepath.Join(f.h.demoRoot,
		"revocation", "attestations", "att-root-good-1.0.tar.gz.json")))
	if canonicalEnvSHA(recs[0].EnvelopeJSON) != envSHA {
		t.Fatal("原始 DSSE 信封规范化摘要不一致（内容被改动）")
	}
}

// 7) 离线核验包：自带策略/信任根/撤销/证据摘要，结论非实时并标注截止。
func TestOfflineBundle(t *testing.T) {
	f := loadRevocationFixture(t)
	f.seedRevocationStore(t, nil)

	bundleDir := t.TempDir()
	demoDir := f.h.demoRoot
	attPath := filepath.Join(demoDir, "revocation", "attestations", "att-root-good-1.0.tar.gz.json")
	tsPath := filepath.Join(demoDir, "revocation", "timestamps", "ts-root-good-1.0.tar.gz.json")

	m, err := offline.Build(offline.BundleSpec{
		OutDir:            bundleDir,
		PolicyPath:        filepath.Join("..", "..", "policies", "trust_policy.rego"),
		TrustRootPath:     filepath.Join(demoDir, "trustroot.json"),
		RevocationPath:    filepath.Join(demoDir, "revocation", "revocation-feed.json"),
		AttestationPaths:  []string{attPath},
		TimeEvidencePaths: []string{tsPath},
		ArtifactNames:     map[string]string{attPath: "root-good-1.0.tar.gz"},
		RevocationFeedVer: 3,
		RevocationCutoff:  time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.RealTimeValid {
		t.Fatal("离线包不得声称实时有效")
	}
	artPath := filepath.Join(demoDir, "revocation", "artifacts", "root-good-1.0.tar.gz")
	concl, err := offline.Verify(context.Background(), bundleDir,
		[]offline.ArtifactFile{{Name: "root-good-1.0.tar.gz", Path: artPath}}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if concl.RealTimeValid {
		t.Fatal("离线结论不得标记实时有效")
	}
	if concl.RevocationCutoff.IsZero() {
		t.Fatal("离线结论必须带撤销更新截止")
	}
	if len(concl.ByEvidence) != 1 {
		t.Fatalf("应输出 1 份证据结论，实际 %d", len(concl.ByEvidence))
	}
	c := concl.ByEvidence[0]
	// root-good 的签名密钥已撤销：实时闸门 deny，但历史分类 unaffected。
	if concl.GateDecision != "deny" {
		t.Fatalf("撤销密钥在截止时点的下载闸门必须 deny，实际 %s", concl.GateDecision)
	}
	if !c.KeyRevoked {
		t.Fatal("应标记密钥已撤销")
	}
	if c.HistoricalClassification != "unaffected" {
		t.Fatalf("撤销前 TSA 证据应判 unaffected，实际 %s（%s）",
			c.HistoricalClassification, c.HistoricalReason)
	}
	if c.SelfReportedTime == "" || !c.SelfReportedTimeUntrusted {
		t.Fatal("自报时间应留证并标注不可信")
	}
	if c.TrustedTimestampCount != 1 {
		t.Fatalf("应有 1 条可信时间证据，实际 %d", c.TrustedTimestampCount)
	}

	// 篡改包内策略文件 => 完整性校验必须失败。
	pf := filepath.Join(bundleDir, "policy.rego")
	bad := append(mustReadFile(t, pf), '\n', '#', 'x')
	if err := os.WriteFile(pf, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := offline.Verify(context.Background(), bundleDir,
		[]offline.ArtifactFile{{Name: "root-good-1.0.tar.gz", Path: artPath}}, f.now); err == nil {
		t.Fatal("包内文件被篡改时离线核验必须拒绝")
	}
}

func classOf(r *review.Report, name string) string {
	for _, a := range r.Artifacts {
		if a.Name == name {
			return a.Classification
		}
	}
	return ""
}

func attestationIn(r *review.Report, artifactName string) review.AttestationReview {
	for _, a := range r.Artifacts {
		if a.Name == artifactName && len(a.Attestations) > 0 {
			return a.Attestations[0]
		}
	}
	return review.AttestationReview{}
}

func buildTSAEvidence(t *testing.T, f *revFixture, attEnv []byte, at time.Time) (
	*timestampevidence.TrustedTimeEvidence, error) {
	t.Helper()
	priv, err := loadDemoTSAPrivate(f.h)
	if err != nil {
		t.Fatal(err)
	}
	return timestampevidence.Sign(priv, canonicalEnvSHA(attEnv), at)
}
