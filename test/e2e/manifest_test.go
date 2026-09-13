package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"scbverify/internal/policy"
	"scbverify/internal/store"
	"scbverify/internal/trust"
	"scbverify/internal/verifier"
)

// expectedManifest 与 cmd/genvectors 写出的 demo/expected_vectors.json 对应。
type expectedManifest struct {
	EvalTime       string `json:"evalTime"`
	TamperedSHA256 string `json:"tamperedArtifactSha256"`
	Expected       []struct {
		File            string `json:"file"`
		ArtifactSHA256  string `json:"actualArtifactSha256"`
		SignatureValid  bool   `json:"signatureValid"`
		IssuerTrusted   bool   `json:"issuerTrusted"`
		PolicyAllowed   bool   `json:"policyAllowed"`
		DigestMatch     bool   `json:"digestMatch"`
		DecisionCurrent string `json:"decisionCurrent"`
		DecisionExpired string `json:"decisionExpired"`
		EnvelopeSHA256  string `json:"envelopeSha256"`
		SignatureB64    string `json:"signatureB64"`
	} `json:"expected"`
}

// TestExpectedVectorsManifest 对每条向量做真实核验，并与清单中的
// “可重复验签向量”逐项比对：
//   - 信封 SHA-256 / 签名 base64 必须逐字节复现（确定性）
//   - 四个维度的布尔结论必须符合预期
//   - 当前策略与过期策略下的最终决策必须符合预期
func TestExpectedVectorsManifest(t *testing.T) {
	demoRoot := filepath.Join("..", "..", "demo")
	raw, err := os.ReadFile(filepath.Join(demoRoot, "expected_vectors.json"))
	if err != nil {
		t.Skip("demo/expected_vectors.json 不存在，请先运行 genvectors")
	}
	var manifest expectedManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}

	root, err := trust.LoadRoot(filepath.Join(demoRoot, "trustroot.json"))
	if err != nil {
		t.Fatal(err)
	}
	loadKnownUntrusted(t, root, demoRoot)

	currentEngine, err := policy.EmbeddedEngine()
	if err != nil {
		t.Fatal(err)
	}
	expiredEngine, err := policy.LoadEngine(
		filepath.Join(demoRoot, "policies", "trust_policy.expired.rego"))
	if err != nil {
		t.Fatal(err)
	}

	goodPath := filepath.Join(demoRoot, "artifacts", "payments-api-1.4.2.tar.gz")
	tamperedPath := filepath.Join(demoRoot, "artifacts", "payments-api-1.4.2.tampered.tar.gz")

	for _, exp := range manifest.Expected {
		exp := exp
		t.Run(exp.File, func(t *testing.T) {
			envJSON, err := os.ReadFile(filepath.Join(demoRoot, "attestations", exp.File))
			if err != nil {
				t.Fatal(err)
			}
			// 确定性：信封内容（含签名）必须与清单一致。
			if got := sha256Hex(envJSON); got != exp.EnvelopeSHA256 {
				t.Fatalf("信封 sha256 不可复现: got %s want %s", got, exp.EnvelopeSHA256)
			}
			var env struct {
				Signatures []struct {
					Sig string `json:"sig"`
				} `json:"signatures"`
			}
			_ = json.Unmarshal(envJSON, &env)
			if len(env.Signatures) == 0 || env.Signatures[0].Sig != exp.SignatureB64 {
				t.Fatalf("签名 base64 不可复现")
			}

			// 清单按向量指定实际核验的产物：02 指向被改过一字节的文件。
			artifactPath := goodPath
			goodSHA := sha256Hex(mustReadFile(t, goodPath))
			if exp.ArtifactSHA256 != goodSHA {
				artifactPath = tamperedPath
				if got := sha256Hex(mustReadFile(t, tamperedPath)); got != exp.ArtifactSHA256 {
					t.Fatalf("篡改产物摘要不可复现: got %s want %s", got, exp.ArtifactSHA256)
				}
			}

			run := func(engine *policy.Engine, wantDecision string, checkDimensions bool) {
				st := store.NewMemoryStore()
				v := verifier.New(root, engine, st, fixedClock)
				resp, err := v.Verify(context.Background(), verifier.Request{
					ArtifactName: "payments-api-1.4.2.tar.gz",
					ArtifactPath: artifactPath,
					Attestations: []verifier.AttestationInput{{SourceRef: "manifest", EnvelopeJSON: envJSON}},
				})
				if err != nil {
					t.Fatalf("核验失败: %v", err)
				}
				if resp.Decision != wantDecision {
					t.Errorf("decision=%s want %s (%s)", resp.Decision, wantDecision, resp.DecisionReason)
				}
				// 三个独立维度 + 摘要闸门只在“当前策略”下与清单逐项比对；
				// 过期策略下仅比对最终决策（策略维度必然不同）。
				if !checkDimensions {
					return
				}
				r := resp.Results[0]
				if r.Signature.Valid != exp.SignatureValid {
					t.Errorf("signature.valid=%v want %v (%s)", r.Signature.Valid, exp.SignatureValid, r.Signature.Reason)
				}
				if r.Issuer.Trusted != exp.IssuerTrusted {
					t.Errorf("issuer.trusted=%v want %v (%s)", r.Issuer.Trusted, exp.IssuerTrusted, r.Issuer.Reason)
				}
				if r.Policy.Allowed != exp.PolicyAllowed {
					t.Errorf("policy.allowed=%v want %v (%v)", r.Policy.Allowed, exp.PolicyAllowed, r.Policy.Violations)
				}
				if r.Digest.Matched != exp.DigestMatch {
					t.Errorf("digest.matched=%v want %v (%s)", r.Digest.Matched, exp.DigestMatch, r.Digest.Reason)
				}
			}
			run(currentEngine, exp.DecisionCurrent, true)
			run(expiredEngine, exp.DecisionExpired, false)
		})
	}
}
