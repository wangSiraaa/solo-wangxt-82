// genvectors 生成可重复的演示与验签向量：
//   - 固定 seed 的 Ed25519 密钥（受信任主机构建者 / 不受信任构建者）
//   - 一个本地产物与一个“被改过一个字节”的产物
//   - 6 份 DSSE 封装的 in-toto SLSA Provenance v1 声明
//   - 信任根、当前策略与已过期策略
//   - expected_vectors.json：包含签名/信封摘要与每种场景的预期判定
//
// 重新运行输出逐字节一致（Ed25519 签名确定性、JSON 字段顺序固定）。
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"scbverify/internal/attestation"
	"scbverify/internal/cryptokit"
)

const (
	trustedBuilder   = "https://build.example.com/builder/primary"
	untrustedBuilder = "https://build.example.com/builder/shadow"
	allowedSource    = "git+https://git.example.com/scm/payments/api"
	allowedCommit    = "7d2e9f1a4b6c8d0e5f7a9b1c3d4e6f8012a4b6c8"
	// 评估时间：当前策略窗口内；过期策略窗口外。固定时间保证可重复。
	evalTime = "2026-09-13T08:00:00Z"
)

// fixedSeed 从口令短语确定性派生 32 字节 seed。
func fixedSeed(label string) []byte {
	h := sha256.Sum256([]byte("scbverify-demo-seed:" + label))
	return h[:]
}

type demoKey struct {
	name string
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   string
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func writeFile(path string, b []byte, mode os.FileMode) {
	must(os.MkdirAll(filepath.Dir(path), 0o755))
	must(os.WriteFile(path, b, mode))
}

func main() {
	dir := flag.String("out", "demo", "输出目录")
	flag.Parse()
	root := *dir

	// 1) 确定性密钥 --------------------------------------------------------
	trusted := loadKey("trusted-builder", filepath.Join(root, "keys", "trusted-builder"))
	untrusted := loadKey("untrusted-builder", filepath.Join(root, "keys", "untrusted-builder"))

	// 2) 信任根：只信任 trusted-builder ---------------------------------
	type trustedKeyJSON struct {
		KeyID        string `json:"keyId"`
		Issuer       string `json:"issuer"`
		PublicKeyPEM string `json:"publicKeyPem"`
	}
	trustPubPEM, _ := cryptokit.MarshalPublicPEM(trusted.pub)
	trustRoot := map[string]any{
		"name":    "scbverify demo trust root",
		"version": 1,
		"trustedKeys": []trustedKeyJSON{{
			KeyID: trusted.id, Issuer: trustedBuilder, PublicKeyPEM: string(trustPubPEM),
		}},
	}
	writeJSON(filepath.Join(root, "trustroot.json"), trustRoot)

	// 供验签器登记的“已知但不受信任”公钥（独立文件，便于服务器加载）
	untrustedPubPEM, _ := cryptokit.MarshalPublicPEM(untrusted.pub)
	writeFile(filepath.Join(root, "keys", "known-untrusted.pub.pem"), untrustedPubPEM, 0o644)

	// 3) 产物：原始 + 被改一字节的副本 ------------------------------------
	artifactBytes := []byte("# scbverify demo artifact\n" +
		"This file is DATA ONLY. The verifier hashes it and never executes it.\n" +
		"sha256-pinning-line-0123456789\n")
	artifactPath := filepath.Join(root, "artifacts", "payments-api-1.4.2.tar.gz")
	writeFile(artifactPath, artifactBytes, 0o644)
	// 注意：落盘文件没有可执行位（0644），且内容不是可执行脚本。
	tampered := make([]byte, len(artifactBytes))
	copy(tampered, artifactBytes)
	tampered[len(tampered)-1] = tampered[len(tampered)-1] ^ 0xFF
	tamperedPath := filepath.Join(root, "artifacts", "payments-api-1.4.2.tampered.tar.gz")
	writeFile(tamperedPath, tampered, 0o644)

	goodSum := sha256.Sum256(artifactBytes)
	tamperedSum := sha256.Sum256(tampered)

	// 4) 构造 Provenance 的工具函数 --------------------------------------
	buildStatement := func(name, claimedSHA, builderID, sourceURI, commit string) *attestation.Statement {
		return &attestation.Statement{
			Type: "https://in-toto.io/Statement/v1",
			Subject: []attestation.Subject{{
				Name:   name,
				Digest: map[string]string{"sha256": claimedSHA},
			}},
			PredicateType: attestation.SLSAProvenanceType,
			Predicate: mustJSON(map[string]any{
				"buildDefinition": map[string]any{
					"buildType": "https://build.example.com/buildtypes/reproducible-v1",
					"externalParameters": map[string]any{
						"source": map[string]any{
							"uri": sourceURI,
							"digest": map[string]string{
								"sha1": commit,
							},
						},
					},
				},
				"runDetails": map[string]any{
					"builder": map[string]any{"id": builderID},
					"metadata": map[string]any{
						"startedOn":  "2026-09-12T23:00:00Z",
						"finishedOn": "2026-09-12T23:04:00Z",
					},
				},
			}),
		}
	}

	artifactName := "payments-api-1.4.2.tar.gz"
	goodSHA := hex.EncodeToString(goodSum[:])
	tamperedSHA := hex.EncodeToString(tamperedSum[:])

	type vecDef struct {
		file     string
		key      demoKey
		builder  string
		source   string
		commit   string
		claimSHA string
		subject  string
		note     string
		// useTampered 表示该向量针对“被改过一字节”的产物核验，
		// 因此即便声明摘要等于原始产物摘要，实际比对也必然失败。
		useTampered bool
	}
	vecs := []vecDef{
		{
			file: "01-valid.attestation.json", key: trusted,
			builder: trustedBuilder, source: allowedSource, commit: allowedCommit,
			claimSHA: goodSHA, subject: artifactName,
			note: "正常：签名有效+签发者可信+符合当前策略+摘要一致",
		},
		{
			file: "02-tampered-file.attestation.json", key: trusted,
			builder: trustedBuilder, source: allowedSource, commit: allowedCommit,
			claimSHA: goodSHA, subject: artifactName, useTampered: true,
			note: "声明摘要仍为原始摘要，但实际文件被改过一字节：摘要硬拒绝",
		},
		{
			file: "03-untrusted-builder.attestation.json", key: untrusted,
			builder: untrustedBuilder, source: allowedSource, commit: allowedCommit,
			claimSHA: goodSHA, subject: artifactName,
			note: "不受信任构建者签名：签名密码学有效，但签发者不可信+策略拒绝",
		},
		{
			file: "04-expired-policy.attestation.json", key: trusted,
			builder: trustedBuilder, source: allowedSource, commit: allowedCommit,
			claimSHA: goodSHA, subject: artifactName,
			note: "签名与信任均成立，但在过期策略版本下评估：策略拒绝",
		},
		{
			file: "05-wrong-source.attestation.json", key: trusted,
			builder: trustedBuilder, source: "git+https://git.example.com/scm/experiments/playground",
			commit: allowedCommit, claimSHA: goodSHA, subject: artifactName,
			note: "源码仓库不在允许列表：策略拒绝（签名/信任仍独立成立）",
		},
		{
			file: "06-digest-field-mismatch.attestation.json", key: trusted,
			builder: trustedBuilder, source: allowedSource, commit: allowedCommit,
			claimSHA: "0000000000000000000000000000000000000000000000000000000000000000",
			subject:  artifactName,
			note:     "JSON 字段齐全但摘要值是伪造的：不能只检查字段，必须重算并拒绝",
		},
	}

	type expected struct {
		Vector          string `json:"vector"`
		File            string `json:"file"`
		Note            string `json:"note"`
		ArtifactPath    string `json:"artifactPath"`
		ArtifactSHA256  string `json:"actualArtifactSha256"`
		ClaimedSHA256   string `json:"claimedSha256"`
		SignatureValid  bool   `json:"signatureValid"`
		IssuerTrusted   bool   `json:"issuerTrusted"`
		PolicyAllowed   bool   `json:"policyAllowed"`
		DigestMatch     bool   `json:"digestMatch"`
		DecisionCurrent string `json:"decisionCurrent"`
		DecisionExpired string `json:"decisionExpired"`
		EnvelopeSHA256  string `json:"envelopeSha256"`
		SignatureB64    string `json:"signatureB64"`
		AcceptedKeyID   string `json:"acceptedKeyId"`
	}
	var expectedList []expected

	for _, d := range vecs {
		st := buildStatement(d.subject, d.claimSHA, d.builder, d.source, d.commit)
		env, err := attestation.SignStatement(d.key.priv, st)
		must(err)
		raw := mustMarshalIndent(env)
		writeFile(filepath.Join(root, "attestations", d.file), raw, 0o644)

		envSum := sha256.Sum256(raw)
		sigValid := true
		issuerTrusted := d.key.name == "trusted-builder" && d.builder == trustedBuilder
		// 02 向量针对篡改文件核验：声明摘要虽等于原始文件摘要，
		// 但与实际字节不符，摘要闸门失败。
		actualFileSHA := goodSHA
		artifactForVector := artifactPath
		if d.useTampered {
			actualFileSHA = tamperedSHA
			artifactForVector = tamperedPath
		}
		digestMatch := d.claimSHA == actualFileSHA
		currentPolicyAllowed := sigValid && issuerTrusted && digestMatch && d.source == allowedSource
		expiredPolicyAllowed := false
		decisionCurrent := decide(sigValid, issuerTrusted, currentPolicyAllowed, digestMatch)
		decisionExpired := decide(sigValid, issuerTrusted, expiredPolicyAllowed, digestMatch)

		expectedList = append(expectedList, expected{
			Vector: d.file, File: d.file, Note: d.note,
			ArtifactPath:    artifactForVector,
			ArtifactSHA256:  actualFileSHA,
			ClaimedSHA256:   d.claimSHA,
			SignatureValid:  sigValid,
			IssuerTrusted:   issuerTrusted,
			PolicyAllowed:   currentPolicyAllowed,
			DigestMatch:     digestMatch,
			DecisionCurrent: decisionCurrent,
			DecisionExpired: decisionExpired,
			EnvelopeSHA256:  hex.EncodeToString(envSum[:]),
			SignatureB64:    env.Signatures[0].Sig,
			AcceptedKeyID:   d.key.id,
		})
	}

	// 篡改文件场景使用实际篡改文件重算（独立一组请求参数，记录在 manifest）
	must(os.MkdirAll(filepath.Join(root, "requests"), 0o755))
	writeJSON(filepath.Join(root, "requests", "req-02-tampered.json"), map[string]any{
		"artifactName": artifactName,
		"artifactPath": tamperedPath,
		"attestations": []map[string]string{{
			"sourceRef": "ci-primary",
			"file":      "attestations/02-tampered-file.attestation.json",
		}},
	})
	writeJSON(filepath.Join(root, "requests", "req-good.json"), map[string]any{
		"artifactName": artifactName,
		"artifactPath": artifactPath,
		"attestations": []map[string]string{{
			"sourceRef": "ci-primary",
			"file":      "attestations/01-valid.attestation.json",
		}},
	})
	// 冲突证据请求：同一产物两份都签名有效，但 builder/source 互斥
	conflictSecond := buildStatement(artifactName, goodSHA, untrustedBuilder, allowedSource, allowedCommit)
	// 将第二份声明也用 trusted 签名但 builder 改成另一个身份 -> 触发身份错配；
	// 真正的“双可信但矛盾”需要两个受信任 builder，演示改用：
	// trusted 正常声明 + untrusted 声明不会冲突（后者不通过）。
	// 因此再构造一份 trusted 签名、builder 仍为主机构建者但 commit 不同的声明，
	// 它同样通过签名/信任/策略吗？commit 不参与策略允许（仅要求固定），所以会通过，
	// 从而与 01 在 source digest 上冲突 => needs_review。
	conflictStmt := buildStatement(artifactName, goodSHA, trustedBuilder, allowedSource,
		"abcdef0123456789abcdef0123456789abcdef01")
	conflictEnv, err := attestation.SignStatement(trusted.priv, conflictStmt)
	must(err)
	writeFile(filepath.Join(root, "attestations", "07-conflicting-commit.attestation.json"),
		mustMarshalIndent(conflictEnv), 0o644)
	writeJSON(filepath.Join(root, "requests", "req-conflict.json"), map[string]any{
		"artifactName": artifactName,
		"artifactPath": artifactPath,
		"attestations": []map[string]string{
			{"sourceRef": "ci-primary", "file": "attestations/01-valid.attestation.json"},
			{"sourceRef": "ci-mirror", "file": "attestations/07-conflicting-commit.attestation.json"},
		},
	})
	_ = conflictSecond
	_ = tamperedSHA

	// 5) 策略文件：当前策略已存在于 policies/，这里生成一份“过期策略” ------
	expiredPolicy := generateExpiredPolicy()
	writeFile(filepath.Join(root, "policies", "trust_policy.expired.rego"), []byte(expiredPolicy), 0o644)

	// 6) expected vectors manifest ----------------------------------------
	manifest := map[string]any{
		"generatedAt":              "deterministic (fixed seeds, eval time " + evalTime + ")",
		"evalTime":                 evalTime,
		"artifactName":             artifactName,
		"goodArtifactSha256":       goodSHA,
		"tamperedArtifactSha256":   tamperedSHA,
		"trustedBuilderId":         trustedBuilder,
		"untrustedBuilderId":       untrustedBuilder,
		"trustedKeyId":             trusted.id,
		"untrustedKeyId":           untrusted.id,
		"currentPolicyVersion":     "2026.09",
		"expiredPolicyVersion":     "2025.06",
		"expected":                 expectedList,
		"conflictExpectedDecision": "needs_review",
	}
	writeJSON(filepath.Join(root, "expected_vectors.json"), manifest)

	fmt.Printf("向量已生成到 %s/\n", root)
	fmt.Printf("评估时间固定为 %s\n", evalTime)
	fmt.Printf("正常产物 sha256=%s\n", goodSHA)
	fmt.Printf("篡改产物 sha256=%s\n", tamperedSHA)
	fmt.Printf("受信任密钥 %s\n", trusted.id)
	fmt.Printf("不受信任密钥 %s\n", untrusted.id)
}

func decide(sig, issuer, pol, digest bool) string {
	if !digest {
		return "deny"
	}
	if sig && issuer && pol {
		return "allow"
	}
	return "deny"
}

func loadKey(name, base string) demoKey {
	pub, priv, err := cryptokit.GenerateEd25519(fixedSeed(name))
	must(err)
	id, err := cryptokit.KeyIDFromPublic(pub)
	must(err)
	pubPEM, err := cryptokit.MarshalPublicPEM(pub)
	must(err)
	privPEM, err := cryptokit.MarshalPrivatePEM(priv)
	must(err)
	writeFile(base+".priv.pem", privPEM, 0o600)
	writeFile(base+".pub.pem", pubPEM, 0o644)
	return demoKey{name: name, pub: pub, priv: priv, id: id}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	must(err)
	return b
}

func mustMarshalIndent(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	return append(b, '\n')
}

func writeJSON(path string, v any) {
	writeFile(path, mustMarshalIndent(v), 0o644)
}

// generateExpiredPolicy 复制当前策略但把窗口改为 2025 年（评估时已过期），
// 并提升版本号，以便验证“过期策略拒绝”。
func generateExpiredPolicy() string {
	return `# 过期策略版本：仅用于验证“过期策略拒绝”路径。
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
`
}

var _ = time.Now
