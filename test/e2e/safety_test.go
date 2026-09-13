package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"scbverify/internal/attestation"
	"scbverify/internal/cryptokit"
	"scbverify/internal/policy"
	"scbverify/internal/verifier"
)

const allowedSourceURI = "git+https://git.example.com/scm/payments/api"

const (
	trustedBuilder   = "https://build.example.com/builder/primary"
	untrustedBuilder = "https://build.example.com/builder/shadow"
)

// TestArtifactNeverExecuted 行为验证：产物本身是一个“一旦被执行就会
// 写出哨兵文件”的 shell 脚本。对它分别走放行路径和所有失败路径
// （篡改文件、伪造摘要、坏签名、不可信构建者、过期策略）后，
// 哨兵文件都不得出现——证明核验只读取字节，从不执行内容。
func TestArtifactNeverExecuted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("该行为测试依赖 POSIX shebang 语义")
	}
	h := loadHarness(t, "")
	engine, _ := policy.EmbeddedEngine()

	dir := t.TempDir()
	sentinel := filepath.Join(dir, "EXECUTED-MARKER")
	scriptPath := filepath.Join(dir, "build-output.bin")
	// 危险载荷形状（可执行脚本内容），但服务绝不能执行它；文件位 0644。
	script := "#!/bin/sh\necho executed > " + sentinel + "\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(script))
	scriptSHA := hex.EncodeToString(sum[:])

	priv, err := cryptokit.LoadPrivatePEMFile(
		filepath.Join(h.demoRoot, "keys", "trusted-builder.priv.pem"))
	if err != nil {
		t.Fatal(err)
	}
	untrustedPriv, err := cryptokit.LoadPrivatePEMFile(
		filepath.Join(h.demoRoot, "keys", "untrusted-builder.priv.pem"))
	if err != nil {
		t.Fatal(err)
	}

	signEnv := func(privKey ed25519.PrivateKey, claimedSHA, builder, source string) []byte {
		t.Helper()
		type kv = map[string]any
		st := &attestation.Statement{
			Type: "https://in-toto.io/Statement/v1",
			Subject: []attestation.Subject{{
				Name:   "build-output.bin",
				Digest: map[string]string{"sha256": claimedSHA},
			}},
			PredicateType: attestation.SLSAProvenanceType,
			Predicate: marshalJSON(t, kv{
				"buildDefinition": kv{
					"buildType": "https://build.example.com/buildtypes/reproducible-v1",
					"externalParameters": kv{
						"source": kv{"uri": source, "digest": kv{"sha1": "7d2e9f1a4b6c8d0e5f7a9b1c3d4e6f8012a4b6c8"}},
					},
				},
				"runDetails": kv{
					"builder":  kv{"id": builder},
					"metadata": kv{"startedOn": "2026-09-12T23:00:00Z"},
				},
			}),
		}
		env, err := attestation.SignStatement(privKey, st)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	good := signEnv(priv, scriptSHA, trustedBuilder, allowedSourceURI)
	forgedDigest := signEnv(priv, strings.Repeat("0", 64), trustedBuilder, allowedSourceURI)
	untrusted := signEnv(untrustedPriv, scriptSHA, untrustedBuilder, allowedSourceURI)

	run := func(name string, envJSON []byte, path string, eng *policy.Engine) {
		t.Run(name, func(t *testing.T) {
			req := verifier.Request{
				ArtifactName: "build-output.bin",
				ArtifactPath: path,
				Attestations: []verifier.AttestationInput{
					{SourceRef: "safety", EnvelopeJSON: envJSON},
				},
			}
			if _, err := verifier.New(h.root, eng, h.st, fixedClock).
				Verify(context.Background(), req); err != nil {
				t.Fatalf("Verify 不应返回基础设施错误: %v", err)
			}
			if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
				t.Fatalf("产物内容被执行了！哨兵文件存在: %v", err)
			}
		})
	}

	// 放行路径：即便判定允许下载，也只产出结论，不执行内容。
	run("allow-path", good, scriptPath, engine)
	// 失败路径：摘要字段值伪造（硬拒绝）。
	run("deny-forged-digest", forgedDigest, scriptPath, engine)
	// 失败路径：实际文件被改动，声明摘要仍是旧值。
	tamperedScriptPath := filepath.Join(dir, "tampered.bin")
	if err := os.WriteFile(tamperedScriptPath,
		append([]byte(script), []byte("echo extra\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	run("deny-tampered-file", good, tamperedScriptPath, engine)
	// 失败路径：不受信任构建者。
	run("deny-untrusted-builder", untrusted, scriptPath, engine)
	// 失败路径：坏签名。
	run("deny-bad-signature", flipFirstSignatureByte(t, good), scriptPath, engine)
	// 失败路径：过期策略。
	expiredEngine, err := policy.LoadEngine(
		filepath.Join(h.demoRoot, "policies", "trust_policy.expired.rego"))
	if err != nil {
		t.Fatal(err)
	}
	run("deny-expired-policy", good, scriptPath, expiredEngine)
}

// TestNoExecImports 静态保证：核心核验代码不得导入任何会派生/执行进程的包。
func TestNoExecImports(t *testing.T) {
	rootDir := filepath.Join("..", "..", "internal")
	forbidden := map[string]bool{
		"os/exec": true,
		"syscall": true,
	}
	fset := token.NewFileSet()
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool { return true })
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if forbidden[p] {
				t.Errorf("文件 %s 导入了被禁止的包 %s：核验流程不得执行产物", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("静态扫描失败: %v", err)
	}
}

func marshalJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func flipFirstSignatureByte(t *testing.T, envelopeJSON []byte) []byte {
	t.Helper()
	var env attestation.Envelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xFF
	env.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
	b, err := json.Marshal(&env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
