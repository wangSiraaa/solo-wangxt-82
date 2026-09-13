package e2e

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"scbverify/internal/attestation"
	"scbverify/internal/cryptokit"
	"scbverify/internal/trust"
)

// sha256Hex 返回字节的小写十六进制 SHA-256 摘要。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// canonicalEnvSHA 返回 DSSE 信封的规范化摘要（绑定时间证据时使用）。
func canonicalEnvSHA(b []byte) string {
	s, err := attestation.CanonicalEnvelopeSHA256(b)
	if err != nil {
		panic(err)
	}
	return s
}

// mustReadFile 读取文件，失败即终止测试。
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// loadKnownUntrusted 把演示中“已知但不受信任”的构建者公钥登记进信任根，
// 使其签名能被密码学验证（独立结论一为真），但信任判定（独立结论二）为假。
func loadKnownUntrusted(t *testing.T, root *trust.Root, demoRoot string) {
	t.Helper()
	pub, err := cryptokit.LoadPublicPEMFile(filepath.Join(demoRoot, "keys", "known-untrusted.pub.pem"))
	if err != nil {
		t.Fatalf("加载不受信任公钥: %v", err)
	}
	if err := root.AddKnownButUntrustedKey(pub); err != nil {
		t.Fatalf("登记已知公钥: %v", err)
	}
}

// loadTrustedPrivate 加载演示中受信任构建者的 Ed25519 私钥，
// 供需要在测试内重新封装签名的用例使用。
func loadTrustedPrivate(t *testing.T, h *harness) ed25519.PrivateKey {
	t.Helper()
	priv, err := cryptokit.LoadPrivatePEMFile(
		filepath.Join(h.demoRoot, "keys", "trusted-builder.priv.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// loadDemoTSAPrivate 加载演示 TSA 时间戳权威私钥（测试中补盖时间证据）。
func loadDemoTSAPrivate(h *harness) (ed25519.PrivateKey, error) {
	return cryptokit.LoadPrivatePEMFile(
		filepath.Join(h.demoRoot, "keys", "demo-tsa.priv.pem"))
}
