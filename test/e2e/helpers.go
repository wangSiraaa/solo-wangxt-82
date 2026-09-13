package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"scbverify/internal/cryptokit"
	"scbverify/internal/trust"
)

// mustReadFile 读取文件，失败即终止测试。
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sha256Hex 返回字节的小写十六进制 SHA-256 摘要。
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
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
