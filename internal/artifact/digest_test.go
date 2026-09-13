package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"scbverify/internal/attestation"
)

const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"

// TestDigestHardComparison 直接验证：字段齐全但摘要不符必须硬拒绝，
// 且 actualDigest 来自对真实字节的重算而非取自 JSON。
func TestDigestHardComparison(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.bin")
	content := []byte("real artifact bytes")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	actual := hex.EncodeToString(sum[:])

	st := &attestation.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []attestation.Subject{{
			Name:   "a.bin",
			Digest: map[string]string{"sha256": zeros64},
		}},
		PredicateType: attestation.SLSAProvenanceType,
	}
	res := VerifySubjectDigest(path, actual, st)
	if res.Matched || !res.HardReject {
		t.Fatalf("摘要不符必须硬拒绝: %+v", res)
	}

	// 摘要正确：匹配且不触发硬拒绝。
	st.Subject[0].Digest["sha256"] = actual
	res = VerifySubjectDigest(path, actual, st)
	if !res.Matched || res.HardReject {
		t.Fatalf("摘要正确应匹配: %+v", res)
	}
}
