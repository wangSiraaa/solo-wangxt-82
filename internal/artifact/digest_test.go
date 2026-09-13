package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"scbverify/internal/attestation"
)

const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"

func writeTemp(t *testing.T, name, content string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return path, hex.EncodeToString(sum[:])
}

// TestDigestHardComparison：字段齐全但摘要不符必须硬拒绝，
// 且 actualDigest 来自对真实字节的重算而非取自 JSON。
func TestDigestHardComparison(t *testing.T) {
	path, actual := writeTemp(t, "a.bin", "real artifact bytes")

	st := &attestation.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []attestation.Subject{{
			Name:   "a.bin",
			Digest: map[string]string{"sha256": zeros64},
		}},
		PredicateType: attestation.SLSAProvenanceType,
	}
	res := VerifySubjectDigest(path, "a.bin", actual, st)
	if res.Matched || !res.HardReject {
		t.Fatalf("摘要不符必须硬拒绝: %+v", res)
	}

	st.Subject[0].Digest["sha256"] = actual
	res = VerifySubjectDigest(path, "a.bin", actual, st)
	if !res.Matched || res.HardReject {
		t.Fatalf("摘要正确应匹配: %+v", res)
	}
}

// TestOtherSubjectsDoNotAffectTarget 是本缺陷的核心回归：
// 同一份声明里除了目标 tar.gz，还有摘要“正确”的 sbom.json 时，
// 只能比较 tar.gz 这个同名 subject；sbom.json 既不与目标文件比较，
// 也不应导致 hardReject。
func TestOtherSubjectsDoNotAffectTarget(t *testing.T) {
	tarContent := "tar-bytes"
	sbomContent := `{"bomFormat":"CycloneDX","components":[]}`
	tarPath, tarSHA := writeTemp(t, "payments-api-1.4.2.tar.gz", tarContent)
	_, sbomSHA := writeTemp(t, "sbom.json", sbomContent)

	target := "payments-api-1.4.2.tar.gz"
	st := &attestation.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []attestation.Subject{
			{Name: target, Digest: map[string]string{"sha256": tarSHA}},
			// 注意：sbom 的摘要对 sbom 字节是正确的，但绝不能拿来和 tar 文件比。
			{Name: "sbom.json", Digest: map[string]string{"sha256": sbomSHA}},
		},
		PredicateType: attestation.SLSAProvenanceType,
	}

	res := VerifySubjectDigest(tarPath, target, tarSHA, st)
	if !res.Matched || res.HardReject {
		t.Fatalf("目标 tar.gz 摘要正确时应匹配，其他 subject 不得造成拒绝: %+v", res)
	}
	if len(res.Subjects) != 1 || res.Subjects[0].Name != target {
		t.Fatalf("只应比较目标 subject，实际比较了: %+v", res.Subjects)
	}
	if want := []string{"sbom.json"}; !reflect.DeepEqual(res.IgnoredSubjects, want) {
		t.Fatalf("sbom.json 应被记录为未参与比对的 subject，实际 %v", res.IgnoredSubjects)
	}
}

// TestOtherSubjectCorrectCannotSubstituteMissingTarget：声明里只有
// sbom.json（摘要正确）而没有目标 tar.gz subject 时，必须明确拒绝，
// 不能因为“存在某个能匹配上字节的 subject”而放行。
func TestOtherSubjectCorrectCannotSubstituteMissingTarget(t *testing.T) {
	tarPath, tarSHA := writeTemp(t, "payments-api-1.4.2.tar.gz", "tar-bytes")
	_, sbomSHA := writeTemp(t, "sbom.json", `{"x":1}`)

	target := "payments-api-1.4.2.tar.gz"
	st := &attestation.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []attestation.Subject{
			// sbom 摘要对自身正确，但目标 subject 缺失。
			{Name: "sbom.json", Digest: map[string]string{"sha256": sbomSHA}},
		},
		PredicateType: attestation.SLSAProvenanceType,
	}

	res := VerifySubjectDigest(tarPath, target, tarSHA, st)
	if res.Matched || !res.HardReject {
		t.Fatalf("缺少目标 subject 时必须硬拒绝，即使其他 subject 摘要正确: %+v", res)
	}
	if len(res.Subjects) != 0 {
		t.Fatalf("不应把非目标 subject 当作匹配依据: %+v", res.Subjects)
	}
}

// TestTargetSubjectTamperedDespiteValidSBOM：目标 tar.gz 被改过，
// 即使同声明附带的 sbom.json 完全合法，仍必须硬拒绝。
func TestTargetSubjectTamperedDespiteValidSBOM(t *testing.T) {
	// 声明里写的是原始内容摘要；磁盘文件实际已被改动。
	originalSum := sha256.Sum256([]byte("original-tar"))
	claimedTarSHA := hex.EncodeToString(originalSum[:])
	tarPath, actualSHA := writeTemp(t, "payments-api-1.4.2.tar.gz", "TAMPERED-tar")
	_, sbomSHA := writeTemp(t, "sbom.json", `{"bomFormat":"CycloneDX"}`)

	target := "payments-api-1.4.2.tar.gz"
	st := &attestation.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []attestation.Subject{
			// 声明仍写着原始摘要；实际字节已变。
			{Name: target, Digest: map[string]string{"sha256": claimedTarSHA}},
			{Name: "sbom.json", Digest: map[string]string{"sha256": sbomSHA}},
		},
		PredicateType: attestation.SLSAProvenanceType,
	}

	res := VerifySubjectDigest(tarPath, target, actualSHA, st)
	if res.Matched || !res.HardReject {
		t.Fatalf("目标被篡改时合法 SBOM 不能挽救，必须硬拒绝: %+v", res)
	}
	foundTargetMismatch := false
	for _, m := range res.Subjects {
		if m.Name == target && !m.Match && m.ActualDigest == actualSHA {
			foundTargetMismatch = true
		}
	}
	if !foundTargetMismatch {
		t.Fatalf("应记录目标 subject 与实际字节的不一致: %+v", res.Subjects)
	}
}
