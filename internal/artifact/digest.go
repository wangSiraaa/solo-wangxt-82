// Package artifact 只做一件与安全相关的事：读取**本地实际产物文件**的
// 字节流并计算摘要，然后与 in-toto statement 中**目标产物同名** subject
// 声明的摘要比对。它绝不执行、解压、反序列化或以任何方式“解释”产物内容。
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"scbverify/internal/attestation"
)

// 支持的摘要算法白名单。未知算法一律视为不支持并拒绝，
// 不允许用 attacker 自选的弱算法/自定义算法名蒙混过关。
var supportedAlgorithms = map[string]bool{
	"sha256": true,
}

// SubjectMatch 是某一个目标 subject 摘要与实际产物的比对结果。
type SubjectMatch struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm,omitempty"`
	// ClaimedDigest 是声明中写的摘要。
	ClaimedDigest string `json:"claimedDigest,omitempty"`
	// ActualDigest 是对磁盘上实际字节重新计算得到的摘要。
	ActualDigest string `json:"actualDigest,omitempty"`
	// Match 为 true 当且仅当重新计算结果与声明摘要相等。
	Match  bool   `json:"match"`
	Reason string `json:"reason,omitempty"`
}

// DigestResult 汇总一份声明中**目标产物同名 subject** 与实际产物的比对结果。
type DigestResult struct {
	// ArtifactPath 是被核验的本地文件路径。
	ArtifactPath string `json:"artifactPath"`
	// TargetName 是本次核验请求的目标产物名；只有同名 subject 参与比对。
	TargetName string `json:"targetName"`
	// Matched 为 true 当且仅当至少存在一个同名 subject，且每个同名
	// subject 都至少有一个受支持算法的摘要与实际字节一致。
	Matched  bool           `json:"matched"`
	Subjects []SubjectMatch `json:"subjects"`
	// IgnoredSubjects 是声明中名称与目标产物不一致、未参与本次比对的
	// subject（例如同一份声明里附带的 sbom.json）。保留名称仅用于取证透明：
	// 这些 subject 的摘要绝不与目标文件字节比较，其正确与否需要由针对
	// 各自文件的独立核验负责。
	IgnoredSubjects []string `json:"ignoredSubjects,omitempty"`
	// HardReject 表示命中硬性拒绝条件，上层必须直接拒绝，
	// 不允许策略放行：没有目标 subject、摘要不一致、仅有不支持的算法等。
	HardReject bool   `json:"hardReject,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// HashFile 以流式（固定缓冲、不缓冲整个文件）计算文件 sha256。
// 文件只被读取，绝不被赋予可执行语义。
func HashFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // 路径来自经过鉴权的核验请求/演示 CLI
	if err != nil {
		return "", fmt.Errorf("artifact: 打开产物 %q 失败: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.CopyBuffer(h, f, make([]byte, 64*1024)); err != nil {
		return "", fmt.Errorf("artifact: 计算产物摘要失败: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifySubjectDigest 只把 statement 中**名称等于 artifactName** 的 subject
// 摘要与实际文件比对；同名 subject 可有多个（声明重复列名），每个都必须匹配。
// 名称不同的 subject（如同一份声明附带的 sbom.json）一律不参与比对，
// 仅在 IgnoredSubjects 中留名。
//
// 这是需求中明确的硬性检查：
//   - 声明里找不到目标产物的 subject：明确硬拒绝（不能拿其他 subject 顶替）；
//   - 目标 subject 的摘要与实际文件不一致：硬拒绝，不能因为 JSON 字段
//     齐全就算通过。即便签名有效、签发者可信，这里不一致也必须拒绝。
func VerifySubjectDigest(path, artifactName, actualSHA256 string, st *attestation.Statement) DigestResult {
	res := DigestResult{ArtifactPath: path, TargetName: artifactName}

	if st == nil {
		res.Reason = "载荷不是可解析的 in-toto statement，无法比对摘要"
		res.HardReject = true
		return res
	}

	// 1) 按名称切分：同名 subject 才是本次核验对象。
	var targetSubjects []attestation.Subject
	ignoredSet := map[string]struct{}{}
	for _, subj := range st.Subject {
		if subj.Name == artifactName {
			targetSubjects = append(targetSubjects, subj)
			continue
		}
		ignoredSet[subj.Name] = struct{}{}
	}
	for name := range ignoredSet {
		res.IgnoredSubjects = append(res.IgnoredSubjects, name)
	}
	sort.Strings(res.IgnoredSubjects)

	// 2) 没有目标 subject：明确拒绝，不能用 sbom.json 等其他 subject 的
	//    正确摘要冒充目标产物。
	if len(targetSubjects) == 0 {
		res.HardReject = true
		res.Matched = false
		if len(res.IgnoredSubjects) > 0 {
			res.Reason = fmt.Sprintf(
				"声明中没有名称为 %q 的 subject（仅有其他产物 %v），无法确认目标产物完整性，硬性拒绝",
				artifactName, res.IgnoredSubjects)
		} else {
			res.Reason = fmt.Sprintf("声明中没有名称为 %q 的 subject，硬性拒绝", artifactName)
		}
		return res
	}

	// 3) 逐个目标 subject 比对；按 subject 出现顺序输出，算法名排序保证稳定。
	var unsupportedSeen, mismatchSeen bool
	for _, subj := range targetSubjects {
		algs := make([]string, 0, len(subj.Digest))
		for alg := range subj.Digest {
			algs = append(algs, alg)
		}
		sort.Strings(algs)

		subjectMatched := false
		for _, alg := range algs {
			claimed := normalizeHex(subj.Digest[alg])
			m := SubjectMatch{Name: subj.Name, Algorithm: alg, ClaimedDigest: claimed}
			if !supportedAlgorithms[alg] {
				m.Reason = "声明使用了不受支持/未启用的摘要算法，该算法不参与匹配"
				unsupportedSeen = true
				res.Subjects = append(res.Subjects, m)
				continue
			}
			// 白名单内的算法（当前仅 sha256）与目标文件实际字节比对。
			m.ActualDigest = actualSHA256
			if claimed == actualSHA256 {
				m.Match = true
				subjectMatched = true
			} else {
				m.Reason = "实际文件字节的摘要与声明摘要不一致（产物可能已被篡改）"
				mismatchSeen = true
			}
			res.Subjects = append(res.Subjects, m)
		}
		if !subjectMatched {
			res.Subjects = append(res.Subjects, SubjectMatch{
				Name:   subj.Name,
				Reason: "该目标 subject 没有任何受支持算法的摘要与实际文件匹配",
			})
		}
	}

	switch {
	case mismatchSeen:
		// 目标 subject 显式声明了 sha256 但值对不上：硬拒绝。
		res.HardReject = true
		res.Matched = false
		res.Reason = "目标产物的声明摘要与实际字节不一致，硬性拒绝"
	case unsupportedSeen && !anyMatch(res.Subjects):
		res.HardReject = true
		res.Matched = false
		res.Reason = "目标 subject 仅提供了不支持的摘要算法，无法确认产物完整性"
	default:
		res.Matched = anyMatch(res.Subjects)
		if !res.Matched {
			res.HardReject = true
			res.Reason = "目标 subject 没有任何摘要能与实际产物匹配"
		}
	}
	return res
}

func anyMatch(ms []SubjectMatch) bool {
	for _, m := range ms {
		if m.Match {
			return true
		}
	}
	return false
}

func normalizeHex(s string) string {
	// 摘要以小写十六进制规范比较；声明侧通常即小写，这里做容错。
	var b []byte
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'F':
			b = append(b, byte(c+('a'-'A')))
		default:
			b = append(b, byte(c))
		}
	}
	return string(b)
}

// ErrSubjectNotFound 表示声明中没有针对指定产物名的 subject。
var ErrSubjectNotFound = errors.New("artifact: statement subject 中找不到该产物")

// SubjectsForArtifact 过滤出与给定产物名相关的 subject（演示中通常即文件名）。
func SubjectsForArtifact(st *attestation.Statement, artifactName string) []attestation.Subject {
	var out []attestation.Subject
	for _, s := range st.Subject {
		if s.Name == artifactName {
			out = append(out, s)
		}
	}
	return out
}
