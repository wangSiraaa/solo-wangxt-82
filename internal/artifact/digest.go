// Package artifact 只做一件与安全相关的事：读取**本地实际产物文件**的
// 字节流并计算摘要，然后与 in-toto statement subject 中声明的摘要逐个
// 比对。它绝不执行、解压、反序列化或以任何方式“解释”产物内容。
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

// SubjectMatch 是某一个 subject 与实际产物的摘要比对结果。
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

// DigestResult 汇总一份声明的全部 subject 与实际产物的比对结果。
type DigestResult struct {
	// ArtifactPath 是被核验的本地文件路径。
	ArtifactPath string `json:"artifactPath"`
	// Matched 为 true 当且仅当存在至少一个 subject，且每个 subject
	// 都至少有一个受支持算法的摘要与实际字节一致。
	Matched  bool           `json:"matched"`
	Subjects []SubjectMatch `json:"subjects"`
	// HardReject 表示命中“摘要与实际文件不一致”的硬性拒绝条件，
	// 上层必须直接拒绝，不允许策略放行。
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

// VerifySubjectDigest 把 statement 的每个 subject 摘要与实际文件比对。
//
// 这是需求中明确的硬性检查：声明里的摘要与实际文件不一致直接拒绝，
// 不能因为 JSON 字段齐全就算通过。即便签名有效、签发者可信，
// 这里不一致也必须拒绝。
func VerifySubjectDigest(path string, actualSHA256 string, st *attestation.Statement) DigestResult {
	res := DigestResult{ArtifactPath: path}

	if st == nil {
		res.Reason = "载荷不是可解析的 in-toto statement，无法比对摘要"
		res.HardReject = true
		return res
	}

	var unsupportedSeen, mismatchSeen bool
	for _, subj := range st.Subject {
		// 一个 subject 可能给出多个算法；按算法名排序保证输出稳定可复现。
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
			// 目前白名单仅 sha256，所有 subject 与同一实际文件比对。
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
			// 若该 subject 完全没有可匹配的算法，也记录一条汇总原因。
			res.Subjects = append(res.Subjects, SubjectMatch{
				Name: subj.Name, Reason: "该 subject 没有任何受支持算法的摘要与实际文件匹配",
			})
		}
	}

	switch {
	case mismatchSeen:
		// 显式声明了 sha256 但值对不上：硬拒绝。
		res.HardReject = true
		res.Matched = false
		res.Reason = "声明摘要与实际产物字节不一致，硬性拒绝"
	case unsupportedSeen && len(res.Subjects) > 0 && !anyMatch(res.Subjects):
		res.HardReject = true
		res.Matched = false
		res.Reason = "声明仅提供了不支持的摘要算法，无法确认产物完整性"
	default:
		res.Matched = anyMatch(res.Subjects)
		if !res.Matched {
			res.HardReject = true
			res.Reason = "没有任何 subject 摘要能与实际产物匹配"
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
