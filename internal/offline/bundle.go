// Package offline 生成与消费“离线核验包”。
//
// 离线包自包含判定所需的信任材料与证据，并显式标注撤销信息更新截止：
//
//	policy.rego         OPA 策略原文
//	trustroot.json      信任根（含 TSA 公钥）
//	revocation.json     撤销清单
//	attestations/*.json 原始 DSSE 信封
//	timestamps/*.json   可信时间证据（TSA 签名）
//	manifest.json       上述文件的 SHA-256 摘要、更新截止与“非实时”声明
//
// 离线结论**不能**声称实时有效：它只对 manifest.revocationCutoff 之前的
// 撤销信息负责；之后发生的撤销/泄露离线端无从得知。
package offline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ManifestVersion 标识离线包格式。
const ManifestVersion = "offline-bundle-v1"

// FileEntry 是包内一个文件的完整性记录。
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// EvidenceRef 引用一个待离线核验的证据（信封 + 可选时间证据文件名）。
type EvidenceRef struct {
	AttestationPath string   `json:"attestationPath"`
	TimestampPaths  []string `json:"timestampPaths,omitempty"`
	ArtifactName    string   `json:"artifactName"`
}

// Manifest 是离线包的清单与有效性边界声明。
type Manifest struct {
	Version string `json:"version"`
	// GeneratedAt 是打包时间（RFC3339），不是结论的实时性保证。
	GeneratedAt string `json:"generatedAt"`
	// RevocationCutoff 是撤销信息的更新截止；离线结论只对此前负责。
	RevocationCutoff string `json:"revocationCutoff"`
	// RevocationFeedVersion 是打包时撤销清单版本。
	RevocationFeedVersion int `json:"revocationFeedVersion"`
	// RealTimeValid 恒为 false：离线结果不得被当作实时结论。
	RealTimeValid bool `json:"realTimeValid"`
	// ValidityNotice 是给使用者的明确提示。
	ValidityNotice string `json:"validityNotice"`

	PolicyPath     string        `json:"policyPath"`
	TrustRootPath  string        `json:"trustRootPath"`
	RevocationPath string        `json:"revocationPath"`
	Evidence       []EvidenceRef `json:"evidence"`
	Files          []FileEntry   `json:"files"`
}

// BundleSpec 描述要打包的内容（均为宿主机上的源文件路径）。
type BundleSpec struct {
	OutDir            string
	PolicyPath        string
	TrustRootPath     string
	RevocationPath    string
	AttestationPaths  []string
	TimeEvidencePaths []string
	ArtifactNames     map[string]string // 信封文件路径 -> 目标产物名
	RevocationFeedVer int
	RevocationCutoff  time.Time
}

func hashFile(path string) (FileEntry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return FileEntry{}, err
	}
	sum := sha256.Sum256(b)
	fi, err := os.Stat(path)
	if err != nil {
		return FileEntry{}, err
	}
	return FileEntry{SHA256: hex.EncodeToString(sum[:]), Size: fi.Size()}, nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

// Build 生成离线核验包目录并写出 manifest.json。
func Build(spec BundleSpec) (*Manifest, error) {
	if err := os.MkdirAll(spec.OutDir, 0o755); err != nil {
		return nil, err
	}
	m := &Manifest{
		Version:               ManifestVersion,
		GeneratedAt:           time.Now().UTC().Format(time.RFC3339),
		RevocationCutoff:      spec.RevocationCutoff.UTC().Format(time.RFC3339),
		RevocationFeedVersion: spec.RevocationFeedVer,
		RealTimeValid:         false,
		ValidityNotice: "离线核验结论仅对撤销信息更新截止 " +
			spec.RevocationCutoff.UTC().Format(time.RFC3339) +
			" 之前负责；不代表该时点之后仍实时有效。",
		PolicyPath:     "policy.rego",
		TrustRootPath:  "trustroot.json",
		RevocationPath: "revocation.json",
	}

	type copyJob struct{ src, dst string }
	jobs := []copyJob{
		{spec.PolicyPath, filepath.Join(spec.OutDir, m.PolicyPath)},
		{spec.TrustRootPath, filepath.Join(spec.OutDir, m.TrustRootPath)},
		{spec.RevocationPath, filepath.Join(spec.OutDir, m.RevocationPath)},
	}
	// 信封复制到 attestations/，时间证据复制到 timestamps/。
	attDst := map[string]string{}
	for _, src := range spec.AttestationPaths {
		base := filepath.Base(src)
		dst := filepath.Join("attestations", base)
		attDst[src] = dst
		jobs = append(jobs, copyJob{src, filepath.Join(spec.OutDir, dst)})
	}
	tsDst := map[string]string{}
	for _, src := range spec.TimeEvidencePaths {
		base := filepath.Base(src)
		dst := filepath.Join("timestamps", base)
		tsDst[src] = dst
		jobs = append(jobs, copyJob{src, filepath.Join(spec.OutDir, dst)})
	}
	for _, j := range jobs {
		if err := copyFile(j.src, j.dst); err != nil {
			return nil, fmt.Errorf("offline: 复制 %s 失败: %w", j.src, err)
		}
	}

	// 按信封组织证据引用（时间证据通过同目录约定手工传入；这里全部挂上，
	// 消费端按信封摘要自行匹配）。
	sortedAtt := append([]string(nil), spec.AttestationPaths...)
	sort.Strings(sortedAtt)
	allTS := make([]string, 0, len(spec.TimeEvidencePaths))
	for _, src := range spec.TimeEvidencePaths {
		allTS = append(allTS, tsDst[src])
	}
	for _, src := range sortedAtt {
		name := spec.ArtifactNames[src]
		if name == "" {
			name = "artifact"
		}
		m.Evidence = append(m.Evidence, EvidenceRef{
			AttestationPath: attDst[src],
			TimestampPaths:  allTS,
			ArtifactName:    name,
		})
	}

	// 计算包内全部数据文件摘要（manifest 自身除外）。
	dataFiles := []string{
		m.PolicyPath, m.TrustRootPath, m.RevocationPath,
	}
	for _, e := range m.Evidence {
		dataFiles = append(dataFiles, e.AttestationPath)
		dataFiles = append(dataFiles, e.TimestampPaths...)
	}
	sort.Strings(dataFiles)
	dataFiles = dedup(dataFiles)
	for _, rel := range dataFiles {
		fe, err := hashFile(filepath.Join(spec.OutDir, rel))
		if err != nil {
			return nil, err
		}
		fe.Path = rel
		m.Files = append(m.Files, fe)
	}

	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(spec.OutDir, "manifest.json"),
		append(mb, '\n'), 0o644); err != nil {
		return nil, err
	}
	return m, nil
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// LoadManifest 读取离线包清单。
func LoadManifest(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("offline: 读取 manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("offline: manifest 非法: %w", err)
	}
	if m.Version != ManifestVersion {
		return nil, fmt.Errorf("offline: 不支持的离线包版本 %q", m.Version)
	}
	return &m, nil
}

// VerifyIntegrity 重算包内每个数据文件的 SHA-256 并与 manifest 比对。
// 任何缺失或不一致都返回错误（离线端据此拒绝被篡改的信任材料/证据）。
func VerifyIntegrity(dir string, m *Manifest) error {
	for _, fe := range m.Files {
		got, err := hashFile(filepath.Join(dir, fe.Path))
		if err != nil {
			return fmt.Errorf("offline: 包文件 %s 不可读: %w", fe.Path, err)
		}
		if got.SHA256 != fe.SHA256 {
			return fmt.Errorf("offline: 文件 %s 摘要不一致（包被篡改或损坏）", fe.Path)
		}
	}
	return nil
}

// Cutoff 返回撤销信息更新截止时间。
func (m *Manifest) Cutoff() (time.Time, error) {
	return time.Parse(time.RFC3339, m.RevocationCutoff)
}
