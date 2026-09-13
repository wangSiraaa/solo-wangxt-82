// Package store 定义核验记录的持久化接口，并提供内存实现与 PostgreSQL
// 实现。存储内容包括：产物摘要、原始证据（DSSE 信封）、以及带有策略/
// 信任根版本的判定记录。冲突证据一律保留，不做“以新盖旧”。
package store

import (
	"context"
	"time"
)

// Artifact 是被核验产物的摘要记录。只保存元数据与摘要，不保存内容。
type Artifact struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	SHA256    string    `json:"sha256"`
	SizeBytes int64     `json:"sizeBytes"`
	FirstSeen time.Time `json:"firstSeenAt"`
}

// AttestationRecord 是一份原始证明证据。
type AttestationRecord struct {
	ID            int64     `json:"id"`
	ArtifactID    int64     `json:"artifactId"`
	EnvelopeJSON  []byte    `json:"envelopeJson"`
	EnvelopeKeyID string    `json:"envelopeKeyid"`
	AcceptedKeyID string    `json:"acceptedKeyId"`
	ReceivedAt    time.Time `json:"receivedAt"`
	SourceRef     string    `json:"sourceRef"`
}

// PolicyVersion 记录参与判定的策略版本。
type PolicyVersion struct {
	PolicyID      string    `json:"policyId"`
	PolicyVersion string    `json:"policyVersion"`
	ContentSHA256 string    `json:"contentSha256"`
	CreatedAt     time.Time `json:"createdAt"`
}

// AttestationVerdict 是单份证明在一次判定中的逐项结论快照。
type AttestationVerdict struct {
	AttestationID  int64   `json:"attestationId"`
	SignatureValid bool    `json:"signatureValid"`
	IssuerTrusted  bool    `json:"issuerTrusted"`
	PolicyAllowed  bool    `json:"policyAllowed"`
	DigestMatch    bool    `json:"digestMatch"`
	ConflictWith   []int64 `json:"conflictWith,omitempty"`
}

// Verification 是一次核验的完整判定记录。
type Verification struct {
	ID                  int64                `json:"id"`
	ArtifactID          int64                `json:"artifactId"`
	Decision            string               `json:"decision"` // allow | deny | needs_review
	DecisionReason      string               `json:"decisionReason"`
	SignatureValid      bool                 `json:"signatureValid"`
	IssuerTrusted       bool                 `json:"issuerTrusted"`
	PolicyAllowed       bool                 `json:"policyAllowed"`
	DigestMatch         bool                 `json:"digestMatch"`
	PolicyID            string               `json:"policyId"`
	PolicyVersion       string               `json:"policyVersion"`
	PolicyContentSHA256 string               `json:"policyContentSha256"`
	TrustRootVersion    int                  `json:"trustRootVersion"`
	EvaluatedAt         time.Time            `json:"evaluatedAt"`
	DetailJSON          []byte               `json:"detailJson"`
	Attestations        []AttestationVerdict `json:"attestations,omitempty"`

	// 复核相关（0002）：
	// ReviewKind 为 gate（实时下载闸门）或 review（历史影响复核）。
	ReviewKind string `json:"reviewKind,omitempty"`
	// Classification 为历史复核分类：affected | insufficient | unaffected。
	Classification string `json:"classification,omitempty"`
	// ReferenceTime 是复核时采信的可信时间参照（可为空=证据不足）。
	ReferenceTime *time.Time `json:"referenceTime,omitempty"`
	// RevocationFeedVersion 是参与判定的撤销清单版本。
	RevocationFeedVersion int `json:"revocationFeedVersion,omitempty"`
}

// RevocationEventRecord 是持久化的密钥撤销事件。
type RevocationEventRecord struct {
	KeyID         string    `json:"keyId"`
	CompromisedAt time.Time `json:"compromisedAt"`
	RevokedAt     time.Time `json:"revokedAt"`
	Reason        string    `json:"reason"`
	FeedVersion   int       `json:"feedVersion"`
	RecordedAt    time.Time `json:"recordedAt"`
}

// TrustedTimeEvidenceRecord 是持久化的可信时间证据（含 TSA 签名原文）。
type TrustedTimeEvidenceRecord struct {
	ID               int64     `json:"id"`
	EnvelopeSHA256   string    `json:"envelopeSha256"`
	TSAKeyID         string    `json:"tsaKeyId"`
	TrustedTimestamp time.Time `json:"trustedTimestamp"`
	EvidenceJSON     []byte    `json:"evidenceJson"`
	ReceivedAt       time.Time `json:"receivedAt"`
}

// DependencyEdge 是一条“下游产物 -> 上游输入”的依赖边。
type DependencyEdge struct {
	ID            int64  `json:"id,omitempty"`
	ArtifactID    int64  `json:"artifactId"`
	AttestationID int64  `json:"attestationId"`
	DepName       string `json:"depName"`
	DepSHA256     string `json:"depSha256"`
}

// IngestTimeEvidenceParams 是补入可信时间证据的请求参数。
type IngestTimeEvidenceParams struct {
	EnvelopeSHA256 string
	Evidence       []byte // timestampevidence.TrustedTimeEvidence 的 JSON
}

// SaveVerificationParams 是写入判定记录的参数。
type SaveVerificationParams struct {
	Artifact            Artifact
	Attestations        []AttestationRecord
	Verification        Verification
	AttestationVerdicts []AttestationVerdict
}

// Store 是持久化抽象。
type Store interface {
	// EnsureArtifact 按 (name,sha256) 幂等登记产物，返回内部 ID。
	EnsureArtifact(ctx context.Context, a Artifact) (int64, error)
	// AddAttestation 原样保存一份证明证据（冲突也保留）。
	AddAttestation(ctx context.Context, rec AttestationRecord) (int64, error)
	// RegisterPolicy 幂等登记一个策略版本。
	RegisterPolicy(ctx context.Context, p PolicyVersion) error
	// SaveVerification 原子写入判定记录及其逐项证明结论。
	SaveVerification(ctx context.Context, p SaveVerificationParams) (int64, error)
	// GetArtifact 按名称与摘要定位产物。
	GetArtifact(ctx context.Context, name, sha256 string) (*Artifact, error)
	// GetArtifactByID 按内部 ID 取产物。
	GetArtifactByID(ctx context.Context, id int64) (*Artifact, error)
	// ListAttestations 列出某产物的全部证明证据（含历史与冲突项）。
	ListAttestations(ctx context.Context, artifactID int64) ([]AttestationRecord, error)
	// ListVerifications 列出某产物的历史判定。
	ListVerifications(ctx context.Context, artifactID int64) ([]Verification, error)
	// GetVerification 取单次判定详情。
	GetVerification(ctx context.Context, id int64) (*Verification, error)

	// --- 撤销 / 可信时间证据 / 依赖链（0002） ---

	// UpsertRevocationEvent 幂等登记一条密钥撤销事件。
	UpsertRevocationEvent(ctx context.Context, rec RevocationEventRecord) error
	// ListRevocationEvents 返回全部撤销事件。
	ListRevocationEvents(ctx context.Context) ([]RevocationEventRecord, error)
	// IngestTimeEvidence 幂等保存一条 TSA 可信时间证据（原始签名材料不动 DSSE）。
	IngestTimeEvidence(ctx context.Context, p IngestTimeEvidenceParams) (int64, error)
	// ListTimeEvidence 返回某信封的全部可信时间证据原文（按可信时间升序）。
	ListTimeEvidence(ctx context.Context, envelopeSHA256 string) ([]TrustedTimeEvidenceRecord, error)
	// AddDependencyEdges 幂等保存由某证明声明的依赖边。
	AddDependencyEdges(ctx context.Context, edges []DependencyEdge) error
	// ListDependencyEdges 返回某下游产物登记的全部依赖边。
	ListDependencyEdges(ctx context.Context, artifactID int64) ([]DependencyEdge, error)
	// ListDependentEdges 反查：哪些下游产物声明固定引用了 (depName, depSHA)。
	ListDependentEdges(ctx context.Context, depName, depSHA string) ([]DependencyEdge, error)
	// FindArtifactByName 仅按名称查找产物（依赖链跨摘要定位上游时使用）。
	FindArtifactByName(ctx context.Context, name string) ([]Artifact, error)

	// Ping 检查连通性。
	Ping(ctx context.Context) error
	// Close 释放资源。
	Close() error
}
