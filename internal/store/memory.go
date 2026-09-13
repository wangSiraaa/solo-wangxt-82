package store

import (
	"context"
	"sync"
	"time"
)

// MemoryStore 是用于测试/无数据库演示的线程安全内存实现。
// 语义与 PostgreSQL 实现保持一致：证据冲突不去重、判定全量保留。
type MemoryStore struct {
	mu           sync.Mutex
	artifactSeq  int64
	attestSeq    int64
	verifSeq     int64
	artifacts    []Artifact
	attestations []AttestationRecord
	policies     map[string]PolicyVersion
	verifs       []Verification
	verifAttests map[int64][]AttestationVerdict
}

// NewMemoryStore 创建空内存存储。
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		policies:     make(map[string]PolicyVersion),
		verifAttests: make(map[int64][]AttestationVerdict),
	}
}

func (m *MemoryStore) EnsureArtifact(_ context.Context, a Artifact) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.artifacts {
		if m.artifacts[i].Name == a.Name && m.artifacts[i].SHA256 == a.SHA256 {
			return m.artifacts[i].ID, nil
		}
	}
	m.artifactSeq++
	a.ID = m.artifactSeq
	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now().UTC()
	}
	m.artifacts = append(m.artifacts, a)
	return a.ID, nil
}

func (m *MemoryStore) AddAttestation(_ context.Context, rec AttestationRecord) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attestSeq++
	rec.ID = m.attestSeq
	if rec.ReceivedAt.IsZero() {
		rec.ReceivedAt = time.Now().UTC()
	}
	m.attestations = append(m.attestations, rec)
	return rec.ID, nil
}

func (m *MemoryStore) RegisterPolicy(_ context.Context, p PolicyVersion) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	m.policies[p.PolicyID+"#"+p.PolicyVersion] = p
	return nil
}

func (m *MemoryStore) SaveVerification(_ context.Context, p SaveVerificationParams) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verifSeq++
	v := p.Verification
	v.ID = m.verifSeq
	v.ArtifactID = p.Artifact.ID
	if v.EvaluatedAt.IsZero() {
		v.EvaluatedAt = time.Now().UTC()
	}
	m.verifs = append(m.verifs, v)
	verdicts := make([]AttestationVerdict, len(p.AttestationVerdicts))
	copy(verdicts, p.AttestationVerdicts)
	m.verifAttests[v.ID] = verdicts
	return v.ID, nil
}

func (m *MemoryStore) GetArtifact(_ context.Context, name, sha256 string) (*Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.artifacts {
		if m.artifacts[i].Name == name && m.artifacts[i].SHA256 == sha256 {
			a := m.artifacts[i]
			return &a, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) ListAttestations(_ context.Context, artifactID int64) ([]AttestationRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AttestationRecord
	for _, a := range m.attestations {
		if a.ArtifactID == artifactID {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *MemoryStore) ListVerifications(_ context.Context, artifactID int64) ([]Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Verification
	for _, v := range m.verifs {
		if v.ArtifactID == artifactID {
			vv := v
			vv.Attestations = append([]AttestationVerdict(nil), m.verifAttests[v.ID]...)
			out = append(out, vv)
		}
	}
	return out, nil
}

func (m *MemoryStore) GetVerification(_ context.Context, id int64) (*Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.verifs {
		if v.ID == id {
			vv := v
			vv.Attestations = append([]AttestationVerdict(nil), m.verifAttests[id]...)
			return &vv, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemoryStore) Ping(_ context.Context) error { return nil }
func (m *MemoryStore) Close() error                 { return nil }
