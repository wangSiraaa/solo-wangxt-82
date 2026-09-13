package store

import (
	"context"
	"sort"
	"time"
)

// MemoryStore 的撤销/时间证据/依赖链实现。
//
// 注意：DSSE 信封原文（attestations）与判定记录从不被覆盖；补入可信时间
// 证据只会新增 trustedTimeEvidence 记录，历史复核只会新增 verifications
// 记录（review_kind='review'）。

func (m *MemoryStore) UpsertRevocationEvent(_ context.Context, rec RevocationEventRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, e := range m.revocationEvents {
		if e.KeyID == rec.KeyID {
			m.revocationEvents[i] = rec
			return nil
		}
	}
	m.revocationEvents = append(m.revocationEvents, rec)
	return nil
}

func (m *MemoryStore) ListRevocationEvents(_ context.Context) ([]RevocationEventRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]RevocationEventRecord(nil), m.revocationEvents...)
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out, nil
}

func (m *MemoryStore) IngestTimeEvidence(_ context.Context, p IngestTimeEvidenceParams) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ts time.Time
	var tsaKeyID string
	// 轻量解析用于去重/索引，完整结构由上层负责验签。
	var probe struct {
		Timestamp string `json:"timestamp"`
		TsaKeyID  string `json:"tsaKeyId"`
	}
	_ = jsonUnmarshal(p.Evidence, &probe)
	if probe.Timestamp != "" {
		ts, _ = time.Parse(time.RFC3339, probe.Timestamp)
	}
	tsaKeyID = probe.TsaKeyID

	for _, e := range m.trustedTimeEvidence {
		if e.EnvelopeSHA256 == p.EnvelopeSHA256 &&
			e.TSAKeyID == tsaKeyID && e.TrustedTimestamp.Equal(ts) {
			return e.ID, nil // 幂等：同一证据不重复入库
		}
	}
	m.tteSeq++
	rec := TrustedTimeEvidenceRecord{
		ID: m.tteSeq, EnvelopeSHA256: p.EnvelopeSHA256, TSAKeyID: tsaKeyID,
		TrustedTimestamp: ts.UTC(), EvidenceJSON: append([]byte(nil), p.Evidence...),
		ReceivedAt: time.Now().UTC(),
	}
	m.trustedTimeEvidence = append(m.trustedTimeEvidence, rec)
	return rec.ID, nil
}

func (m *MemoryStore) ListTimeEvidence(_ context.Context, envelopeSHA256 string) ([]TrustedTimeEvidenceRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []TrustedTimeEvidenceRecord
	for _, e := range m.trustedTimeEvidence {
		if e.EnvelopeSHA256 == envelopeSHA256 {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].TrustedTimestamp.Before(out[j].TrustedTimestamp)
	})
	return out, nil
}

func (m *MemoryStore) AddDependencyEdges(_ context.Context, edges []DependencyEdge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range edges {
		dup := false
		for _, ex := range m.dependencies {
			if ex.ArtifactID == e.ArtifactID && ex.AttestationID == e.AttestationID &&
				ex.DepName == e.DepName && ex.DepSHA256 == e.DepSHA256 {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		m.depSeq++
		e.ID = m.depSeq
		m.dependencies = append(m.dependencies, e)
	}
	return nil
}

func (m *MemoryStore) ListDependencyEdges(_ context.Context, artifactID int64) ([]DependencyEdge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []DependencyEdge
	for _, e := range m.dependencies {
		if e.ArtifactID == artifactID {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DepName != out[j].DepName {
			return out[i].DepName < out[j].DepName
		}
		return out[i].DepSHA256 < out[j].DepSHA256
	})
	return out, nil
}

func (m *MemoryStore) FindArtifactByName(_ context.Context, name string) ([]Artifact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Artifact
	for _, a := range m.artifacts {
		if a.Name == name {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *MemoryStore) ListDependentEdges(_ context.Context, depName, depSHA string) ([]DependencyEdge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []DependencyEdge
	for _, e := range m.dependencies {
		if e.DepName == depName && e.DepSHA256 == depSHA {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
