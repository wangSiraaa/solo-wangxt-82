package offline

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"scbverify/internal/artifact"
	"scbverify/internal/attestation"
	"scbverify/internal/policy"
	"scbverify/internal/revocation"
	"scbverify/internal/timestampevidence"
	"scbverify/internal/trust"
)

// EvidenceConclusion 是离线对单份证据的判定（四关 + 撤销 + 历史分类）。
type EvidenceConclusion struct {
	AttestationPath string `json:"attestationPath"`
	ArtifactName    string `json:"artifactName"`
	ArtifactSHA256  string `json:"artifactSha256"`

	SignatureValid   bool     `json:"signatureValid"`
	SignatureReason  string   `json:"signatureReason,omitempty"`
	IssuerTrusted    bool     `json:"issuerTrusted"`
	IssuerReason     string   `json:"issuerReason,omitempty"`
	KeyRevoked       bool     `json:"keyRevoked"`
	DigestMatched    bool     `json:"digestMatched"`
	DigestReason     string   `json:"digestReason,omitempty"`
	PolicyAllowed    bool     `json:"policyAllowed"`
	PolicyViolations []string `json:"policyViolations,omitempty"`

	// 历史复核：只有自报时间不算数。
	SelfReportedTime          string `json:"selfReportedTime,omitempty"`
	SelfReportedTimeUntrusted bool   `json:"selfReportedTimeUntrusted"`
	TrustedTimestampCount     int    `json:"trustedTimestampCount"`
	EarliestTrustedTime       string `json:"earliestTrustedTime,omitempty"`
	// HistoricalClassification 为 unaffected | affected | insufficient。
	HistoricalClassification string `json:"historicalClassification"`
	HistoricalReason         string `json:"historicalReason"`
}

// Conclusion 是离线核验总结论。
type Conclusion struct {
	// GateDecision 是“按更新截止时点的撤销信息做下载闸门”的结论。
	GateDecision string `json:"gateDecision"`
	// ArtifactByEvidence 是每份证据的明细。
	ByEvidence []EvidenceConclusion `json:"byEvidence"`
	// 有效性边界（不得声称实时）。
	RealTimeValid     bool      `json:"realTimeValid"`
	RevocationCutoff  time.Time `json:"revocationCutoff"`
	RevocationFeedVer int       `json:"revocationFeedVersion"`
	PolicyID          string    `json:"policyId"`
	PolicyVersion     string    `json:"policyVersion"`
	EvaluatedAt       time.Time `json:"evaluatedAt"`
	ValidityNotice    string    `json:"validityNotice"`
}

// ArtifactFile 告诉离线核验器某目标产物在本机的实际路径。
type ArtifactFile struct {
	Name string
	Path string
}

// Verify 在离线包目录上核验：完整性 -> 加载信任根/策略/撤销 -> 逐证据判定。
// now 仅用于策略生效窗口评估（可固定以便可重复）；撤销结论只对 cutoff 负责。
func Verify(ctx context.Context, dir string, artifacts []ArtifactFile, now time.Time) (*Conclusion, error) {
	m, err := LoadManifest(dir)
	if err != nil {
		return nil, err
	}
	if err := VerifyIntegrity(dir, m); err != nil {
		return nil, err
	}
	cutoff, err := m.Cutoff()
	if err != nil {
		return nil, err
	}

	root, err := trust.LoadRoot(filepath.Join(dir, m.TrustRootPath))
	if err != nil {
		return nil, err
	}
	engine, err := policy.LoadEngine(filepath.Join(dir, m.PolicyPath))
	if err != nil {
		return nil, err
	}
	revBytes, err := os.ReadFile(filepath.Join(dir, m.RevocationPath))
	if err != nil {
		return nil, err
	}
	rev, err := revocation.ParseFeed(revBytes)
	if err != nil {
		return nil, err
	}
	// 撤销清单中带公钥的事件也纳入已知公钥，使其签名可验但闸门失败。
	if pubs, err := rev.KnownRevocationPublicKeys(); err == nil {
		for _, pub := range pubs {
			_ = root.AddKnownButUntrustedKey(pub)
		}
	}

	pathByName := map[string]string{}
	for _, a := range artifacts {
		pathByName[a.Name] = a.Path
	}
	known := root.KnownKeys()

	out := &Conclusion{
		RealTimeValid: false, RevocationCutoff: cutoff,
		RevocationFeedVer: m.RevocationFeedVersion,
		PolicyID:          engine.ID(), PolicyVersion: engine.Version(),
		EvaluatedAt: now.UTC(), ValidityNotice: m.ValidityNotice,
	}
	gateAllow := true
	hasEvidence := false

	for _, ref := range m.Evidence {
		hasEvidence = true
		c := EvidenceConclusion{
			AttestationPath: ref.AttestationPath, ArtifactName: ref.ArtifactName,
			SelfReportedTimeUntrusted: true,
		}
		envBytes, err := os.ReadFile(filepath.Join(dir, ref.AttestationPath))
		if err != nil {
			return nil, err
		}
		envSum, err := attestation.CanonicalEnvelopeSHA256(envBytes)
		if err != nil {
			return nil, err
		}
		env, err := attestation.ParseEnvelope(envBytes)
		if err != nil {
			c.SignatureReason = err.Error()
			c.HistoricalClassification = revocation.ClassInsufficient
			c.HistoricalReason = "信封无法解析"
			out.ByEvidence = append(out.ByEvidence, c)
			gateAllow = false
			continue
		}
		sigCheck, _, st := attestation.VerifyEnvelope(env, known)
		c.SignatureValid = sigCheck.Valid
		c.SignatureReason = sigCheck.Reason

		// 加载该证据的可信时间证据（消费端按信封规范化摘要严格绑定）。
		var points []revocation.TrustedTimePoint
		var tteObjs []*timestampevidence.TrustedTimeEvidence
		for _, tp := range ref.TimestampPaths {
			raw, err := os.ReadFile(filepath.Join(dir, tp))
			if err != nil {
				return nil, err
			}
			var ev timestampevidence.TrustedTimeEvidence
			if err := json.Unmarshal(raw, &ev); err != nil {
				continue
			}
			tteObjs = append(tteObjs, &ev)
		}
		verified, err := timestampevidence.VerifyAll(
			tteObjs, envSum, root.TSAKeys(), root.TSAName)
		if err != nil {
			return nil, err
		}
		c.TrustedTimestampCount = len(verified)
		for _, v := range verified {
			points = append(points, revocation.TrustedTimePoint{Time: v.Time, TSA: v.TSAName})
			if c.EarliestTrustedTime == "" || v.Time.Format(time.RFC3339) < c.EarliestTrustedTime {
				c.EarliestTrustedTime = v.Time.Format(time.RFC3339)
			}
		}

		var builderID, selfTime string
		var src *policy.SourceFact
		if st != nil {
			builderID, src = extractFacts(st)
			if st.PredicateType == attestation.SLSAProvenanceType {
				if prov, perr := attestation.ParseSLSAProvenance(st.Predicate); perr == nil {
					if prov.RunDetails.Metadata.FinishedOn != "" {
						selfTime = prov.RunDetails.Metadata.FinishedOn
					} else {
						selfTime = prov.RunDetails.Metadata.StartedOn
					}
				}
			}
			c.SelfReportedTime = selfTime
		}

		if sigCheck.Valid {
			trustRes := root.Evaluate(sigCheck.AcceptedKeyID, builderID)
			c.IssuerTrusted = trustRes.Trusted
			c.IssuerReason = trustRes.Reason

			gate := rev.Gate(sigCheck.AcceptedKeyID)
			c.KeyRevoked = gate.Revoked
			if gate.Revoked {
				c.IssuerTrusted = false
			}

			// 摘要闸门：实际文件字节重算，只比目标同名 subject。
			artifactPath := pathByName[ref.ArtifactName]
			if artifactPath == "" {
				c.DigestReason = "离线核验未提供该产物的本地文件路径"
			} else {
				actualSHA, herr := artifact.HashFile(artifactPath)
				if herr != nil {
					return nil, herr
				}
				c.ArtifactSHA256 = actualSHA
				d := artifact.VerifySubjectDigest(artifactPath, ref.ArtifactName, actualSHA, st)
				c.DigestMatched = d.Matched
				if !d.Matched {
					c.DigestReason = d.Reason
				}
			}

			// OPA 策略（撤销命中时强制不信任输入）。
			inp := policy.Input{
				Statement: policy.StatementInput{
					PredicateType: func() string {
						if st == nil {
							return ""
						}
						return st.PredicateType
					}(),
					BuilderID: builderID,
				},
				Policy: policy.PreconditionsInput{
					SignatureValid:     sigCheck.Valid,
					IssuerTrusted:      c.IssuerTrusted,
					DigestMatch:        c.DigestMatched,
					PayloadTypeCorrect: env.PayloadType == attestation.InTotoStatementType,
				},
			}
			if src != nil {
				inp.Statement.Source = *src
			}
			pres, err := engine.Evaluate(ctx, inp, now)
			if err != nil {
				return nil, fmt.Errorf("offline: OPA 评估失败: %w", err)
			}
			c.PolicyAllowed = pres.Allowed
			c.PolicyViolations = pres.Violations

			// 历史三分类（只看可信 TSA 时间；自报时间不参与）。
			cls := rev.Classify(sigCheck.AcceptedKeyID, points)
			c.HistoricalClassification = cls.Class
			c.HistoricalReason = cls.Reason

			// 下载闸门（fail-closed，按 cutoff 时点撤销信息）。
			if gate.Revoked || !c.IssuerTrusted || !c.DigestMatched || !pres.Allowed {
				gateAllow = false
			}
		} else {
			gateAllow = false
			c.HistoricalClassification = revocation.ClassInsufficient
			c.HistoricalReason = "签名未通过，不能作为可信历史证据"
		}
		out.ByEvidence = append(out.ByEvidence, c)
	}

	if !hasEvidence {
		out.GateDecision = "deny"
		return out, nil
	}
	if gateAllow {
		out.GateDecision = "allow"
	} else {
		out.GateDecision = "deny"
	}
	return out, nil
}

func extractFacts(st *attestation.Statement) (string, *policy.SourceFact) {
	if st == nil || st.PredicateType != attestation.SLSAProvenanceType {
		return "", nil
	}
	p, err := attestation.ParseSLSAProvenance(st.Predicate)
	if err != nil {
		return "", nil
	}
	src := &policy.SourceFact{Digest: map[string]string{}}
	var ext attestation.SourceExternalParameters
	if err := json.Unmarshal(p.BuildDefinition.ExternalParameters, &ext); err == nil && ext.Source != nil {
		src.URI = ext.Source.URI
		for alg, val := range ext.Source.Digest {
			src.Digest[alg] = val
		}
	}
	return p.RunDetails.Builder.ID, src
}

var _ = ed25519.PublicKey(nil)
