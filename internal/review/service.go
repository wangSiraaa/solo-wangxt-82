// Package review 在密钥泄露后做“历史影响复核”，与实时下载闸门严格区分。
//
// 它不会改写任何历史结论：原始 DSSE 信封、原始 gate 判定都原样保留；
// 复核只会**新增** review_kind='review' 的判定记录。
//
// 输入：
//   - 存储中的原始签名材料（重新独立验签，不信任历史判定的布尔值）；
//   - 已入库且通过授权 TSA 验签、绑定到具体信封摘要的可信时间证据；
//   - 撤销清单（含泄露/撤销时间）；
//   - provenance 中声明的固定依赖产物链。
//
// 输出三分类（每个产物、每条证据分别给出）：
// affected（确定受影响）/ insufficient（证据不足）/ unaffected（不受影响）。
package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"scbverify/internal/attestation"
	"scbverify/internal/policy"
	"scbverify/internal/revocation"
	"scbverify/internal/store"
	"scbverify/internal/timestampevidence"
	"scbverify/internal/trust"
)

// AttestationReview 是单份历史证据的复核结论。
type AttestationReview struct {
	StoredAttestationID int64  `json:"storedAttestationId"`
	EnvelopeSHA256      string `json:"envelopeSha256"`
	SignatureValid      bool   `json:"signatureValid"`
	RootAnchored        bool   `json:"rootAnchored"`
	SigningKeyID        string `json:"signingKeyId,omitempty"`
	KeyRevoked          bool   `json:"keyRevoked"`

	// SelfReportedTime 仅留证展示，显式标注不可信，绝不参与判定。
	SelfReportedTime          string `json:"selfReportedTime,omitempty"`
	SelfReportedTimeUntrusted bool   `json:"selfReportedTimeUntrusted"`

	// TrustedTimestampCount 是通过 TSA 验签的可信时间证据条数。
	TrustedTimestampCount int `json:"trustedTimestampCount"`
	// EarliestTrusted 是用于分类的最早可信时间。
	EarliestTrusted *time.Time `json:"earliestTrusted,omitempty"`
	// Classification 是该证据自身签名密钥的撤销分类。
	Classification string `json:"classification"`
	Reason         string `json:"reason"`

	// DeclaredDependencies 是该证据声明的固定上游输入。
	DeclaredDependencies []store.DependencyEdge `json:"declaredDependencies,omitempty"`
}

// ArtifactReview 是一个产物在一次历史复核中的结论。
type ArtifactReview struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`

	// Classification 为综合自身证据与依赖传播后的分类。
	Classification string `json:"classification"`
	Reason         string `json:"reason"`
	// ReferenceTime 是采信的最早可信时间（证据不足时为空）。
	ReferenceTime *time.Time `json:"referenceTime,omitempty"`
	// ReviewRecordID 是新写入的 review 判定记录 ID（原始 gate 记录不动）。
	ReviewRecordID int64 `json:"reviewRecordId,omitempty"`

	Attestations []AttestationReview `json:"attestations"`
	// ReachedVia 记录依赖传播路径（产物名序列），便于复核解释。
	ReachedVia []string `json:"reachedVia,omitempty"`
}

// Report 是一次历史复核的完整结果。
type Report struct {
	GeneratedAt time.Time `json:"generatedAt"`
	// RevocationFeedVersion 是本次复采用的撤销清单版本。
	RevocationFeedVersion int `json:"revocationFeedVersion"`
	// RevocationCutoff 是撤销清单的更新截止（复核结论只对该时点之前的信息负责）。
	RevocationCutoff time.Time `json:"revocationCutoff"`
	// RealTimeValid 恒为 false：历史复核不是实时结论。
	RealTimeValid bool `json:"realTimeValid"`

	Artifacts []ArtifactReview `json:"artifacts"`
}

// Service 执行历史复核。
type Service struct {
	st     store.Store
	root   *trust.Root
	engine *policy.Engine
	rev    *revocation.List
	now    func() time.Time
	// cutoff 是撤销信息更新截止；默认取撤销清单中最晚 revokedAt 与 now 的较早者。
	cutoff time.Time
}

// NewService 构造复核服务。
func NewService(st store.Store, root *trust.Root, engine *policy.Engine,
	rev *revocation.List, nowFunc func() time.Time) *Service {
	if nowFunc == nil {
		nowFunc = func() time.Time { return time.Now().UTC() }
	}
	cutoff := nowFunc()
	if rev != nil {
		for _, id := range rev.RevokedKeyIDs() {
			if e, ok := rev.EventFor(id); ok {
				if rt, err := time.Parse(time.RFC3339, e.RevokedAt); err == nil && rt.After(cutoff) {
					cutoff = rt
				}
			}
		}
	}
	return &Service{st: st, root: root, engine: engine, rev: rev, now: nowFunc, cutoff: cutoff.UTC()}
}

// RevocationCutoff 暴露撤销信息更新截止时间。
func (s *Service) RevocationCutoff() time.Time { return s.cutoff }

// IngestTimeEvidence 补入一条可信时间证据：必须通过授权 TSA 验签、绑定到
// 给定信封摘要，才会落库。补入证据不会修改原始 DSSE 信封或历史 gate 判定。
func (s *Service) IngestTimeEvidence(ctx context.Context, envelopeSHA string,
	ev *timestampevidence.TrustedTimeEvidence) (int64, error) {
	if ev == nil {
		return 0, fmt.Errorf("review: 时间证据为空")
	}
	v, err := timestampevidence.Verify(ev, envelopeSHA, s.root.TSAKeys(), s.root.TSAName)
	if err != nil {
		return 0, err
	}
	if !v.Valid {
		return 0, fmt.Errorf("review: 时间证据未通过 TSA 验签: %s", v.Reason)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return 0, err
	}
	return s.st.IngestTimeEvidence(ctx, store.IngestTimeEvidenceParams{
		EnvelopeSHA256: envelopeSHA, Evidence: raw,
	})
}

// graphNode / Review 定义见下方（保持一个连续的 BFS 实现）。

type graphNode struct {
	id   int64
	name string
	sha  string
}

// Review 从一个根产物出发，沿依赖链做历史复核，并为每个到达的产物新增
// review 判定记录（不改写任何原始材料）。
func (s *Service) Review(ctx context.Context, rootName, rootSHA string) (*Report, error) {
	report := &Report{
		GeneratedAt:   s.now().UTC(),
		RealTimeValid: false,
	}
	if s.rev != nil {
		report.RevocationFeedVersion = s.rev.Version
	}
	report.RevocationCutoff = s.cutoff

	rootArt, err := s.st.GetArtifact(ctx, rootName, rootSHA)
	if err != nil {
		return nil, fmt.Errorf("review: 定位根产物失败: %w", err)
	}
	rootNode := graphNode{id: rootArt.ID, name: rootArt.Name, sha: rootArt.SHA256}

	// ---- 阶段 1：双向 BFS，建立根产物的可达闭包（上游链 + 下游引用） ----
	type ownedEdge struct {
		target graphNode
		edge   store.DependencyEdge
	}
	ownedBy := map[int64][]ownedEdge{} // 边的“声明方（下游）” -> 它固定引用的上游
	paths := map[int64][]string{rootNode.id: {rootNode.name}}
	visited := map[int64]bool{rootNode.id: true}
	var order []graphNode
	queue := []graphNode{rootNode}

	addOwnedEdge := func(ownerID int64, e store.DependencyEdge) error {
		up, err := s.st.GetArtifact(ctx, e.DepName, e.DepSHA256)
		if err != nil {
			if errorsIs(err, store.ErrNotFound) {
				return nil
			}
			return err
		}
		ownedBy[ownerID] = append(ownedBy[ownerID], ownedEdge{
			target: graphNode{id: up.ID, name: up.Name, sha: up.SHA256}, edge: e,
		})
		return nil
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		order = append(order, cur)

		// 该产物声明的固定上游（沿依赖边向下）。
		upEdges, err := s.st.ListDependencyEdges(ctx, cur.id)
		if err != nil {
			return nil, err
		}
		dedup := map[string]bool{}
		for _, e := range upEdges {
			key := e.DepName + "@" + e.DepSHA256 + "#" + fmt.Sprint(e.AttestationID)
			if dedup[key] {
				continue
			}
			dedup[key] = true
			if err := addOwnedEdge(cur.id, e); err != nil {
				return nil, err
			}
		}
		for _, oe := range ownedBy[cur.id] {
			if !visited[oe.target.id] {
				visited[oe.target.id] = true
				paths[oe.target.id] = append(append([]string{}, paths[cur.id]...), oe.target.name)
				queue = append(queue, oe.target)
			}
		}

		// 谁固定引用了该产物（反向边）。
		downEdges, err := s.st.ListDependentEdges(ctx, cur.name, cur.sha)
		if err != nil {
			return nil, err
		}
		seen := map[int64]bool{}
		for _, e := range downEdges {
			if seen[e.ArtifactID] {
				continue
			}
			seen[e.ArtifactID] = true
			down, err := s.st.GetArtifactByID(ctx, e.ArtifactID)
			if err != nil {
				continue
			}
			dn := graphNode{id: down.ID, name: down.Name, sha: down.SHA256}
			if err := addOwnedEdge(dn.id, e); err != nil {
				return nil, err
			}
			if !visited[dn.id] {
				visited[dn.id] = true
				paths[dn.id] = append(append([]string{}, paths[cur.id]...), down.Name)
				queue = append(queue, dn)
			}
		}
	}

	// ---- 阶段 2：逐产物复核自身证据（独立重验签 + 时间证据 + 撤销分类） ----
	reviews := map[int64]*ArtifactReview{}
	ownClass := map[int64]string{}
	ownRefTime := map[int64]*time.Time{}
	for _, n := range order {
		ar, err := s.reviewOne(ctx, n)
		if err != nil {
			return nil, err
		}
		ar.ReachedVia = paths[n.id]
		reviews[n.id] = ar
		ownClass[n.id] = aggregateAttestationClass(ar.Attestations)
		if rt := earliestReference(ar.Attestations); rt != nil {
			t := *rt
			ownRefTime[n.id] = &t
		}
	}

	// ---- 阶段 3：污染沿“受信任的固定依赖边”定向传播（上游 -> 声明方） ----
	// 多跳链按可达顺序迭代到不动点；污染不会反向（引用方不会污染其上游）。
	affected := map[int64]bool{}
	inherited := map[int64]string{}
	for _, n := range order {
		if ownClass[n.id] == revocation.ClassAffected {
			affected[n.id] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, n := range order {
			if affected[n.id] {
				continue
			}
			for _, oe := range ownedBy[n.id] {
				if !affected[oe.target.id] {
					continue
				}
				if s.edgeTrusted(n.id, oe.edge, reviews) {
					affected[n.id] = true
					inherited[n.id] = fmt.Sprintf(
						"固定依赖链引用了确定受影响的上游 %s（路径 %v）：污染传播",
						oe.target.name, paths[n.id])
					changed = true
					break
				}
			}
		}
	}

	// ---- 阶段 4：汇总并仅新增 review 判定记录 ----
	for _, n := range order {
		ar := reviews[n.id]
		switch {
		case affected[n.id]:
			ar.Classification = revocation.ClassAffected
			if ownClass[n.id] == revocation.ClassAffected {
				ar.Reason = "自身签名密钥在泄露窗口内有可信存在证据：确定受影响"
			} else if r := inherited[n.id]; r != "" {
				ar.Reason = r
			} else {
				ar.Reason = "依赖链引用了确定受影响的上游：污染传播"
			}
			ar.ReferenceTime = ownRefTime[n.id]
		case ownClass[n.id] == revocation.ClassInsufficient:
			ar.Classification = revocation.ClassInsufficient
			ar.Reason = "存在已撤销签名密钥的证据，但缺少撤销前的可信时间证据：证据不足，保留待复核"
		default:
			ar.Classification = revocation.ClassUnaffected
			ar.ReferenceTime = ownRefTime[n.id]
			if ar.Reason == "" {
				ar.Reason = "有撤销前的可信时间证据或密钥未撤销，且依赖链未引用受影响上游：不受影响"
			}
		}

		recID, err := s.persistReview(ctx, n, ar)
		if err != nil {
			return nil, err
		}
		ar.ReviewRecordID = recID
		report.Artifacts = append(report.Artifacts, *ar)
	}
	// 稳定输出：按内部 ID（与遍历顺序一致）。
	sort.SliceStable(report.Artifacts, func(i, j int) bool {
		if len(report.Artifacts[i].ReachedVia) != len(report.Artifacts[j].ReachedVia) {
			return len(report.Artifacts[i].ReachedVia) < len(report.Artifacts[j].ReachedVia)
		}
		return report.Artifacts[i].Name < report.Artifacts[j].Name
	})
	return report, nil
}

// edgeTrusted 判断依赖边来自一份签名有效且被信任根锚定的证据，
// 伪造/无效 provenance 里声称的依赖不能用于污染传播。
func (s *Service) edgeTrusted(artifactID int64, e store.DependencyEdge, reviews map[int64]*ArtifactReview) bool {
	ar := reviews[artifactID]
	if ar == nil {
		return false
	}
	for _, a := range ar.Attestations {
		if a.StoredAttestationID == e.AttestationID && a.SignatureValid && a.RootAnchored {
			return true
		}
	}
	return false
}

// resolveUpstream 按依赖边的固定摘要定位已登记的上游产物。
// 非 sha256 固定（如仅有 git sha1）无法在产物表中定位，返回空（不传播）。
func (s *Service) resolveUpstream(ctx context.Context, e store.DependencyEdge) ([]graphNode, error) {
	if len(e.DepSHA256) == 0 || hasAlgorithmPrefix(e.DepSHA256) {
		return nil, nil
	}
	a, err := s.st.GetArtifact(ctx, e.DepName, e.DepSHA256)
	if err != nil {
		if errorsIs(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return []graphNode{{id: a.ID, name: a.Name, sha: a.SHA256}}, nil
}

// reviewOne 复核单个产物的全部历史证据（独立重验签 + 时间证据 + 撤销分类）。
func (s *Service) reviewOne(ctx context.Context, n graphNode) (*ArtifactReview, error) {
	ar := &ArtifactReview{Name: n.name, SHA256: n.sha}
	recs, err := s.st.ListAttestations(ctx, n.id)
	if err != nil {
		return nil, err
	}
	known := s.root.KnownKeys()
	edges, _ := s.st.ListDependencyEdges(ctx, n.id)
	edgeByAtt := map[int64][]store.DependencyEdge{}
	for _, e := range edges {
		edgeByAtt[e.AttestationID] = append(edgeByAtt[e.AttestationID], e)
	}

	for _, rec := range recs {
		ar2 := AttestationReview{
			StoredAttestationID:       rec.ID,
			EnvelopeSHA256:            envelopeSHA(rec.EnvelopeJSON),
			SelfReportedTimeUntrusted: true,
			DeclaredDependencies:      edgeByAtt[rec.ID],
		}
		env, perr := attestation.ParseEnvelope(rec.EnvelopeJSON)
		if perr == nil {
			sigCheck, _, st := attestation.VerifyEnvelope(env, known)
			ar2.SignatureValid = sigCheck.Valid
			ar2.SigningKeyID = sigCheck.AcceptedKeyID
			if sigCheck.Valid {
				if _, ok := s.root.Anchor(sigCheck.AcceptedKeyID); ok {
					ar2.RootAnchored = true
				}
			}
			// 自报时间：仅展示，绝不参与分类。
			if st != nil && st.PredicateType == attestation.SLSAProvenanceType {
				if prov, perr2 := attestation.ParseSLSAProvenance(st.Predicate); perr2 == nil {
					if prov.RunDetails.Metadata.FinishedOn != "" {
						ar2.SelfReportedTime = prov.RunDetails.Metadata.FinishedOn
					} else {
						ar2.SelfReportedTime = prov.RunDetails.Metadata.StartedOn
					}
				}
			}
		}

		// 可信时间证据：从存储取出并逐条用授权 TSA 重新验签。
		points := []revocation.TrustedTimePoint{}
		if ar2.SignatureValid {
			tteRecs, err := s.st.ListTimeEvidence(ctx, ar2.EnvelopeSHA256)
			if err != nil {
				return nil, err
			}
			var evs []*timestampevidence.TrustedTimeEvidence
			for _, tr := range tteRecs {
				var ev timestampevidence.TrustedTimeEvidence
				if err := json.Unmarshal(tr.EvidenceJSON, &ev); err != nil {
					continue
				}
				evs = append(evs, &ev)
			}
			verified, err := timestampevidence.VerifyAll(
				evs, ar2.EnvelopeSHA256, s.root.TSAKeys(), s.root.TSAName)
			if err != nil {
				return nil, err
			}
			ar2.TrustedTimestampCount = len(verified)
			for _, v := range verified {
				points = append(points, revocation.TrustedTimePoint{Time: v.Time, TSA: v.TSAName})
			}
		}

		// 撤销分类（仅对签名有效的证据；无效证据不产生结论）。
		if ar2.SignatureValid {
			ar2.KeyRevoked = s.rev != nil && s.rev.IsRevoked(ar2.SigningKeyID)
			c := s.rev.Classify(ar2.SigningKeyID, points)
			ar2.Classification = c.Class
			ar2.Reason = c.Reason
			if c.TrustedEarliest != nil {
				t := *c.TrustedEarliest
				ar2.EarliestTrusted = &t
			}
		} else {
			ar2.Classification = revocation.ClassInsufficient
			ar2.Reason = "历史信封签名无法通过验签，不能作为可信历史证据"
		}
		ar.Attestations = append(ar.Attestations, ar2)
	}
	sort.Slice(ar.Attestations, func(i, j int) bool {
		return ar.Attestations[i].StoredAttestationID < ar.Attestations[j].StoredAttestationID
	})
	return ar, nil
}

// persistReview 只新增一条 review 判定记录，原始 gate 记录与信封保持不变。
func (s *Service) persistReview(ctx context.Context, n graphNode, ar *ArtifactReview) (int64, error) {
	detail, _ := json.Marshal(ar)
	anySig, anyDigest := false, true
	for _, a := range ar.Attestations {
		if a.SignatureValid {
			anySig = true
		}
	}
	decision := "needs_review"
	if ar.Classification == revocation.ClassUnaffected {
		decision = "allow"
	}
	if ar.Classification == revocation.ClassAffected {
		decision = "deny"
	}
	v := store.Verification{
		Decision: decision, DecisionReason: ar.Reason,
		SignatureValid: anySig, IssuerTrusted: anySig,
		PolicyAllowed: ar.Classification != revocation.ClassAffected,
		DigestMatch:   anyDigest,
		PolicyID:      s.engine.ID(), PolicyVersion: s.engine.Version(),
		PolicyContentSHA256: policyContentSHA(s.engine.Module()),
		TrustRootVersion:    s.root.Version,
		EvaluatedAt:         s.now().UTC(), DetailJSON: detail,
		ReviewKind: "review", Classification: ar.Classification,
		ReferenceTime:         ar.ReferenceTime,
		RevocationFeedVersion: s.revVersion(),
	}
	return s.st.SaveVerification(ctx, store.SaveVerificationParams{
		Artifact:     store.Artifact{ID: n.id, Name: n.name, SHA256: n.sha},
		Verification: v,
	})
}

func (s *Service) revVersion() int {
	if s.rev == nil {
		return 0
	}
	return s.rev.Version
}

func aggregateAttestationClass(as []AttestationReview) string {
	hasValid := false
	worst := ""
	rank := map[string]int{
		revocation.ClassUnaffected: 1, revocation.ClassInsufficient: 2,
		revocation.ClassAffected: 3,
	}
	for _, a := range as {
		if !a.SignatureValid {
			continue
		}
		hasValid = true
		if rank[a.Classification] > rank[worst] {
			worst = a.Classification
		}
	}
	if !hasValid {
		return revocation.ClassInsufficient
	}
	return worst
}

func earliestReference(as []AttestationReview) *time.Time {
	var best *time.Time
	for i := range as {
		if as[i].EarliestTrusted != nil {
			if best == nil || as[i].EarliestTrusted.Before(*best) {
				t := *as[i].EarliestTrusted
				best = &t
			}
		}
	}
	return best
}

func envelopeSHA(raw []byte) string {
	// 使用规范化信封摘要：库内经 JSONB 存储后原始字节可能变化。
	s, err := attestation.CanonicalEnvelopeSHA256(raw)
	if err != nil {
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	return s
}

func policyContentSHA(module string) string {
	sum := sha256.Sum256([]byte(module))
	return hex.EncodeToString(sum[:])
}

func hasAlgorithmPrefix(s string) bool {
	// "sha1:...." 等非纯 sha256 摘要无法在产物表（仅 sha256）定位。
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
		if s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f' {
			continue
		}
		return true
	}
	return false
}

func errorsIs(err, target error) bool { return err != nil && err.Error() == target.Error() }
