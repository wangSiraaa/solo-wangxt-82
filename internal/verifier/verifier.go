// Package verifier 编排完整核验流程，但不把三件事混为一谈：
//
//  1. 签名有效：由 attestation 包在已知公钥全集上做 DSSE/Ed25519 密码学验签；
//  2. 签发者可信：由 trust 包判断验签公钥是否在信任根、绑定身份是否一致；
//  3. 声明符合策略：由 policy 包执行 OPA Rego（默认拒绝，含过期窗口）。
//
// 另有一道独立的硬性闸门：statement subject 摘要必须与磁盘上实际产物字节
// 重算结果一致；不一致直接拒绝（哪怕前三件都成立）。
//
// 对产物文件只做流式哈希读取，任何路径（包括失败路径）都不会执行/
// 解释/反序列化产物内容。
package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"scbverify/internal/artifact"
	"scbverify/internal/attestation"
	"scbverify/internal/policy"
	"scbverify/internal/store"
	"scbverify/internal/trust"
)

// Decision 常量。
const (
	DecisionAllow       = "allow"
	DecisionDeny        = "deny"
	DecisionNeedsReview = "needs_review"
)

// AttestationInput 是一份待核验证明（信封 JSON 原文）。
type AttestationInput struct {
	// SourceRef 标识证据来源（上传者/仓库 URL），仅用于留证。
	SourceRef string
	// EnvelopeJSON 是 DSSE 信封原始 JSON。
	EnvelopeJSON []byte
}

// Request 是一次核验请求。
type Request struct {
	ArtifactName string
	ArtifactPath string
	Attestations []AttestationInput
}

// PerAttestationResult 是单份证明的分项结论——四个维度分别给出。
type PerAttestationResult struct {
	StoredAttestationID int64  `json:"storedAttestationId,omitempty"`
	SourceRef           string `json:"sourceRef,omitempty"`

	// (1) 签名是否密码学有效
	Signature attestation.SignatureCheck `json:"signature"`
	// (2) 签发者是否受信任
	Issuer trust.TrustResult `json:"issuer"`
	// (3) 声明是否符合策略
	Policy policy.Result `json:"policy"`
	// (4) 摘要与实际产物字节是否一致（硬性闸门）
	Digest artifact.DigestResult `json:"digest"`

	// 解析出的声明事实，便于调用方与复核界面使用
	PredicateType string             `json:"predicateType,omitempty"`
	BuilderID     string             `json:"builderId,omitempty"`
	Source        *policy.SourceFact `json:"source,omitempty"`
	ParseError    string             `json:"parseError,omitempty"`
}

// FullyPassed 报告该证明是否四关全过。
func (p PerAttestationResult) FullyPassed() bool {
	return p.Signature.Valid && p.Issuer.Trusted && p.Policy.Allowed && p.Digest.Matched
}

// Response 是核验响应。
type Response struct {
	ArtifactName   string    `json:"artifactName"`
	ArtifactSHA256 string    `json:"artifactSha256"`
	ArtifactSize   int64     `json:"artifactSize"`
	EvaluatedAt    time.Time `json:"evaluatedAt"`

	// 顶层汇总是“存在可下载的可信依据”的结论；分项细节看 results。
	Decision       string `json:"decision"` // allow | deny | needs_review
	DecisionReason string `json:"decisionReason"`

	// 三件事在“是否存在任一证明分别满足”层面的汇总，仍然独立返回。
	AnySignatureValid bool `json:"anySignatureValid"`
	AnyIssuerTrusted  bool `json:"anyIssuerTrusted"`
	AnyPolicyAllowed  bool `json:"anyPolicyAllowed"`
	// 摘要闸门：任何一份证明出现摘要不一致都视为危险信号
	AnyDigestMismatch bool `json:"anyDigestMismatch"`

	// 冲突留证：全部通过但互相矛盾的证据索引
	ConflictingEvidence [][]int `json:"conflictingEvidence,omitempty"`

	Results []PerAttestationResult `json:"results"`

	StoredVerificationID int64 `json:"storedVerificationId,omitempty"`
}

// Verifier 是核验服务。
type Verifier struct {
	root    *trust.Root
	engine  *policy.Engine
	st      store.Store
	nowFunc func() time.Time
}

// New 构造核验器。nowFunc 为 nil 时使用真实时钟（测试可注入固定时间）。
func New(root *trust.Root, engine *policy.Engine, st store.Store, nowFunc func() time.Time) *Verifier {
	if nowFunc == nil {
		nowFunc = func() time.Time { return time.Now().UTC() }
	}
	return &Verifier{root: root, engine: engine, st: st, nowFunc: nowFunc}
}

// Verify 执行核验并持久化证据与判定。
func (v *Verifier) Verify(ctx context.Context, req Request) (*Response, error) {
	if len(req.Attestations) == 0 {
		return nil, fmt.Errorf("verifier: 至少需要一份证明证据")
	}

	now := v.nowFunc()

	// 1) 对实际产物做一次流式哈希。只读字节，不执行内容。
	actualSHA, err := artifact.HashFile(req.ArtifactPath)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(req.ArtifactPath)
	if err != nil {
		return nil, fmt.Errorf("verifier: 读取产物元数据失败: %w", err)
	}

	resp := &Response{
		ArtifactName:   req.ArtifactName,
		ArtifactSHA256: actualSHA,
		ArtifactSize:   fi.Size(),
		EvaluatedAt:    now,
	}

	// 2) 登记产物（幂等）。
	artifactID, err := v.st.EnsureArtifact(ctx, store.Artifact{
		Name: req.ArtifactName, SHA256: actualSHA, SizeBytes: fi.Size(), FirstSeen: now,
	})
	if err != nil {
		return nil, err
	}

	known := v.root.KnownKeys()

	// 3) 逐份证据独立核验并留证。
	for _, in := range req.Attestations {
		pr := v.verifyOne(ctx, known, in, req.ArtifactPath, req.ArtifactName, actualSHA, now)
		resp.Results = append(resp.Results, pr)
		idx := len(resp.Results) - 1

		// 原始信封无论结论如何都保存（冲突/失败证据保留供复核）。
		envKeyID, acceptedID := resp.Results[idx].Signature.EnvelopeKeyID,
			resp.Results[idx].Signature.AcceptedKeyID
		attID, err := v.st.AddAttestation(ctx, store.AttestationRecord{
			ArtifactID:    artifactID,
			EnvelopeJSON:  in.EnvelopeJSON,
			EnvelopeKeyID: envKeyID,
			AcceptedKeyID: acceptedID,
			SourceRef:     resp.Results[idx].SourceRef,
			ReceivedAt:    now,
		})
		if err != nil {
			return nil, err
		}
		resp.Results[idx].StoredAttestationID = attID
	}

	// 4) 汇总独立结论与冲突。
	for _, r := range resp.Results {
		if r.Signature.Valid {
			resp.AnySignatureValid = true
		}
		if r.Issuer.Trusted {
			resp.AnyIssuerTrusted = true
		}
		if r.Policy.Allowed {
			resp.AnyPolicyAllowed = true
		}
		for _, sm := range r.Digest.Subjects {
			if !sm.Match && sm.Algorithm != "" {
				// 仅统计“显式给出算法却不匹配”的硬失败。
				if sm.ClaimedDigest != "" && sm.ClaimedDigest != sm.ActualDigest {
					resp.AnyDigestMismatch = true
				}
			}
		}
		if r.Digest.HardReject {
			resp.AnyDigestMismatch = true
		}
	}

	// 5) 冲突检测：仅在四关全过的证据之间比较“构建者+源码+固定版本”，
	//    不一致即冲突，全部保留并转 needs_review。
	passedIdx := []int{}
	for i, r := range resp.Results {
		if r.FullyPassed() {
			passedIdx = append(passedIdx, i)
		}
	}
	groups := groupConflicting(resp.Results, passedIdx)
	resp.ConflictingEvidence = groups
	conflict := len(groups) > 0

	switch {
	case resp.AnyDigestMismatch:
		resp.Decision = DecisionDeny
		resp.DecisionReason = "存在摘要与实际产物不一致的证据，硬性拒绝（产物疑似被篡改）"
	case len(passedIdx) == 0:
		resp.Decision = DecisionDeny
		resp.DecisionReason = summarizeDeny(resp.Results)
	case conflict:
		resp.Decision = DecisionNeedsReview
		resp.DecisionReason = "存在多份全部通过但互相矛盾的证据，保留冲突证据并转人工复核"
	default:
		resp.Decision = DecisionAllow
		resp.DecisionReason = "至少一份证据四关全过，且证据间无冲突，允许下载"
	}

	// 6) 判定版本登记 + 持久化判定记录。
	policySHA := policyModuleSHA(v.engine.Module())
	if err := v.st.RegisterPolicy(ctx, store.PolicyVersion{
		PolicyID: v.engine.ID(), PolicyVersion: v.engine.Version(),
		ContentSHA256: policySHA, CreatedAt: now,
	}); err != nil {
		return nil, err
	}

	detailJSON, _ := json.Marshal(resp)
	// conflictPartners[i] 是与证据 i 矛盾的其他证据下标集合：
	// 同组（同 builder+source 固定版本）不算冲突；与任何其他组的成员互为冲突。
	conflictPartners := map[int][]int{}
	if len(groups) > 1 {
		for gi, grp := range groups {
			for _, memberIdx := range grp {
				var partners []int
				for otherGI, otherGrp := range groups {
					if otherGI == gi {
						continue
					}
					partners = append(partners, otherGrp...)
				}
				sort.Ints(partners)
				conflictPartners[memberIdx] = partners
			}
		}
	}

	verdicts := make([]store.AttestationVerdict, 0, len(resp.Results))
	for resultIdx, r := range resp.Results {
		var confIDs []int64
		for _, partnerIdx := range conflictPartners[resultIdx] {
			confIDs = append(confIDs, resp.Results[partnerIdx].StoredAttestationID)
		}
		sort.Slice(confIDs, func(a, b int) bool { return confIDs[a] < confIDs[b] })
		verdicts = append(verdicts, store.AttestationVerdict{
			AttestationID:  r.StoredAttestationID,
			SignatureValid: r.Signature.Valid,
			IssuerTrusted:  r.Issuer.Trusted,
			PolicyAllowed:  r.Policy.Allowed,
			DigestMatch:    r.Digest.Matched,
			ConflictWith:   confIDs,
		})
	}

	vid, err := v.st.SaveVerification(ctx, store.SaveVerificationParams{
		Artifact: store.Artifact{ID: artifactID, Name: req.ArtifactName, SHA256: actualSHA, SizeBytes: fi.Size()},
		Verification: store.Verification{
			ArtifactID: artifactID,
			Decision:   resp.Decision, DecisionReason: resp.DecisionReason,
			SignatureValid: resp.AnySignatureValid,
			IssuerTrusted:  resp.AnyIssuerTrusted,
			PolicyAllowed:  resp.AnyPolicyAllowed,
			DigestMatch:    !resp.AnyDigestMismatch,
			PolicyID:       v.engine.ID(), PolicyVersion: v.engine.Version(),
			PolicyContentSHA256: policySHA,
			TrustRootVersion:    v.root.Version,
			EvaluatedAt:         now, DetailJSON: detailJSON,
		},
		AttestationVerdicts: verdicts,
	})
	if err != nil {
		return nil, err
	}
	resp.StoredVerificationID = vid
	return resp, nil
}

// verifyOne 对单份证据执行四步独立核验。
func (v *Verifier) verifyOne(
	ctx context.Context,
	known map[string]ed25519.PublicKey,
	in AttestationInput,
	artifactPath, artifactName, actualSHA string,
	now time.Time,
) PerAttestationResult {
	pr := PerAttestationResult{
		SourceRef: nonEmpty(in.SourceRef, "unknown"),
		Policy:    policy.Result{Allowed: false, Violations: []string{}},
	}

	// (0) 信封解析（不属于任何信任结论，只决定能否进入验签）。
	env, err := attestation.ParseEnvelope(in.EnvelopeJSON)
	if err != nil {
		pr.Signature = attestation.SignatureCheck{Valid: false, Reason: err.Error()}
		pr.ParseError = err.Error()
		pr.Policy = deniedPolicy(v.engine, []string{"DSSE 信封无法解析"})
		pr.Digest = artifact.DigestResult{ArtifactPath: artifactPath, HardReject: true,
			Reason: "信封无法解析，无法取得声明摘要"}
		return pr
	}

	// (1) 签名有效性（独立结论一）。
	sigCheck, body, st := attestation.VerifyEnvelope(env, known)
	pr.Signature = sigCheck

	// (4) 摘要闸门：基于实际字节。无法解析 statement 时记录硬失败。
	pr.Digest = artifact.VerifySubjectDigest(artifactPath, actualSHA, st)

	// 没有合法 statement 时，信任与策略无法继续，给出独立失败结论。
	if st == nil {
		pr.ParseError = sigCheck.Reason
		pr.Issuer = trust.TrustResult{Trusted: false, KeyID: sigCheck.AcceptedKeyID,
			Reason: "载荷不是合法 in-toto statement，无法评估签发者"}
		pr.Policy = deniedPolicy(v.engine, []string{nonEmpty(sigCheck.Reason, "载荷不可解析")})
		return pr
	}

	pr.PredicateType = st.PredicateType

	// 解析 SLSA provenance（未知谓词：builder/source 留空，策略会拒绝）。
	builderID, src := extractProvenanceFacts(st)
	pr.BuilderID = builderID
	if src != nil {
		s := *src
		pr.Source = &s
	}

	// (2) 签发者可信（独立结论二）。
	pr.Issuer = v.root.Evaluate(sigCheck.AcceptedKeyID, builderID)

	// (3) 策略符合性（独立结论三）。
	inp := policy.Input{
		Statement: policy.StatementInput{
			PredicateType: st.PredicateType,
			BuilderID:     builderID,
		},
		Policy: policy.PreconditionsInput{
			SignatureValid:     sigCheck.Valid,
			IssuerTrusted:      pr.Issuer.Trusted,
			DigestMatch:        pr.Digest.Matched,
			PayloadTypeCorrect: env.PayloadType == attestation.InTotoStatementType,
		},
	}
	if src != nil {
		inp.Statement.Source = *src
	}
	res, err := v.engine.Evaluate(ctx, inp, now)
	if err != nil {
		res = policy.Result{Allowed: false, PolicyID: v.engine.ID(),
			PolicyVersion: v.engine.Version(), Violations: []string{err.Error()}, Reason: err.Error()}
	}
	pr.Policy = res
	_ = body
	return pr
}

// extractProvenanceFacts 从 statement 中提取 builder.id 与源码事实。
func extractProvenanceFacts(st *attestation.Statement) (string, *policy.SourceFact) {
	if st.PredicateType != attestation.SLSAProvenanceType {
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

// groupConflicting 按 (builder,source uri,source digest) 分组；
// 多于一个不同分组即存在冲突，返回每组的证据索引（仅返回互斥组≥2的情形）。
func groupConflicting(results []PerAttestationResult, passedIdx []int) [][]int {
	if len(passedIdx) < 2 {
		return nil
	}
	keyOf := func(r PerAttestationResult) string {
		src := ""
		if r.Source != nil {
			algs := make([]string, 0, len(r.Source.Digest))
			for a := range r.Source.Digest {
				algs = append(algs, a)
			}
			sort.Strings(algs)
			parts := make([]string, 0, len(algs))
			for _, a := range algs {
				parts = append(parts, a+"="+r.Source.Digest[a])
			}
			src = r.Source.URI + "#" + joinParts(parts)
		}
		return r.BuilderID + "|" + src
	}
	groups := map[string][]int{}
	for _, idx := range passedIdx {
		k := keyOf(results[idx])
		groups[k] = append(groups[k], idx)
	}
	if len(groups) < 2 {
		return nil
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][]int, 0, len(keys))
	for _, k := range keys {
		out = append(out, groups[k])
	}
	return out
}

func joinParts(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ","
		}
		out += p
	}
	return out
}

func summarizeDeny(results []PerAttestationResult) string {
	var sigFail, trustFail, policyFail, digestFail int
	for _, r := range results {
		if !r.Signature.Valid {
			sigFail++
		}
		if !r.Issuer.Trusted {
			trustFail++
		}
		if !r.Policy.Allowed {
			policyFail++
		}
		if !r.Digest.Matched {
			digestFail++
		}
	}
	return fmt.Sprintf(
		"没有证据同时通过四关：签名无效 %d 份，签发者不可信 %d 份，策略不符 %d 份，摘要不一致 %d 份",
		sigFail, trustFail, policyFail, digestFail)
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func deniedPolicy(e *policy.Engine, violations []string) policy.Result {
	reason := "策略拒绝："
	for i, v := range violations {
		if i > 0 {
			reason += "; "
		}
		reason += v
	}
	return policy.Result{Allowed: false, PolicyID: e.ID(), PolicyVersion: e.Version(),
		Violations: violations, Reason: reason}
}

func policyModuleSHA(module string) string {
	sum := sha256.Sum256([]byte(module))
	return hex.EncodeToString(sum[:])
}
