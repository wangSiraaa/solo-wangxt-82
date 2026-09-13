// Package attestation 负责 DSSE 封装（v1）与 in-toto 声明（v1 Statement）
// 的解析、签名与密码学校验。
//
// 这里只做“封装与密码学层面”的事：DSSE PAE 重放保护、载荷解码、
// JSON 结构解析、Ed25519 验签。它**不**判断签名者是否受信任，也**不**
// 判断声明内容是否符合业务策略——那两件事分别属于 trust 与 policy 包，
// 三者结果必须分开返回。
package attestation

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// InTotoStatementType 是 DSSE 载荷类型字符串，标识载荷为 in-toto 声明。
const InTotoStatementType = "https://in-toto.io/Statement/v1"

// Subject 是 in-toto Statement 的 subject 条目：产物名 + 摘要集合。
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement 是 in-toto v1 声明。
// Predicate 保留为原始 JSON，由上层按 predicateType 再解析，
// 避免对未知谓词直接报错丢弃证据。
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// BuildDefinition 是 SLSA Provenance v1.0 构建定义中本服务关心的字段。
type BuildDefinition struct {
	BuildType string `json:"buildType"`
	// ExternalParameters 通常为结构化对象，这里取出 source 信息时
	// 单独定义 Source 结构配合解析。
	ExternalParameters json.RawMessage `json:"externalParameters"`
	InternalParameters json.RawMessage `json:"internalParameters"`
	// ResolvedDependencies 是本次构建实际使用的上游输入（源码/产物）的
	// 固定描述（名称 + 摘要）。用于构建依赖产物链。
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// SourceRef 描述构建所用源码仓库与固定版本。
type SourceRef struct {
	URI    string `json:"uri"`
	Digest Digest `json:"digest"`
}

// Digest 是算法->十六进制摘要的映射。
type Digest map[string]string

// RunDetails 是 SLSA Provenance v1.0 的 runDetails。
type RunDetails struct {
	Builder    Builder              `json:"builder"`
	Metadata   Metadata             `json:"metadata"`
	Byproducts []ResourceDescriptor `json:"byproducts,omitempty"`
}

// Builder 是运行构建流程的构建者标识。
type Builder struct {
	ID string `json:"id"`
}

// Metadata 记录构建开始/结束时间。
type Metadata struct {
	StartedOn  string `json:"startedOn,omitempty"`
	FinishedOn string `json:"finishedOn,omitempty"`
}

// ResourceDescriptor 对应 in-toto ResourceDescriptor，这里只保留常用字段。
type ResourceDescriptor struct {
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// ProvenancePredicate 是 SLSA Provenance v1.0 谓词中本服务关心的字段。
// https://slsa.dev/spec/v1.0/provenance
type ProvenancePredicate struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// SourceExternalParameters 用于从 buildDefinition.externalParameters 中
// 取出源码定位信息（workflow 型构建器也常用该形状）。
type SourceExternalParameters struct {
	Source *SourceRef `json:"source,omitempty"`
}

// slsaProvenanceType 是本服务接受的谓词类型。
const SLSAProvenanceType = "https://slsa.dev/provenance/v1"

// ParseStatement 从已通过签名验证的载荷字节中解析 in-toto v1 声明，
// 并做结构性校验。注意：结构合法不等于内容受信任。
func ParseStatement(body []byte) (*Statement, error) {
	var st Statement
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("attestation: statement 不是合法 JSON: %w", err)
	}
	if st.Type != "https://in-toto.io/Statement/v1" {
		return nil, fmt.Errorf("attestation: 不支持的 _type %q（期望 https://in-toto.io/Statement/v1）", st.Type)
	}
	if len(st.Subject) == 0 {
		return nil, errors.New("attestation: statement 缺少 subject")
	}
	for i, s := range st.Subject {
		if s.Name == "" {
			return nil, fmt.Errorf("attestation: subject[%d] 缺少 name", i)
		}
		if len(s.Digest) == 0 {
			return nil, fmt.Errorf("attestation: subject[%d] 缺少 digest", i)
		}
	}
	if st.PredicateType == "" {
		return nil, errors.New("attestation: statement 缺少 predicateType")
	}
	return &st, nil
}

// ParseSLSAProvenance 从谓词原始 JSON 解析 SLSA Provenance v1.0。
func ParseSLSAProvenance(raw json.RawMessage) (*ProvenancePredicate, error) {
	var p ProvenancePredicate
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("attestation: provenance 谓词不是合法 JSON: %w", err)
	}
	if p.RunDetails.Builder.ID == "" {
		return nil, errors.New("attestation: provenance 缺少 runDetails.builder.id")
	}
	return &p, nil
}

// Envelope 是 DSSE v1 信封的本地类型（与 go-securesystemslib 的类型等价，
// 单独定义便于 JSON 标签与持久化保持稳定）。
type Envelope struct {
	PayloadType string        `json:"payloadType"`
	Payload     string        `json:"payload"`
	Signatures  []EnvelopeSig `json:"signatures"`
}

// EnvelopeSig 是信封中的一条签名。
type EnvelopeSig struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// ParseEnvelope 解析 DSSE 信封 JSON。此步骤**不**验签。
func ParseEnvelope(data []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("attestation: DSSE 信封不是合法 JSON: %w", err)
	}
	if e.Payload == "" {
		return nil, errors.New("attestation: DSSE 信封缺少 payload")
	}
	if e.PayloadType == "" {
		return nil, errors.New("attestation: DSSE 信封缺少 payloadType")
	}
	if len(e.Signatures) == 0 {
		return nil, errors.New("attestation: DSSE 信封没有任何签名")
	}
	return &e, nil
}

// toLibEnvelope / fromLibEnvelope 在本地类型与库类型之间转换。
// --- 规范化信封摘要：时间证据绑定与跨存储比对统一使用该摘要 ---

// CanonicalEnvelopeSHA256 返回 DSSE 信封的**规范化**字节摘要：先解析再以
// 确定字段顺序重新 JSON 编码（Go 对 map 键排序）。这样无论信封原文的空白、
// 键序如何，也无论存储是否经过 JSONB 规范化，绑定的摘要都一致。
//
// 时间证据（TSA）与复核服务必须使用该摘要，而不是原始字节摘要。
func CanonicalEnvelopeSHA256(raw []byte) (string, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("attestation: 信封规范化失败: %w", err)
	}
	canonical, err := json.Marshal(&env)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func (e *Envelope) toLibEnvelope() *dsse.Envelope {
	sigs := make([]dsse.Signature, 0, len(e.Signatures))
	for _, s := range e.Signatures {
		sigs = append(sigs, dsse.Signature{KeyID: s.KeyID, Sig: s.Sig})
	}
	return &dsse.Envelope{PayloadType: e.PayloadType, Payload: e.Payload, Signatures: sigs}
}

func fromLibEnvelope(e *dsse.Envelope) *Envelope {
	sigs := make([]EnvelopeSig, 0, len(e.Signatures))
	for _, s := range e.Signatures {
		sigs = append(sigs, EnvelopeSig{KeyID: s.KeyID, Sig: s.Sig})
	}
	return &Envelope{PayloadType: e.PayloadType, Payload: e.Payload, Signatures: sigs}
}

// ed25519Verifier 实现 dsse.Verifier；KeyID 由公钥自行计算，
// 不信信封自报的 keyid。
type ed25519Verifier struct {
	pub   ed25519.PublicKey
	keyID string
}

func newEd25519Verifier(pub ed25519.PublicKey) (*ed25519Verifier, error) {
	id, err := publicKeyID(pub)
	if err != nil {
		return nil, err
	}
	return &ed25519Verifier{pub: pub, keyID: id}, nil
}

func (v *ed25519Verifier) Verify(_ context.Context, data, sig []byte) error {
	if !ed25519.Verify(v.pub, data, sig) {
		return errBadSignature
	}
	return nil
}

func (v *ed25519Verifier) KeyID() (string, error)   { return v.keyID, nil }
func (v *ed25519Verifier) Public() crypto.PublicKey { return v.pub }

var errBadSignature = errors.New("attestation: ed25519 签名校验失败")

// ed25519Signer 用于演示向量的签名生成（服务端正常运行时不需要私钥）。
type ed25519Signer struct {
	*ed25519Verifier
	priv ed25519.PrivateKey
}

func newEd25519Signer(priv ed25519.PrivateKey) (*ed25519Signer, error) {
	pub := priv.Public().(ed25519.PublicKey)
	v, err := newEd25519Verifier(pub)
	if err != nil {
		return nil, err
	}
	return &ed25519Signer{ed25519Verifier: v, priv: priv}, nil
}

func (s *ed25519Signer) Sign(_ context.Context, data []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, data), nil
}

// SignStatement 用 Ed25519 私钥对 in-toto Statement 做 DSSE 封装签名。
// 仅演示/测试代码使用（确定性签名便于生成可复现向量）。
func SignStatement(priv ed25519.PrivateKey, st *Statement) (*Envelope, error) {
	body, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("attestation: 序列化 statement: %w", err)
	}
	signer, err := newEd25519Signer(priv)
	if err != nil {
		return nil, err
	}
	es, err := dsse.NewEnvelopeSigner(signer)
	if err != nil {
		return nil, err
	}
	env, err := es.SignPayload(context.Background(), InTotoStatementType, body)
	if err != nil {
		return nil, fmt.Errorf("attestation: DSSE 签名: %w", err)
	}
	return fromLibEnvelope(env), nil
}

// SignatureCheck 是“签名有效”这一件事的独立结论。
type SignatureCheck struct {
	// Valid 为 true 当且仅当：载荷类型正确、存在至少一条由已知公钥
	// 通过的 Ed25519 签名，且 DSSE PAE 校验流程由成熟库完成。
	Valid bool `json:"valid"`
	// AcceptedKeyID 是实际通过验签的公钥指纹（由服务端自行计算）。
	AcceptedKeyID string `json:"acceptedKeyId,omitempty"`
	// EnvelopeKeyID 是信封里自报的 keyid，仅作取证记录，不参与信任。
	EnvelopeKeyID string `json:"envelopeKeyId,omitempty"`
	// Reason 在 Valid=false 时给出失败原因。
	Reason string `json:"reason,omitempty"`
}

// VerifyEnvelope 在给定的“已知公钥集合”上做纯密码学验签。
//
// knownKeys 包含服务端有记录的**所有**公钥（含不受信任的构建者），
// 这样“签名有效但签发者不受信任”才能作为独立情况被区分出来；
// 若公钥完全不在已知集合内，返回未知密钥（签名本身无法被核验）。
//
// 成功时同时返回解码后的载荷字节与解析出的 Statement。
func VerifyEnvelope(env *Envelope, knownKeys map[string]ed25519.PublicKey) (SignatureCheck, []byte, *Statement) {
	libEnv := env.toLibEnvelope()
	if libEnv.PayloadType != InTotoStatementType {
		return SignatureCheck{Valid: false, Reason: fmt.Sprintf("payloadType 不是 %s", InTotoStatementType)}, nil, nil
	}

	var envelopeKeyID string
	if len(env.Signatures) > 0 {
		envelopeKeyID = env.Signatures[0].KeyID
	}

	// 收集验签提供者，同时记录其服务端指纹。
	type provider struct {
		v  dsse.Verifier
		id string
	}
	var providers []provider
	var idOrder []string
	for id, pub := range knownKeys {
		v, err := newEd25519Verifier(pub)
		if err != nil {
			continue
		}
		providers = append(providers, provider{v: v, id: id})
		idOrder = append(idOrder, id)
	}
	if len(providers) == 0 {
		return SignatureCheck{Valid: false, EnvelopeKeyID: envelopeKeyID, Reason: "服务端没有配置任何验签公钥"}, nil, nil
	}

	dsseVs := make([]dsse.Verifier, 0, len(providers))
	for _, p := range providers {
		dsseVs = append(dsseVs, p.v)
	}
	ev, err := dsse.NewEnvelopeVerifier(dsseVs...)
	if err != nil {
		return SignatureCheck{Valid: false, EnvelopeKeyID: envelopeKeyID, Reason: fmt.Sprintf("构造验签器失败: %v", err)}, nil, nil
	}

	accepted, err := ev.Verify(context.Background(), libEnv)
	if err != nil || len(accepted) == 0 {
		// 区分：是否存在一条签名“声称”的 keyid 恰好对应某个已知公钥。
		// 不用于信任判断，只为报告更准确的失败原因。
		return SignatureCheck{Valid: false, EnvelopeKeyID: envelopeKeyID,
			Reason: classifyVerifyError(env, err)}, nil, nil
	}

	// 找到实际通过验签的那个 provider 的指纹。
	acceptedID := ""
	for _, p := range providers {
		if p.v.Public().(ed25519.PublicKey).Equal(accepted[0].Public) {
			acceptedID = p.id
			break
		}
	}
	if acceptedID == "" {
		id, _ := publicKeyID(accepted[0].Public.(ed25519.PublicKey))
		acceptedID = id
	}

	body, err := libEnv.DecodeB64Payload()
	if err != nil {
		return SignatureCheck{Valid: false, AcceptedKeyID: acceptedID, EnvelopeKeyID: envelopeKeyID,
			Reason: fmt.Sprintf("载荷 base64 解码失败: %v", err)}, nil, nil
	}
	st, err := ParseStatement(body)
	if err != nil {
		// 签名有效，但载荷不是合法 in-toto Statement：签名这件事仍然成立，
		// 结构错误作为策略层的拒绝理由，所以这里 Valid 保持 true 并返回载荷。
		return SignatureCheck{Valid: true, AcceptedKeyID: acceptedID, EnvelopeKeyID: envelopeKeyID,
			Reason: fmt.Sprintf("载荷结构不合法: %v", err)}, body, nil
	}
	return SignatureCheck{Valid: true, AcceptedKeyID: acceptedID, EnvelopeKeyID: envelopeKeyID}, body, st
}

func classifyVerifyError(env *Envelope, err error) string {
	if errors.Is(err, dsse.ErrNoSignature) {
		return "信封中没有任何签名"
	}
	if err == nil {
		return "签名均未通过校验"
	}
	return fmt.Sprintf("DSSE 验签失败: %v", err)
}
