// Package trust 实现“签发者可信”这一独立判定。
//
// 信任根（trust root）是一份显式配置：哪些公钥指纹在什么时间区间内被信任、
// 每个被信任密钥绑定到哪个签发者身份（builder.id）、以及哪些公钥被授权为
// 时间戳权威（TSA，对可信时间证据签名）。
//
// 判断依据是**验签实际通过的公钥指纹**，而不是信封里自报的 keyid，
// 也不是 JSON 声明里自报的 builder.id（后者还要与绑定值比对）。
package trust

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"

	"scbverify/internal/cryptokit"
)

// TrustedKey 是一条信任锚：公钥指纹 + 其被授权代表的签发者身份。
type TrustedKey struct {
	// KeyID 必须等于该公钥 DER(SPKI) 的 SHA-256 指纹；加载时会强校验。
	KeyID string `json:"keyId"`
	// Issuer 是该密钥被授权的签发者标识，需与 provenance 中
	// runDetails.builder.id 完全一致。
	Issuer string `json:"issuer"`
	// PublicKeyPEM 是 PKIX PEM 公钥（演示用途直接内嵌；
	// 生产可改为引用受保护路径/KMS 引用）。
	PublicKeyPEM string `json:"publicKeyPem"`
}

// TimestampAuthority 是一把被授权签发可信时间证据的公钥锚。
type TimestampAuthority struct {
	// Name 是该时间戳权威的可读名称（如演示 TSA）。
	Name string `json:"name"`
	// KeyID 必须等于公钥指纹；加载时强校验。
	KeyID        string `json:"keyId"`
	PublicKeyPEM string `json:"publicKeyPem"`
}

// Root 是服务的信任根。
type Root struct {
	// Version 随信任根内容变更而提升，会写入判定记录。
	Version int          `json:"version"`
	Name    string       `json:"name"`
	Keys    []TrustedKey `json:"trustedKeys"`
	// TimestampAuthorities 是可信时间证据的验签公钥集合。
	TimestampAuthorities []TimestampAuthority `json:"timestampAuthorities,omitempty"`

	// byID 是解析后的索引：服务端 KeyID -> 信任锚。
	byID map[string]TrustedKey
	// pubByID 是已知公钥全集（含不受信任构建者的公钥）。
	// 不受信任的公钥通过 AddKnownButUntrustedKey 单独登记，
	// 这样密码学验签可以成功，信任判定仍独立失败。
	pubByID map[string]ed25519.PublicKey
	// tsaByID 是 TSA 公钥索引：KeyID -> 公钥。
	tsaByID map[string]ed25519.PublicKey
	// tsaNames 是 TSA 公钥 KeyID -> 名称。
	tsaNames map[string]string
}

// LoadRoot 从 JSON 文件加载并校验信任根。
func LoadRoot(path string) (*Root, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("trust: 读取信任根 %q: %w", path, err)
	}
	return ParseRoot(data)
}

// ParseRoot 解析并校验信任根 JSON。
func ParseRoot(data []byte) (*Root, error) {
	var r Root
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("trust: 信任根 JSON 非法: %w", err)
	}
	r.byID = make(map[string]TrustedKey)
	r.pubByID = make(map[string]ed25519.PublicKey)
	r.tsaByID = make(map[string]ed25519.PublicKey)
	r.tsaNames = make(map[string]string)
	if len(r.Keys) == 0 {
		return nil, fmt.Errorf("trust: 信任根版本 %d 没有任何受信任密钥", r.Version)
	}
	for i, k := range r.Keys {
		if k.KeyID == "" || k.Issuer == "" || k.PublicKeyPEM == "" {
			return nil, fmt.Errorf("trust: trustedKeys[%d] 字段不完整", i)
		}
		pub, err := cryptokit.ParsePublicPEM([]byte(k.PublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("trust: trustedKeys[%d] 公钥解析失败: %w", i, err)
		}
		actualID, err := cryptokit.KeyIDFromPublic(pub)
		if err != nil {
			return nil, fmt.Errorf("trust: trustedKeys[%d] 指纹计算失败: %w", i, err)
		}
		if actualID != k.KeyID {
			return nil, fmt.Errorf("trust: trustedKeys[%d] 自报 keyId 与公钥实际指纹不一致（拒绝信任错配的锚点）", i)
		}
		if _, dup := r.byID[k.KeyID]; dup {
			return nil, fmt.Errorf("trust: 受信任密钥 %s 重复", k.KeyID)
		}
		r.byID[k.KeyID] = k
		r.pubByID[k.KeyID] = pub
	}
	for i, tsa := range r.TimestampAuthorities {
		if tsa.KeyID == "" || tsa.PublicKeyPEM == "" {
			return nil, fmt.Errorf("trust: timestampAuthorities[%d] 字段不完整", i)
		}
		pub, err := cryptokit.ParsePublicPEM([]byte(tsa.PublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("trust: timestampAuthorities[%d] 公钥解析失败: %w", i, err)
		}
		actualID, err := cryptokit.KeyIDFromPublic(pub)
		if err != nil {
			return nil, fmt.Errorf("trust: timestampAuthorities[%d] 指纹计算失败: %w", i, err)
		}
		if actualID != tsa.KeyID {
			return nil, fmt.Errorf("trust: timestampAuthorities[%d] 自报 keyId 与公钥指纹不一致", i)
		}
		r.tsaByID[actualID] = pub
		r.tsaNames[actualID] = tsa.Name
	}
	return &r, nil
}

// AddKnownButUntrustedKey 登记一把“已知但不受信任”的公钥。
// 用于把不受信任构建者纳入密码学验签范围，使“签名有效”与
// “签发者可信”可以分别得出结论。
func (r *Root) AddKnownButUntrustedKey(pub ed25519.PublicKey) error {
	id, err := cryptokit.KeyIDFromPublic(pub)
	if err != nil {
		return err
	}
	if _, exists := r.pubByID[id]; !exists {
		r.pubByID[id] = pub
	}
	return nil
}

// KnownKeys 返回验签所需的已知公钥全集（受信任 + 已知但不受信任）。
func (r *Root) KnownKeys() map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(r.pubByID))
	for id, pub := range r.pubByID {
		out[id] = pub
	}
	return out
}

// TSAKeys 返回所有时间戳权威公钥（KeyID -> 公钥）。
func (r *Root) TSAKeys() map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(r.tsaByID))
	for id, pub := range r.tsaByID {
		out[id] = pub
	}
	return out
}

// TSAName 返回某 TSA KeyID 的名称。
func (r *Root) TSAName(keyID string) string { return r.tsaNames[keyID] }

// IsTSAKeyID 判断某公钥指纹是否为授权 TSA。
func (r *Root) IsTSAKeyID(keyID string) bool {
	_, ok := r.tsaByID[keyID]
	return ok
}

// Anchor 返回某受信任密钥的信任锚及其是否存在。
func (r *Root) Anchor(keyID string) (TrustedKey, bool) {
	a, ok := r.byID[keyID]
	return a, ok
}

// TrustResult 是“签发者可信”这一件事的独立结论。
type TrustResult struct {
	Trusted bool `json:"trusted"`
	// KeyID 是验签实际通过的公钥指纹。
	KeyID string `json:"keyId,omitempty"`
	// BoundIssuer 是该公钥在信任根中被绑定的签发者身份。
	BoundIssuer string `json:"boundIssuer,omitempty"`
	// ClaimedBuilder 是 provenance 中自报的 builder.id。
	ClaimedBuilder string `json:"claimedBuilder,omitempty"`
	// Revoked 表示该签名密钥命中撤销事件（信任根层面不再可信）。
	Revoked bool   `json:"revoked,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// Evaluate 判断：通过验签的公钥是否在信任根中，且其绑定签发者身份
// 与 provenance 自报的 builder.id 一致。
//
// acceptedKeyID 为空（签名未通过）时直接不可信，但理由会如实区分。
// 撤销状态由调用方（revocation 包）在 Gate 阶段注入，不在信任根本身；
// 这里只回答“信任根是否锚定且身份一致”。
func (r *Root) Evaluate(acceptedKeyID, claimedBuilderID string) TrustResult {
	if acceptedKeyID == "" {
		return TrustResult{Trusted: false, ClaimedBuilder: claimedBuilderID,
			Reason: "没有通过密码学验签的公钥，无法建立签发者信任"}
	}
	anchor, ok := r.byID[acceptedKeyID]
	if !ok {
		return TrustResult{Trusted: false, KeyID: acceptedKeyID, ClaimedBuilder: claimedBuilderID,
			Reason: "验签公钥不在信任根中（已知构建者，但未被授权）"}
	}
	if claimedBuilderID == "" {
		return TrustResult{Trusted: false, KeyID: acceptedKeyID, BoundIssuer: anchor.Issuer,
			Reason: "provenance 缺少 builder.id，无法与绑定身份比对"}
	}
	if anchor.Issuer != claimedBuilderID {
		return TrustResult{Trusted: false, KeyID: acceptedKeyID, BoundIssuer: anchor.Issuer,
			ClaimedBuilder: claimedBuilderID,
			Reason:         "签名密钥绑定的签发者与 provenance 自报 builder.id 不一致（身份错配）"}
	}
	return TrustResult{Trusted: true, KeyID: acceptedKeyID, BoundIssuer: anchor.Issuer,
		ClaimedBuilder: claimedBuilderID}
}
