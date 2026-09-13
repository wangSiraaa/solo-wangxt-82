// Package timestampevidence 实现“可信时间证据”（trusted time evidence）。
//
// 它回答一个非常具体的问题：**这份 DSSE 信封在时间 T 时已经存在**。
// 由信任根中授权的时间戳权威（TSA）对“信封摘要 + 时间戳”做 Ed25519 签名。
//
// 边界（重要）：
//   - 可信时间证据**不**证明声明内容为真，构建者签名仍须独立验签；
//   - provenance 里 runDetails.metadata 的 startedOn/finishedOn 属于
//     **自报时间**，任何持有构建密钥的人都能填写，不能当作可信历史证明；
//   - TSA 在撤销发生**之后**才签发的时间证据，只能证明信封“此刻已存在”，
//     无法把它追溯为撤销前产物（是否采信由 revocation/review 规则决定）。
package timestampevidence

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"scbverify/internal/cryptokit"
)

// EvidenceType 标识证据格式版本。
const EvidenceType = "https://scbverify.example.com/timestamp-evidence/v1"

// TrustedTimeEvidence 是一条可信时间证据。
type TrustedTimeEvidence struct {
	Version int    `json:"version"`
	Type    string `json:"type"`
	// EnvelopeSHA256 是被加盖时间戳的 DSSE 信封原文的 SHA-256（十六进制）。
	EnvelopeSHA256 string `json:"envelopeSha256"`
	// Timestamp 是 TSA 见证该信封存在的时间（RFC3339，UTC）。
	Timestamp string `json:"timestamp"`
	// TsaKeyID 是 TSA 公钥指纹（服务端会按实际验签公钥自行复核）。
	TsaKeyID string `json:"tsaKeyId"`
	// Signature 是对下述待签字节的 Ed25519 签名（base64）。
	Signature string `json:"signature"`
}

// signedPayload 是时间证据实际被签名的稳定字节结构。
// 字段顺序固定，Go 的 encoding/json 对结构体按声明顺序输出，保证可复现。
type signedPayload struct {
	Type           string `json:"type"`
	EnvelopeSHA256 string `json:"envelopeSha256"`
	Timestamp      string `json:"timestamp"`
	TsaKeyID       string `json:"tsaKeyId"`
}

func (e *TrustedTimeEvidence) payloadToSign() ([]byte, error) {
	if e.Type != EvidenceType {
		return nil, fmt.Errorf("timestampevidence: 不支持的证据类型 %q", e.Type)
	}
	return json.Marshal(signedPayload{
		Type:           e.Type,
		EnvelopeSHA256: e.EnvelopeSHA256,
		Timestamp:      e.Timestamp,
		TsaKeyID:       e.TsaKeyID,
	})
}

// Sign 用 TSA 私钥对 (信封摘要, 时间) 生成可信时间证据。
// 仅演示/测试向量生成使用；正常核验服务不需要 TSA 私钥。
func Sign(tsaPrivate ed25519.PrivateKey, envelopeSHA256 string, at time.Time) (*TrustedTimeEvidence, error) {
	pub := tsaPrivate.Public().(ed25519.PublicKey)
	id, err := cryptokit.KeyIDFromPublic(pub)
	if err != nil {
		return nil, err
	}
	ev := &TrustedTimeEvidence{
		Version:        1,
		Type:           EvidenceType,
		EnvelopeSHA256: envelopeSHA256,
		Timestamp:      at.UTC().Format(time.RFC3339),
		TsaKeyID:       id,
	}
	body, err := ev.payloadToSign()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(tsaPrivate, body)
	ev.Signature = base64.StdEncoding.EncodeToString(sig)
	return ev, nil
}

// LoadEvidenceFile 从 JSON 文件读取一条时间证据。
func LoadEvidenceFile(path string) (*TrustedTimeEvidence, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("timestampevidence: 读取 %q: %w", path, err)
	}
	var ev TrustedTimeEvidence
	if err := json.Unmarshal(b, &ev); err != nil {
		return nil, fmt.Errorf("timestampevidence: JSON 非法: %w", err)
	}
	return &ev, nil
}

// Verification 是一条时间证据的核验结论。
type Verification struct {
	Valid bool `json:"valid"`
	// Time 是证据中可信的时间点（仅在 Valid=true 时有意义）。
	Time           time.Time `json:"-"`
	Timestamp      string    `json:"timestamp,omitempty"`
	TsaKeyID       string    `json:"tsaKeyId,omitempty"`
	TSAName        string    `json:"tsaName,omitempty"`
	EnvelopeSHA256 string    `json:"envelopeSha256,omitempty"`
	Reason         string    `json:"reason,omitempty"`
}

// Verify 校验时间证据：
//  1. 结构与时间格式合法；
//  2. TSA 公钥必须在信任根授权集合中（按证据自报 keyid 定位后，
//     仍以“验签实际通过的公钥”的指纹为准）；
//  3. Ed25519 签名通过；
//  4. 证据绑定的信封摘要等于期望的 envelopeSHA256。
func Verify(ev *TrustedTimeEvidence, expectedEnvelopeSHA256 string,
	tsaKeys map[string]ed25519.PublicKey, tsaName func(string) string) (Verification, error) {
	if ev == nil {
		return Verification{Valid: false, Reason: "时间证据为空"}, nil
	}
	out := Verification{EnvelopeSHA256: ev.EnvelopeSHA256, TsaKeyID: ev.TsaKeyID, Timestamp: ev.Timestamp}
	if ev.Type != EvidenceType {
		out.Reason = fmt.Sprintf("不支持的时间证据类型 %q", ev.Type)
		return out, nil
	}
	if ev.EnvelopeSHA256 == "" || ev.Timestamp == "" || ev.Signature == "" || ev.TsaKeyID == "" {
		out.Reason = "时间证据字段不完整"
		return out, nil
	}
	if expectedEnvelopeSHA256 != "" && ev.EnvelopeSHA256 != expectedEnvelopeSHA256 {
		out.Reason = "时间证据绑定的是另一份信封（摘要不一致），不能用于本证据"
		return out, nil
	}
	ts, err := time.Parse(time.RFC3339, ev.Timestamp)
	if err != nil {
		out.Reason = fmt.Sprintf("时间戳不是合法 RFC3339: %v", err)
		return out, nil
	}
	pub, ok := tsaKeys[ev.TsaKeyID]
	if !ok {
		out.Reason = "时间证据的 TSA 公钥不在信任根授权集合中"
		return out, nil
	}
	sig, err := base64.StdEncoding.DecodeString(ev.Signature)
	if err != nil {
		out.Reason = fmt.Sprintf("时间证据签名 base64 非法: %v", err)
		return out, nil
	}
	body, err := ev.payloadToSign()
	if err != nil {
		out.Reason = err.Error()
		return out, nil
	}
	// 不信任证据自报 keyid：验签后用实际公钥指纹复核。
	if !ed25519.Verify(pub, body, sig) {
		out.Reason = "TSA Ed25519 签名校验失败"
		return out, nil
	}
	actualID, err := cryptokit.KeyIDFromPublic(pub)
	if err != nil {
		return out, err
	}
	if actualID != ev.TsaKeyID {
		out.Reason = "时间证据自报 tsaKeyId 与实际验签公钥指纹不一致"
		return out, nil
	}
	out.Valid = true
	out.Time = ts.UTC()
	if tsaName != nil {
		out.TSAName = tsaName(actualID)
	}
	return out, nil
}

// VerifyAll 对同一信封核验多条时间证据，返回全部“密码学有效且绑定本信封”
// 的结论（调用方再按撤销时间窗口取舍）。顺序按时间升序，保证结果稳定。
func VerifyAll(evs []*TrustedTimeEvidence, expectedEnvelopeSHA256 string,
	tsaKeys map[string]ed25519.PublicKey, tsaName func(string) string) ([]Verification, error) {
	var out []Verification
	for _, ev := range evs {
		v, err := Verify(ev, expectedEnvelopeSHA256, tsaKeys, tsaName)
		if err != nil {
			return nil, err
		}
		if v.Valid {
			out = append(out, v)
		}
	}
	sortByTime(out)
	return out, nil
}

func sortByTime(vs []Verification) {
	for i := 1; i < len(vs); i++ {
		for j := i; j > 0 && vs[j-1].Time.After(vs[j].Time); j-- {
			vs[j-1], vs[j] = vs[j], vs[j-1]
		}
	}
}

// SelfReportedTime 是 provenance 中构建者自报的时间，**不可信**。
type SelfReportedTime struct {
	StartedOn  string `json:"startedOn,omitempty"`
	FinishedOn string `json:"finishedOn,omitempty"`
}

// Parse 仅用于留证展示；返回的时间不得作为“可信历史证明”。
func (s SelfReportedTime) Parse() (time.Time, error) {
	raw := s.FinishedOn
	if raw == "" {
		raw = s.StartedOn
	}
	if raw == "" {
		return time.Time{}, errors.New("没有自报时间")
	}
	return time.Parse(time.RFC3339, raw)
}

// 保证 crypto 包被引用（KeyID 计算依赖统一算法标签）。
var _ crypto.PublicKey = (ed25519.PublicKey)(nil)
