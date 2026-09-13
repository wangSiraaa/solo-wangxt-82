// Package revocation 处理签名密钥撤销事件及其在“下载闸门”与
// “历史影响复核”两类场景中的判定。
//
// 设计原则：发现某构建签名密钥泄露后，**不能**简单把数据库里所有历史
// “通过”改成“失败”。历史产物是否受影响，取决于它是否有可信时间证据
// 证明其在泄露/撤销时间点之前已经存在（见 timestampevidence 包）。
//
//   - 下载闸门（Gate，实时）：命中已撤销密钥的签名一律不放行（fail-closed）；
//   - 历史复核（Classify）：依据可信时间证据分为
//     unaffected（不受影响）/ affected（确定受影响）/ insufficient（证据不足）。
package revocation

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"scbverify/internal/cryptokit"
)

// 历史复核三分类。
const (
	// ClassUnaffected：有可信时间证据证明信封在泄露点之前已存在。
	ClassUnaffected = "unaffected"
	// ClassAffected：有可信时间证据证明信封在撤销点之后仍存在/产生，
	// 或其自报/可信时间落在泄露窗口内（确定受影响）。
	ClassAffected = "affected"
	// ClassInsufficient：没有任何可信时间证据，无法判断产物在泄露时是否已存在。
	ClassInsufficient = "insufficient"
)

// Event 是一次密钥撤销/泄露事件。
type Event struct {
	// KeyID 是被撤销的签名公钥指纹（与信任根同一指纹规则）。
	KeyID string `json:"keyId"`
	// CompromisedAt 是有把握的泄露发生时间（RFC3339）。
	// 早于该时间、且有可信时间证据的产物可判为不受影响。
	CompromisedAt string `json:"compromisedAt"`
	// RevokedAt 是密钥被正式撤销/信任根移除的时间；通常 >= CompromisedAt。
	RevokedAt string `json:"revokedAt"`
	// Reason 为人类可读说明。
	Reason string `json:"reason,omitempty"`
	// PublicKeyPEM 可选：用于核对 KeyID 与公钥一致（加载时校验）。
	PublicKeyPEM string `json:"publicKeyPem,omitempty"`
}

// Feed 是撤销事件清单（可来自日志/CRL/CT 式追加源）。
type Feed struct {
	Version int     `json:"version"`
	Name    string  `json:"name"`
	Events  []Event `json:"events"`
}

// parsedEvent 是解析后的内部形态。
type parsedEvent struct {
	Event
	compromisedAt time.Time
	revokedAt     time.Time
}

// List 是已校验、已解析时间的撤销列表。
type List struct {
	Version  int
	Name     string
	events   map[string]parsedEvent
	keyOrder []string
}

// LoadFeed 从 JSON 文件加载撤销清单。
func LoadFeed(path string) (*List, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("revocation: 读取撤销清单 %q: %w", path, err)
	}
	return ParseFeed(b)
}

// ParseFeed 解析并校验撤销清单。
func ParseFeed(b []byte) (*List, error) {
	var f Feed
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("revocation: 撤销清单 JSON 非法: %w", err)
	}
	l := &List{Version: f.Version, Name: f.Name, events: map[string]parsedEvent{}}
	for i, e := range f.Events {
		if e.KeyID == "" || e.CompromisedAt == "" || e.RevokedAt == "" {
			return nil, fmt.Errorf("revocation: events[%d] 缺少 keyId/compromisedAt/revokedAt", i)
		}
		comp, err := time.Parse(time.RFC3339, e.CompromisedAt)
		if err != nil {
			return nil, fmt.Errorf("revocation: events[%d] compromisedAt 非法: %w", i, err)
		}
		rev, err := time.Parse(time.RFC3339, e.RevokedAt)
		if err != nil {
			return nil, fmt.Errorf("revocation: events[%d] revokedAt 非法: %w", i, err)
		}
		if rev.Before(comp) {
			return nil, fmt.Errorf("revocation: events[%d] revokedAt 早于 compromisedAt", i)
		}
		if e.PublicKeyPEM != "" {
			pub, err := cryptokit.ParsePublicPEM([]byte(e.PublicKeyPEM))
			if err != nil {
				return nil, fmt.Errorf("revocation: events[%d] 公钥解析失败: %w", i, err)
			}
			actual, err := cryptokit.KeyIDFromPublic(pub)
			if err != nil {
				return nil, err
			}
			if actual != e.KeyID {
				return nil, fmt.Errorf("revocation: events[%d] keyId 与公钥指纹不一致", i)
			}
		}
		if _, dup := l.events[e.KeyID]; dup {
			return nil, fmt.Errorf("revocation: keyId %s 的撤销事件重复", e.KeyID)
		}
		l.events[e.KeyID] = parsedEvent{Event: e, compromisedAt: comp.UTC(), revokedAt: rev.UTC()}
		l.keyOrder = append(l.keyOrder, e.KeyID)
	}
	return l, nil
}

// IsRevoked 报告某签名密钥是否已撤销（用于实时下载闸门）。
func (l *List) IsRevoked(keyID string) bool {
	if l == nil {
		return false
	}
	_, ok := l.events[keyID]
	return ok
}

// EventFor 返回某密钥的撤销事件（若存在）。
func (l *List) EventFor(keyID string) (Event, bool) {
	if l == nil {
		return Event{}, false
	}
	e, ok := l.events[keyID]
	return e.Event, ok
}

// RevokedAt 返回撤销时间（用于下载闸门的时间留痕），无事件返回零值。
func (l *List) RevokedAt(keyID string) time.Time {
	if l == nil {
		return time.Time{}
	}
	if e, ok := l.events[keyID]; ok {
		return e.revokedAt
	}
	return time.Time{}
}

// GateResult 是实时下载闸门对单份证明签名密钥的撤销结论。
type GateResult struct {
	KeyID     string    `json:"keyId"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revokedAt,omitempty"`
	Reason    string    `json:"reason,omitempty"`
}

// Gate 实时判定：只要签名密钥在撤销清单中就 fail-closed。
// 下载场景不接受“事后补盖”的时间证据来放行。
func (l *List) Gate(keyID string) GateResult {
	if !l.IsRevoked(keyID) {
		return GateResult{KeyID: keyID, Revoked: false}
	}
	e := l.events[keyID]
	return GateResult{KeyID: keyID, Revoked: true, RevokedAt: e.revokedAt,
		Reason: fmt.Sprintf("签名密钥已于 %s 撤销（%s）", e.revokedAt.Format(time.RFC3339), nonEmpty(e.Reason, "密钥泄露"))}
}

// TrustedTimePoint 是一条被采信的“信封存在时间”证据（已通过 TSA 验签）。
type TrustedTimePoint struct {
	Time time.Time
	TSA  string
}

// Classification 是历史影响复核结论。
type Classification struct {
	Class string `json:"class"`
	KeyID string `json:"keyId,omitempty"`
	// TrustedEarliest 是用于判定的最早可信时间（若有）。
	TrustedEarliest *time.Time `json:"-"`
	CompromisedAt   *time.Time `json:"-"`
	RevokedAt       *time.Time `json:"-"`
	// TrustedPointsCount 是参与判定的可信时间证据条数。
	TrustedPointsCount int    `json:"trustedPointsCount"`
	Reason             string `json:"reason"`
}

// Classify 在历史复核场景下，依据可信时间证据对“由 keyID 签名的某份历史
// 信封”做三分类。可信时间点来自已通过 TSA 验签且绑定本信封的证据。
//
// 规则：
//   - 密钥未撤销：不受影响（无泄露事件）；
//   - 已撤销且没有任何可信时间点：insufficient（不能回溯判死，也不能放行）；
//   - 最早可信时间点 < compromisedAt：unaffected（撤销前已存在的产物）；
//   - 最早可信时间点 >= compromisedAt：affected（泄露后仍能见到该信封）。
//
// 注意：必须传入“最早”可信时间点。撤销之后才补盖的 TSA 时间戳若晚于
// compromisedAt，无法把产物洗白；这正是 affected/insufficient 的边界。
func (l *List) Classify(keyID string, trustedPoints []TrustedTimePoint) Classification {
	if l == nil || !l.IsRevoked(keyID) {
		return Classification{Class: ClassUnaffected, KeyID: keyID,
			Reason: "签名密钥没有撤销事件，历史产物不受密钥撤销影响"}
	}
	e := l.events[keyID]
	comp, rev := e.compromisedAt, e.revokedAt

	// 仅保留时间顺序，取最早可信存在时间。
	earliest := time.Time{}
	var pts []TrustedTimePoint
	for _, p := range trustedPoints {
		if p.Time.IsZero() {
			continue
		}
		pts = append(pts, p)
		if earliest.IsZero() || p.Time.Before(earliest) {
			earliest = p.Time
		}
	}
	out := Classification{KeyID: keyID, TrustedPointsCount: len(pts),
		CompromisedAt: &comp, RevokedAt: &rev}

	if earliest.IsZero() {
		out.Class = ClassInsufficient
		out.Reason = "密钥已撤销，但该历史信封没有任何可信时间证据，无法证明其在泄露点之前存在（证据不足，保留待复核）"
		return out
	}
	et := earliest.UTC()
	out.TrustedEarliest = &et
	if earliest.Before(comp) {
		out.Class = ClassUnaffected
		out.Reason = fmt.Sprintf("最早可信时间 %s 早于泄露时间 %s：该产物在密钥泄露前已存在，判定不受影响",
			et.Format(time.RFC3339), comp.Format(time.RFC3339))
		return out
	}
	out.Class = ClassAffected
	out.Reason = fmt.Sprintf("最早可信时间 %s 不早于泄露时间 %s：泄露后仍可产生/见到该信封，判定确定受影响",
		et.Format(time.RFC3339), comp.Format(time.RFC3339))
	return out
}

// RevokedKeyIDs 按稳定顺序返回全部已撤销 KeyID。
func (l *List) RevokedKeyIDs() []string {
	if l == nil {
		return nil
	}
	out := make([]string, len(l.keyOrder))
	copy(out, l.keyOrder)
	return out
}

// KnownRevocationPublicKeys 从撤销清单里带 PEM 的事件提取公钥，便于把
// 已撤销但仍需验签的密钥纳入“已知公钥全集”（验签成功但闸门/信任失败）。
func (l *List) KnownRevocationPublicKeys() (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	if l == nil {
		return out, nil
	}
	for _, id := range l.keyOrder {
		e := l.events[id]
		if e.PublicKeyPEM == "" {
			continue
		}
		pub, err := cryptokit.ParsePublicPEM([]byte(e.PublicKeyPEM))
		if err != nil {
			return nil, err
		}
		out[id] = pub
	}
	return out, nil
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
