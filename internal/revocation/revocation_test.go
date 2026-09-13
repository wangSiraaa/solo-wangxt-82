package revocation

import (
	"testing"
	"time"
)

const keyA = "key-a"

func feedFor(t *testing.T) *List {
	t.Helper()
	feed, err := ParseFeed([]byte(`{
      "name":"t","version":1,
      "events":[{
        "keyId":"` + keyA + `",
        "compromisedAt":"2026-03-05T00:00:00Z",
        "revokedAt":"2026-04-01T00:00:00Z",
        "reason":"leak"
      }]}`))
	if err != nil {
		t.Fatal(err)
	}
	return feed
}

func TestGateFailClosed(t *testing.T) {
	l := feedFor(t)
	if g := l.Gate("other"); g.Revoked {
		t.Fatal("未撤销密钥不应命中闸门")
	}
	g := l.Gate(keyA)
	if !g.Revoked {
		t.Fatal("已撤销密钥实时闸门必须 fail-closed")
	}
	if g.RevokedAt.IsZero() {
		t.Fatal("闸门结果应带撤销时间")
	}
}

func TestClassificationMatrix(t *testing.T) {
	l := feedFor(t)
	comp, _ := time.Parse(time.RFC3339, "2026-03-05T00:00:00Z")

	// 未撤销密钥：unaffected。
	if c := l.Classify("other", nil); c.Class != ClassUnaffected {
		t.Fatalf("未撤销密钥应 unaffected，实际 %s", c.Class)
	}
	// 已撤销但无任何可信时间点：insufficient。
	if c := l.Classify(keyA, nil); c.Class != ClassInsufficient {
		t.Fatalf("无时间证据应 insufficient，实际 %s", c.Class)
	}
	// 撤销前存在：unaffected。
	before := []TrustedTimePoint{{Time: comp.Add(-time.Hour), TSA: "tsa"}}
	if c := l.Classify(keyA, before); c.Class != ClassUnaffected {
		t.Fatalf("撤销前可信时间应 unaffected，实际 %s (%s)", c.Class, c.Reason)
	}
	// 撤销后补盖：affected（不能洗白）。
	after := []TrustedTimePoint{{Time: comp.Add(time.Hour), TSA: "tsa"}}
	if c := l.Classify(keyA, after); c.Class != ClassAffected {
		t.Fatalf("撤销后补盖应 affected，实际 %s", c.Class)
	}
	// 既有撤销前也有撤销后证据：取最早可信时间 => unaffected。
	both := append(before, after...)
	if c := l.Classify(keyA, both); c.Class != ClassUnaffected {
		t.Fatalf("存在撤销前最早证据时应 unaffected，实际 %s", c.Class)
	}
}

func TestRejectInvalidFeed(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"events":[{"keyId":"k","revokedAt":"2026-04-01T00:00:00Z"}]}`), // 缺 compromisedAt
		[]byte(`{"events":[{"keyId":"k","compromisedAt":"2026-04-02T00:00:00Z","revokedAt":"2026-04-01T00:00:00Z"}]}`),
	}
	for _, b := range cases {
		if _, err := ParseFeed(b); err == nil {
			t.Fatalf("非法撤销清单必须报错: %s", b)
		}
	}
}
