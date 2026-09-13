package timestampevidence

import (
	"crypto/ed25519"
	"testing"
	"time"

	"scbverify/internal/cryptokit"
)

func tsaKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := cryptokit.GenerateEd25519(nil)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := cryptokit.KeyIDFromPublic(pub)
	return pub, priv, map[string]ed25519.PublicKey{id: pub}
}

func TestTimeEvidenceRoundTripAndReject(t *testing.T) {
	pub, priv, keys := tsaKeys(t)
	id, _ := cryptokit.KeyIDFromPublic(pub)
	at := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	ev, err := Sign(priv, "envsha", at)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(ev, "envsha", keys, func(string) string { return "demo-tsa" })
	if err != nil || !v.Valid || !v.Time.Equal(at) || v.TsaKeyID != id {
		t.Fatalf("合法时间证据应通过: %+v err=%v", v, err)
	}
	if v.TSAName != "demo-tsa" {
		t.Fatal("TSA 名称应可解析")
	}

	// 绑定到另一份信封：拒绝。
	if v, _ := Verify(ev, "other-env", keys, nil); v.Valid {
		t.Fatal("绑定信封不一致必须拒绝")
	}
	// 未授权 TSA：拒绝。
	if v, _ := Verify(ev, "envsha", map[string]ed25519.PublicKey{}, nil); v.Valid {
		t.Fatal("未授权 TSA 必须拒绝")
	}
	// 篡改时间后用旧签名：拒绝。
	tampered := *ev
	tampered.Timestamp = "2026-09-01T00:00:00Z"
	if v, _ := Verify(&tampered, "envsha", keys, nil); v.Valid {
		t.Fatal("时间被改而签名未更新必须拒绝")
	}
	// 自报 tsaKeyId 伪造为其他值但签名真实：拒绝。
	forgedID := *ev
	forgedID.TsaKeyID = "deadbeef"
	if v, _ := Verify(&forgedID, "envsha", keys, nil); v.Valid {
		t.Fatal("自报 tsaKeyId 与实际公钥不符必须拒绝")
	}
}
