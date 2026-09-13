package trust

import (
	"strings"
	"testing"

	"scbverify/internal/cryptokit"
)

func TestTrustRootRejectsKeyIDMismatch(t *testing.T) {
	pub, _, err := cryptokit.GenerateEd25519(nil)
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := cryptokit.MarshalPublicPEM(pub)
	goodID, _ := cryptokit.KeyIDFromPublic(pub)

	// 自报 keyId 与公钥实际指纹不一致：必须拒绝该信任锚。
	bad := `{"version":1,"name":"t","trustedKeys":[{"keyId":"` +
		strings.Repeat("ab", 32) + `","issuer":"x","publicKeyPem":` +
		quote(string(pem)) + `}]}`
	if _, err := ParseRoot([]byte(bad)); err == nil {
		t.Fatal("自报 keyId 与公钥指纹不一致时必须拒绝")
	}

	good := `{"version":1,"name":"t","trustedKeys":[{"keyId":"` + goodID +
		`","issuer":"builder-1","publicKeyPem":` + quote(string(pem)) + `}]}`
	r, err := ParseRoot([]byte(good))
	if err != nil {
		t.Fatalf("合法信任根应加载成功: %v", err)
	}

	// 信任判定：验签公钥在根中、且 builder.id 与绑定身份一致。
	if res := r.Evaluate(goodID, "builder-1"); !res.Trusted {
		t.Fatalf("相同身份应可信: %s", res.Reason)
	}
	if res := r.Evaluate(goodID, "builder-impostor"); res.Trusted {
		t.Fatal("builder.id 与绑定身份不一致时不可信")
	}
	if res := r.Evaluate(strings.Repeat("cd", 32), "builder-1"); res.Trusted {
		t.Fatal("不在信任根的公钥不可信")
	}
	if res := r.Evaluate("", "builder-1"); res.Trusted {
		t.Fatal("没有验签公钥时不可信")
	}
}

func quote(s string) string {
	b := make([]byte, 0, len(s)+2)
	b = append(b, '"')
	for _, c := range s {
		if c == '\n' {
			b = append(b, '\\', 'n')
			continue
		}
		b = append(b, byte(c))
	}
	b = append(b, '"')
	return string(b)
}
