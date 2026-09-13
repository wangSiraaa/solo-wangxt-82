package attestation

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"scbverify/internal/cryptokit"
)

func validStatement() *Statement {
	return &Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []Subject{{
			Name:   "artifact.bin",
			Digest: map[string]string{"sha256": "00"},
		}},
		PredicateType: SLSAProvenanceType,
		Predicate:     json.RawMessage(`{"runDetails":{"builder":{"id":"b"}}}`),
	}
}

func known(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := cryptokit.GenerateEd25519(nil)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := cryptokit.KeyIDFromPublic(pub)
	return pub, priv, map[string]ed25519.PublicKey{id: pub}
}

// TestDSSESignatureRoundTrip：正确签名通过；改签名或改载荷都失败。
func TestDSSESignatureRoundTrip(t *testing.T) {
	_, priv, keys := known(t)
	env, err := SignStatement(priv, validStatement())
	if err != nil {
		t.Fatal(err)
	}
	check, body, st := VerifyEnvelope(env, keys)
	if !check.Valid || st == nil || len(body) == 0 {
		t.Fatalf("正确签名应通过: %+v", check)
	}
	if check.AcceptedKeyID == "" {
		t.Fatal("应报告实际验签公钥指纹")
	}

	// 篡改签名：失败
	tamperedSig := *env
	sig, _ := base64.StdEncoding.DecodeString(tamperedSig.Signatures[0].Sig)
	sig[0] ^= 0xFF
	tamperedSig.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
	if c, _, _ := VerifyEnvelope(&tamperedSig, keys); c.Valid {
		t.Fatal("篡改签名必须失败")
	}

	// 篡改载荷但保留旧签名：失败（DSSE PAE 保护载荷）
	tamperedPayload := *env
	tamperedPayload.Payload = base64.StdEncoding.EncodeToString([]byte(`{"_type":"evil"}`))
	if c, _, _ := VerifyEnvelope(&tamperedPayload, keys); c.Valid {
		t.Fatal("载荷被替换后旧签名必须失败")
	}
}

// TestUnknownKeyCannotVerify：未知公钥集合 => 签名无法被核验。
func TestUnknownKeyCannotVerify(t *testing.T) {
	_, priv, _ := known(t)
	otherPub, _, _ := cryptokit.GenerateEd25519(nil)
	otherID, _ := cryptokit.KeyIDFromPublic(otherPub)
	env, err := SignStatement(priv, validStatement())
	if err != nil {
		t.Fatal(err)
	}
	// 伪造 keyid 指向“另一把已知公钥”也不能蒙混：密码学验签只认实际公钥。
	env.Signatures[0].KeyID = otherID
	if c, _, _ := VerifyEnvelope(env, map[string]ed25519.PublicKey{otherID: otherPub}); c.Valid {
		t.Fatal("伪造 keyid 不得让签名通过")
	}
}

func TestParseStatementValidation(t *testing.T) {
	if _, err := ParseStatement([]byte(`{"_type":"other"}`)); err == nil {
		t.Fatal("非 Statement v1 必须报错")
	}
	if _, err := ParseStatement([]byte(`{"_type":"https://in-toto.io/Statement/v1"}`)); err == nil {
		t.Fatal("缺少 subject/predicateType 必须报错")
	}
}
