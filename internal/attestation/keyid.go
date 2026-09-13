package attestation

import (
	"crypto/ed25519"

	"scbverify/internal/cryptokit"
)

// publicKeyID 复用 cryptokit 的密钥指纹规则（SHA-256 over DER SPKI）。
func publicKeyID(pub ed25519.PublicKey) (string, error) {
	return cryptokit.KeyIDFromPublic(pub)
}
