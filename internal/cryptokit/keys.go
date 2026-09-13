// Package cryptokit 封装演示所用的非对称密码原语（Ed25519 密钥对生成、
// PEM 编解码、密钥指纹）。
//
// 演示使用本地测试密钥，不依赖任何商业证书服务。Ed25519 签名确定性，
// 因而可以产出“可重复的验签向量”（相同私钥与相同载荷 => 相同签名）。
package cryptokit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// KeyIDAlgorithm 是本服务计算密钥标识所用的算法标签。
// KeyID = sha256(DER 编码的 SPKI 公钥) 的十六进制值，长度 64。
// 我们**不**依赖信封里自报的 keyid 字符串完成信任判定，而是按实际公钥
// 自行计算指纹，避免攻击者把恶意公钥的 keyid 改成受信任值。
const KeyIDAlgorithm = "sha256-spki"

// ErrNotPEM 表示输入不是合法的 PEM 数据块。
var ErrNotPEM = errors.New("cryptokit: not a valid PEM block")

// GenerateEd25519 生成一把全新的 Ed25519 密钥。
// seed 为 nil 时使用 crypto/rand；传入固定 32 字节 seed 可在演示中
// 确定性地重建同一把密钥。
func GenerateEd25519(seed []byte) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if len(seed) == 0 {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return pub, priv, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("cryptokit: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv, nil
}

// KeyIDFromPublic 按 DER(SPKI) 公钥的 SHA-256 指纹计算稳定的密钥标识。
func KeyIDFromPublic(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("cryptokit: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// MarshalPublicPEM 把公钥编码成 PKIX PEM（"PUBLIC KEY"）。
func MarshalPublicPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("cryptokit: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// MarshalPrivatePEM 把私钥编码成 PKCS#8 PEM（"PRIVATE KEY"）。
func MarshalPrivatePEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("cryptokit: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePublicPEM 解析 PKIX PEM 公钥，仅接受 Ed25519。
func ParsePublicPEM(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrNotPEM
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cryptokit: parse SPKI public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cryptokit: unsupported public key type %T (demo supports ed25519 only)", pub)
	}
	return edPub, nil
}

// ParsePrivatePEM 解析 PKCS#8 PEM 私钥，仅接受 Ed25519。
func ParsePrivatePEM(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrNotPEM
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cryptokit: parse PKCS#8 private key: %w", err)
	}
	edPriv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cryptokit: unsupported private key type %T (demo supports ed25519 only)", key)
	}
	return edPriv, nil
}

// LoadPublicPEMFile 从文件读取 PEM 公钥。
func LoadPublicPEMFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cryptokit: read public key %q: %w", path, err)
	}
	return ParsePublicPEM(data)
}

// LoadPrivatePEMFile 从文件读取 PEM 私钥。
func LoadPrivatePEMFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cryptokit: read private key %q: %w", path, err)
	}
	return ParsePrivatePEM(data)
}
