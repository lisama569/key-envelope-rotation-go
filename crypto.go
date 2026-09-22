package keyenvelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
)

const (
	aes256KeyLen        = 32
	gcmStandardNonceLen = 12
	gcmTagLen           = 16
)

// newAES256Key 生成一把新的随机 AES-256 密钥。
func newAES256Key() ([]byte, error) {
	k := make([]byte, aes256KeyLen)
	if _, err := rand.Read(k); err != nil {
		return nil, newErr(KindIO, "crypto.keygen", "", "", "crypto/rand failed", err)
	}
	return k, nil
}

// newGCM 以给定原始密钥构造 AES-GCM。
func newGCM(rawKey []byte) (cipher.AEAD, error) {
	if len(rawKey) != aes256KeyLen {
		return nil, newErr(KindState, "crypto.gcm", "", "",
			fmt.Sprintf("internal: key length must be %d, got %d", aes256KeyLen, len(rawKey)), nil)
	}
	block, err := aes.NewCipher(rawKey)
	if err != nil {
		// 仅在密钥长度非法时发生，内部不变量被破坏才会走到这里。
		return nil, newErr(KindState, "crypto.gcm", "", "", "aes.NewCipher failed", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, newErr(KindState, "crypto.gcm", "", "", "cipher.NewGCM failed", err)
	}
	return aead, nil
}

// buildAAD 把信封头部（格式版本、接收方、密钥标识）拼接成 AAD。
// 这些字段因此被认证标签覆盖：篡改任一字段都会让 gcmOpen 认证失败。
//
//	version(1) | recipientLen(1) | recipient | keyIDLen(1) | keyID
func buildAAD(ev *Envelope) []byte {
	aad := make([]byte, 0, 3+len(ev.Recipient)+len(ev.KeyID))
	aad = append(aad, ev.FormatVersion)
	aad = append(aad, byte(len(ev.Recipient)))
	aad = append(aad, ev.Recipient...)
	aad = append(aad, byte(len(ev.KeyID)))
	aad = append(aad, ev.KeyID...)
	return aad
}

// gcmSeal 用给定密钥对 plaintext 加密。
// nonce 在本地用 crypto/rand 全新生成并写入信封，保证：
//   - 每次封装的 nonce 独立，绝不复用；
//   - 并发调用各自持有独立信封与独立 nonce；
//   - rand 失败时显式报错而不是退化为确定性输出。
func gcmSeal(rawKey []byte, ev *Envelope, plaintext []byte) error {
	const op = "crypto.seal"
	aead, err := newGCM(rawKey)
	if err != nil {
		return err
	}
	if len(ev.Nonce) != gcmStandardNonceLen {
		return newErr(KindState, op, ev.KeyID, ev.Recipient, "envelope missing fresh nonce buffer", nil)
	}
	if _, err := rand.Read(ev.Nonce); err != nil {
		return newErr(KindIO, op, ev.KeyID, ev.Recipient, "nonce generation failed", err)
	}
	// 防御性检查：全零 nonce 在实践中概率可忽略，但显式拒绝更安全。
	var zeroNonce [gcmStandardNonceLen]byte
	if subtle.ConstantTimeCompare(ev.Nonce, zeroNonce[:]) == 1 {
		return newErr(KindIO, op, ev.KeyID, ev.Recipient, "rng returned all-zero nonce", nil)
	}
	ev.Ciphertext = aead.Seal(ev.Ciphertext[:0], ev.Nonce, plaintext, buildAAD(ev))
	return nil
}

// gcmOpen 用给定密钥对信封解密并认证。
// 认证失败返回 KindTampered：调用方拿不到任何明文（输出不返回）。
func gcmOpen(rawKey []byte, ev *Envelope) ([]byte, error) {
	const op = "crypto.open"
	aead, err := newGCM(rawKey)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, ev.Nonce, ev.Ciphertext, buildAAD(ev))
	if err != nil {
		return nil, newErr(KindTampered, op, ev.KeyID, ev.Recipient,
			"AES-GCM authentication failed: ciphertext tampered or header altered", err)
	}
	return pt, nil
}
