package keyring

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// Magic 标识本系统的密文封装格式，Version 为内容格式版本。
const (
	Magic   = "KEN1"
	Version = uint16(1)

	keySize = 32 // AES-256
)

// Header 是密文携带的明文头部，受 AEAD 附加数据完整性保护。
type Header struct {
	Magic     string `json:"magic"`
	Version   uint16 `json:"v"`
	KeyID     string `json:"kid"`
	NonceSize int    `json:"ns"`
	Recipient string `json:"rcp"`
}

// Envelope 表示一个已封装密文的全部组成部分。
type Envelope struct {
	Header Header
	Nonce  []byte
	Cipher []byte
	aad    []byte // 头部在线格式的原始字节，作为 AEAD 的 AAD
}

// 线格式: "KEN1" | uint16be(头部JSON长度) | 头部JSON | nonce | 密文(含GCM标签)
func encodeEnvelope(e *Envelope) []byte {
	hdrJSON, _ := json.Marshal(&e.Header)
	out := make([]byte, 0, len(Magic)+2+len(hdrJSON)+len(e.Nonce)+len(e.Cipher))
	out = append(out, Magic...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(hdrJSON)))
	out = append(out, lenBuf[:]...)
	out = append(out, hdrJSON...)
	out = append(out, e.Nonce...)
	out = append(out, e.Cipher...)
	return out
}

func decodeEnvelope(data []byte) (*Envelope, error) {
	const op = "envelope.decode"
	if len(data) < len(Magic)+2 {
		return nil, wrapErr(op, "", ErrMalformed, "密文短于最小头部长度")
	}
	if string(data[:len(Magic)]) != Magic {
		return nil, wrapErr(op, "", ErrUnsupportedVersion, "魔数不匹配")
	}
	hdrLen := int(binary.BigEndian.Uint16(data[len(Magic) : len(Magic)+2]))
	prefixLen := len(Magic) + 2 + hdrLen
	if hdrLen == 0 || len(data) < prefixLen {
		return nil, wrapErr(op, "", ErrMalformed, "头部长度字段越界")
	}
	var h Header
	if err := json.Unmarshal(data[len(Magic)+2:prefixLen], &h); err != nil {
		return nil, wrapErr(op, "", ErrMalformed, "头部JSON无法解析: "+err.Error())
	}
	if h.Magic != Magic {
		return nil, wrapErr(op, h.KeyID, ErrUnsupportedVersion, "头部魔数不匹配")
	}
	if h.Version != Version {
		return nil, wrapErr(op, h.KeyID, ErrUnsupportedVersion, fmt.Sprintf("不支持的版本 %d", h.Version))
	}
	if h.NonceSize <= 0 {
		return nil, wrapErr(op, h.KeyID, ErrMalformed, "nonce长度非法")
	}
	rest := data[prefixLen:]
	if len(rest) < h.NonceSize+1 {
		return nil, wrapErr(op, h.KeyID, ErrMalformed, "密文主体不完整")
	}
	return &Envelope{
		Header: h,
		Nonce:  append([]byte(nil), rest[:h.NonceSize]...),
		Cipher: append([]byte(nil), rest[h.NonceSize:]...),
		aad:    append([]byte(nil), data[:prefixLen]...),
	}, nil
}

func newAESGCMKey() ([]byte, string, error) {
	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, "", fmt.Errorf("生成密钥失败: %w", err)
	}
	raw := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, "", fmt.Errorf("生成密钥标识失败: %w", err)
	}
	return key, "k-" + hex.EncodeToString(raw), nil
}

func seal(key []byte, e *Envelope, plaintext []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return wrapErr("envelope.seal", e.Header.KeyID, ErrTampered, "密钥材料无法初始化AEAD: "+err.Error())
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return wrapErr("envelope.seal", e.Header.KeyID, ErrTampered, "GCM初始化失败: "+err.Error())
	}
	e.Header.Magic = Magic
	e.Header.Version = Version
	e.Header.NonceSize = g.NonceSize()

	nonce := make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("生成nonce失败: %w", err)
	}

	hdrJSON, err := json.Marshal(&e.Header)
	if err != nil {
		return wrapErr("envelope.seal", e.Header.KeyID, ErrMalformed, "头部序列化失败: "+err.Error())
	}
	aad := make([]byte, 0, len(Magic)+2+len(hdrJSON))
	aad = append(aad, Magic...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(hdrJSON)))
	aad = append(aad, lenBuf[:]...)
	aad = append(aad, hdrJSON...)

	e.Nonce = nonce
	e.aad = aad
	e.Cipher = g.Seal(nil, nonce, plaintext, aad)
	return nil
}

func open(key []byte, e *Envelope, recipient string) ([]byte, error) {
	const op = "envelope.open"
	if subtle.ConstantTimeCompare([]byte(e.Header.Recipient), []byte(recipient)) != 1 {
		return nil, wrapErr(op, e.Header.KeyID, ErrRecipientMismatch,
			fmt.Sprintf("接收方不匹配: 期望=%q 密文=%q", recipient, e.Header.Recipient))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, wrapErr(op, e.Header.KeyID, ErrTampered, "密钥材料无法初始化AEAD: "+err.Error())
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, wrapErr(op, e.Header.KeyID, ErrTampered, "GCM初始化失败: "+err.Error())
	}
	if len(e.Nonce) != g.NonceSize() {
		return nil, wrapErr(op, e.Header.KeyID, ErrMalformed,
			fmt.Sprintf("nonce长度与算法不符: 头=%d 算法=%d", len(e.Nonce), g.NonceSize()))
	}
	pt, err := g.Open(nil, e.Nonce, e.Cipher, e.aad)
	if err != nil {
		return nil, wrapErr(op, e.Header.KeyID, ErrTampered, "AEAD完整性校验失败（密文或头部被篡改）")
	}
	return pt, nil
}
