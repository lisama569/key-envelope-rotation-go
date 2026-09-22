package keyenvelope

import (
	"fmt"
	"unicode/utf8"
)

// 密文磁盘/传输格式（v1），全部字段按如下顺序紧密排列：
//
//	offset  size         field
//	0       4            magic   = "KEN1"
//	4       1            format version（内容版本），当前为 1
//	5       1            recipientLen
//	6       recipientLen recipient（UTF-8 文本）
//	...     1            keyIDLen
//	...     keyIDLen     keyID（生成该密文的密钥标识）
//	...     1            nonceLen
//	...     nonceLen     nonce
//	...     remainder    ciphertext（AES-GCM 输出，密文末尾附 16 字节认证标签）
//
// 该布局自描述且可顺序解析；所有长度前缀为 1 字节，故单字段上限 255。
// recipient / formatVersion / keyID 在 GCM 中作为附加认证数据（AAD），
// 因此即使结构解析通过，任何对头部的篡改也会在解密时被认证标签拒绝。
const (
	envelopeMagic    = "KEN1"
	currentFormatVer = 1
	maxFieldLen      = 255
	headerSize       = 5 // magic(4) + version(1)
)

// Envelope 是一封密文的结构化表示。MarshalBinary 后即为持久化/传输字节。
type Envelope struct {
	FormatVersion uint8
	Recipient     string
	KeyID         string
	Nonce         []byte
	Ciphertext    []byte // AES-GCM 输出，密文末尾附带 16 字节认证标签
}

// MarshalBinary 将信封序列化为自描述的二进制格式。
// 该函数只负责结构序列化，不执行任何加密。
func (e *Envelope) MarshalBinary() ([]byte, error) {
	const op = "envelope.marshal"
	if e == nil {
		return nil, newErr(KindFormat, op, "", "", "nil envelope", nil)
	}
	if e.FormatVersion != currentFormatVer {
		return nil, newErr(KindFormat, op, e.KeyID, e.Recipient,
			fmt.Sprintf("unsupported format version %d", e.FormatVersion), nil)
	}
	if len(e.Recipient) > maxFieldLen || len(e.KeyID) > maxFieldLen || len(e.Nonce) > maxFieldLen {
		return nil, newErr(KindFormat, op, e.KeyID, e.Recipient, "field longer than 255 bytes", nil)
	}
	if len(e.Recipient) == 0 {
		return nil, newErr(KindFormat, op, e.KeyID, e.Recipient, "empty recipient", nil)
	}
	if len(e.KeyID) == 0 {
		return nil, newErr(KindFormat, op, e.KeyID, e.Recipient, "empty key id", nil)
	}
	if len(e.Nonce) != gcmStandardNonceLen {
		return nil, newErr(KindFormat, op, e.KeyID, e.Recipient,
			fmt.Sprintf("nonce length must be %d, got %d", gcmStandardNonceLen, len(e.Nonce)), nil)
	}
	if len(e.Ciphertext) < gcmTagLen {
		return nil, newErr(KindFormat, op, e.KeyID, e.Recipient, "ciphertext too short to carry tag", nil)
	}

	out := make([]byte, 0, headerSize+3+len(e.Recipient)+len(e.KeyID)+len(e.Nonce)+len(e.Ciphertext))
	out = append(out, envelopeMagic...)
	out = append(out, e.FormatVersion)
	out = append(out, byte(len(e.Recipient)))
	out = append(out, e.Recipient...)
	out = append(out, byte(len(e.KeyID)))
	out = append(out, e.KeyID...)
	out = append(out, byte(len(e.Nonce)))
	out = append(out, e.Nonce...)
	out = append(out, e.Ciphertext...)
	return out, nil
}

// readField 读取一个 1 字节长度前缀的字段，返回字段内容（共享底层数组的切片）与新偏移。
func readField(b []byte, off int, what, keyID, recipient string) ([]byte, int, error) {
	if off >= len(b) {
		return nil, off, newErr(KindFormat, "envelope.parse", keyID, recipient,
			"truncated: missing length byte for "+what, nil)
	}
	n := int(b[off])
	off++
	if off+n > len(b) {
		return nil, off, newErr(KindFormat, "envelope.parse", keyID, recipient,
			"truncated: field "+what+" exceeds remaining bytes", nil)
	}
	return b[off : off+n : off+n], off + n, nil
}

// ParseEnvelope 只做结构解析，不做任何密码学校验。
// 格式不完整返回 KindFormat；它永远不会“解出”任何明文。
func ParseEnvelope(b []byte) (*Envelope, error) {
	const op = "envelope.parse"
	if len(b) < headerSize {
		return nil, newErr(KindFormat, op, "", "", "input shorter than header", nil)
	}
	if string(b[0:4]) != envelopeMagic {
		return nil, newErr(KindFormat, op, "", "", "bad magic: not a KEN1 envelope", nil)
	}
	ver := b[4]
	if ver != currentFormatVer {
		return nil, newErr(KindFormat, op, "", "",
			fmt.Sprintf("unsupported format version %d", ver), nil)
	}

	off := headerSize
	recipientRaw, off, err := readField(b, off, "recipient", "", "")
	if err != nil {
		return nil, err
	}
	keyIDRaw, off, err := readField(b, off, "key_id", string(recipientRaw), string(recipientRaw))
	if err != nil {
		return nil, err
	}
	recipient := string(recipientRaw)
	keyID := string(keyIDRaw)
	nonce, off, err := readField(b, off, "nonce", keyID, recipient)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcmStandardNonceLen {
		return nil, newErr(KindFormat, op, keyID, recipient,
			fmt.Sprintf("nonce length must be %d, got %d", gcmStandardNonceLen, len(nonce)), nil)
	}
	ct := b[off:]
	if len(ct) < gcmTagLen {
		return nil, newErr(KindFormat, op, keyID, recipient,
			"ciphertext too short to carry tag", nil)
	}
	if !utf8.Valid(recipientRaw) || !utf8.Valid(keyIDRaw) {
		return nil, newErr(KindFormat, op, keyID, recipient,
			"recipient/key id is not valid UTF-8", nil)
	}
	return &Envelope{
		FormatVersion: ver,
		Recipient:     recipient,
		KeyID:         keyID,
		Nonce:         append([]byte(nil), nonce...),
		Ciphertext:    append([]byte(nil), ct...),
	}, nil
}
