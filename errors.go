package keyring

import "fmt"

// Reason 是密钥环操作失败的可归类原因码，调用方可据此区分失败类型。
type Reason string

const (
	// ReasonMalformed 密文格式不完整或无法解析。
	ReasonMalformed Reason = "malformed"
	// ReasonUnsupportedVersion 密文魔数/格式版本不受支持。
	ReasonUnsupportedVersion Reason = "unsupported_version"
	// ReasonUnknownKey 密文携带的密钥标识在环中不存在。
	ReasonUnknownKey Reason = "unknown_key"
	// ReasonRevoked 密钥已被吊销：禁止新封装，也拒绝解封既有密文。
	ReasonRevoked Reason = "revoked"
	// ReasonKeyRetired 密钥世代已被显式清理：其历史密文一律拒绝，且不会尝试任何其他密钥。
	ReasonKeyRetired Reason = "key_retired"
	// ReasonCurrentKeyProtected 当前正在生效的密钥世代受保护，不允许被清理。
	ReasonCurrentKeyProtected Reason = "current_key_protected"
	// ReasonTampered 密文（头部或主体）被篡改，AEAD 校验失败。
	ReasonTampered Reason = "tampered"
	// ReasonNoCurrentKey 密钥环中没有当前有效密钥（空环）。
	ReasonNoCurrentKey Reason = "no_current_key"
	// ReasonRecipientMismatch 解封接收方与封装备注的接收方不一致。
	ReasonRecipientMismatch Reason = "recipient_mismatch"
)

// Error 携带可区分的失败原因、涉及的密钥标识与上下文说明。
type Error struct {
	Reason Reason
	Op     string
	KeyID  string
	Detail string
	Err    error
}

func (e *Error) Error() string {
	msg := string(e.Reason)
	if e.Op != "" {
		msg = e.Op + ": " + msg
	}
	if e.KeyID != "" {
		msg += fmt.Sprintf(" (key=%s)", e.KeyID)
	}
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// Is 按原因码匹配，便于 errors.Is(err, ErrKeyRevoked) 之类的判定。
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return t.Reason == e.Reason
}

// 哨兵错误，仅用于 errors.Is 的原因归类。
var (
	ErrMalformed           = &Error{Reason: ReasonMalformed}
	ErrUnsupportedVersion  = &Error{Reason: ReasonUnsupportedVersion}
	ErrUnknownKey          = &Error{Reason: ReasonUnknownKey}
	ErrKeyRevoked          = &Error{Reason: ReasonRevoked}
	ErrKeyRetired          = &Error{Reason: ReasonKeyRetired}
	ErrCurrentKeyProtected = &Error{Reason: ReasonCurrentKeyProtected}
	ErrTampered            = &Error{Reason: ReasonTampered}
	ErrNoCurrentKey        = &Error{Reason: ReasonNoCurrentKey}
	ErrRecipientMismatch   = &Error{Reason: ReasonRecipientMismatch}
)

func wrapErr(op string, keyID string, cause *Error, detail string) *Error {
	return &Error{
		Reason: cause.Reason,
		Op:     op,
		KeyID:  keyID,
		Detail: detail,
		Err:    cause,
	}
}
