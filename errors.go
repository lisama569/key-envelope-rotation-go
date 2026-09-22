// Package keyenvelope 提供本地密钥环上的加密封装（envelope）与密钥轮换能力。
//
// 一封密文面向唯一接收方，自带格式版本（内容版本）与密钥标识（KeyID）；
// 密钥环支持多代密钥并存：active 用于新封装，retired 仍可解封历史密文，
// revoked 则拒绝一切使用。所有失败均归类为可区分的 FailureKind，
// 任何解析/认证失败路径都不会返回明文。
package keyenvelope

import "errors"

// FailureKind 是可区分的失败类别，调用方可据此做不同处理。
type FailureKind string

const (
	// KindFormat 密文格式不完整、魔数/版本不支持或字段无法解析。
	KindFormat FailureKind = "format"
	// KindUnknownKey 密文携带的密钥标识在本地密钥环中不存在。
	KindUnknownKey FailureKind = "unknown_key"
	// KindKeyRevoked 密钥已被吊销：禁止用于新封装，也禁止解封既有密文。
	KindKeyRevoked FailureKind = "key_revoked"
	// KindTampered 密文结构完整但密码学认证失败：被篡改、nonce 异常或密钥不匹配。
	KindTampered FailureKind = "tampered"
	// KindRecipientMismatch 密文的接收方与当前密钥环不一致。
	KindRecipientMismatch FailureKind = "recipient_mismatch"
	// KindNoActiveKey 当前没有可用于新封装的有效（active）密钥。
	KindNoActiveKey FailureKind = "no_active_key"
	// KindState 密钥环状态非法或生命周期状态迁移不被允许。
	KindState FailureKind = "invalid_state"
	// KindIO 持久化读写失败。
	KindIO FailureKind = "io"
)

// OpError 携带可区分的失败类别与诊断上下文（不含任何密钥材料）。
type OpError struct {
	Kind      FailureKind
	Op        string // 发生失败的操作，如 "seal" / "open" / "rotate"
	KeyID     string // 相关密钥标识（可能为空）
	Recipient string // 相关接收方（可能为空）
	Detail    string // 人类可读的补充说明
	Err       error  // 被包装的底层错误
}

func (e *OpError) Error() string {
	s := string(e.Kind) + " at " + e.Op
	if e.Recipient != "" {
		s += " recipient=" + e.Recipient
	}
	if e.KeyID != "" {
		s += " key_id=" + e.KeyID
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *OpError) Unwrap() error { return e.Err }

// newErr 构造一个 OpError。
func newErr(kind FailureKind, op, keyID, recipient, detail string, cause error) *OpError {
	return &OpError{Kind: kind, Op: op, KeyID: keyID, Recipient: recipient, Detail: detail, Err: cause}
}

// KindOf 提取错误的 FailureKind；非本包错误返回空串。
func KindOf(err error) FailureKind {
	var oe *OpError
	if errors.As(err, &oe) {
		return oe.Kind
	}
	return ""
}
