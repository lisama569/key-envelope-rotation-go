package keyenvelope

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// KeyState 表示密钥在生命周期中的状态。
type KeyState string

const (
	// StateActive 当前有效密钥：可用于新封装，也可解封。
	StateActive KeyState = "active"
	// StateRetired 已轮换退役：不可用于新封装，但保留期间仍可解封历史密文。
	StateRetired KeyState = "retired"
	// StateRevoked 已吊销（疑似失陷）：新封装与解封一律拒绝。
	StateRevoked KeyState = "revoked"
)

// keyEntry 是密钥环节点（含密钥材料，仅存于内存与 0600 持久化文件中）。
type keyEntry struct {
	ID        string
	State     KeyState
	Raw       []byte
	CreatedAt time.Time
	RotatedAt time.Time // 非零表示该密钥何时被轮换下场
	RevokedAt time.Time // 非零表示何时被吊销
}

// KeyInfo 是对外诊断/导出视图，刻意不包含密钥材料。
type KeyInfo struct {
	ID        string
	State     KeyState
	CreatedAt time.Time
	RotatedAt time.Time
	RevokedAt time.Time
}

// Keyring 是面向单个接收方的多代本地密钥环，并发安全。
//
// 不变量（始终在 mu 写锁内维护）：
//   - 每个 KeyID 唯一映射到一个 keyEntry；
//   - activeID 为空，或指向一个状态恰为 StateActive 的 entry；
//   - 任意时刻至多一个 active 密钥；retired/revoked 可有多代并存。
type Keyring struct {
	mu        sync.RWMutex
	recipient string
	keys      map[string]*keyEntry
	activeID  string
	path      string // 关联的持久化路径，为空表示未绑定文件
}

// NewKeyring 创建一个空密钥环（尚无密钥，需 Rotate 后才能封装）。
func NewKeyring(recipient string) *Keyring {
	return &Keyring{
		recipient: recipient,
		keys:      make(map[string]*keyEntry),
	}
}

// newKeyID 生成密钥标识：key- 前缀 + 16 个十六进制随机字符。
func newKeyID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", newErr(KindIO, "keyid", "", "", "crypto/rand failed", err)
	}
	return "key-" + hex.EncodeToString(b[:]), nil
}

// Seal 用当前 active 密钥为本密钥环的接收方封装一封密文。
// 密文携带格式版本与所用密钥标识；每次调用生成独立随机 nonce。
func (k *Keyring) Seal(plaintext []byte) (*Envelope, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.activeID == "" {
		return nil, newErr(KindNoActiveKey, "seal", "", k.recipient,
			"no active key; rotate the keyring before sealing", nil)
	}
	entry := k.keys[k.activeID]
	// 不变量保证 entry 非 nil 且为 active，这里防御性复核。
	if entry == nil || entry.State != StateActive {
		return nil, newErr(KindKeyRevoked, "seal", k.activeID, k.recipient,
			"active slot does not point at an active key (revoked?)", nil)
	}

	ev := &Envelope{
		FormatVersion: currentFormatVer,
		Recipient:     k.recipient,
		KeyID:         entry.ID,
		Nonce:         make([]byte, gcmStandardNonceLen),
	}
	// gcmSeal 向 ev.Nonce 填充随机数并写出密文；不修改密钥环任何共享状态，
	// 因此在 RLock 下并发执行也是安全的。
	if err := gcmSeal(entry.Raw, ev, plaintext); err != nil {
		return nil, err
	}
	return ev, nil
}

// SealBytes 是 Seal + MarshalBinary 的便捷组合，直接返回可存储/传输的字节。
func (k *Keyring) SealBytes(plaintext []byte) ([]byte, error) {
	ev, err := k.Seal(plaintext)
	if err != nil {
		return nil, err
	}
	return ev.MarshalBinary()
}

// Open 解封已解析的信封。
//
// 判定顺序（错误类别互斥、可区分）：
//  1. 接收方不一致 -> KindRecipientMismatch
//  2. KeyID 在环中不存在 -> KindUnknownKey
//  3. 密钥已吊销 -> KindKeyRevoked（既有密文也拒绝，行为确定）
//  4. GCM 认证失败 -> KindTampered（篡改 / AAD 头部改动 / nonce 异常）
//
// 任何失败路径都不返回明文。
func (k *Keyring) Open(ev *Envelope) ([]byte, error) {
	if ev == nil {
		return nil, newErr(KindFormat, "open", "", "", "nil envelope", nil)
	}
	k.mu.RLock()
	defer k.mu.RUnlock()

	if ev.Recipient != k.recipient {
		return nil, newErr(KindRecipientMismatch, "open", ev.KeyID, ev.Recipient,
			"envelope recipient does not match keyring recipient", nil)
	}
	entry, ok := k.keys[ev.KeyID]
	if !ok {
		return nil, newErr(KindUnknownKey, "open", ev.KeyID, ev.Recipient,
			"key id not found in local keyring", nil)
	}
	switch entry.State {
	case StateRevoked:
		return nil, newErr(KindKeyRevoked, "open", entry.ID, k.recipient,
			"key has been revoked; both new seals and existing ciphertext are refused", nil)
	case StateActive, StateRetired:
		// active 与 retired（保留期内）都允许解封历史密文。
	default:
		return nil, newErr(KindState, "open", entry.ID, k.recipient,
			"key in unsupported lifecycle state", nil)
	}
	return gcmOpen(entry.Raw, ev)
}

// OpenBytes 先做纯结构解析（KindFormat），再走 Open 的完整判定链。
func (k *Keyring) OpenBytes(b []byte) ([]byte, error) {
	ev, err := ParseEnvelope(b)
	if err != nil {
		return nil, err
	}
	return k.Open(ev)
}

// Rotate 生成新一代 active 密钥；旧 active 密钥转为 retired（仍可解封历史密文）。
// 返回新密钥 ID。若密钥环绑定了持久化文件，会同步落盘。
func (k *Keyring) Rotate() (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	raw, err := newAES256Key()
	if err != nil {
		return "", err
	}
	id, err := newKeyID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	if k.activeID != "" {
		if old := k.keys[k.activeID]; old != nil && old.State == StateActive {
			old.State = StateRetired
			old.RotatedAt = now
		}
	}
	entry := &keyEntry{ID: id, State: StateActive, Raw: raw, CreatedAt: now}
	k.keys[id] = entry
	k.activeID = id

	if err := k.persistIfBoundLocked(); err != nil {
		return "", err
	}
	return id, nil
}

// Revoke 将指定密钥标记为吊销。
// 此后该密钥既不能用于新封装，也不能解封其既有密文（确定地返回 KindKeyRevoked）。
// 若被吊销的是当前 active 密钥，active 槽清空，需重新 Rotate 才能封装。
func (k *Keyring) Revoke(keyID string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	entry, ok := k.keys[keyID]
	if !ok {
		return newErr(KindUnknownKey, "revoke", keyID, k.recipient,
			"cannot revoke: key id not found in keyring", nil)
	}
	if entry.State == StateRevoked {
		return newErr(KindState, "revoke", keyID, k.recipient, "key already revoked", nil)
	}
	entry.State = StateRevoked
	entry.RevokedAt = time.Now().UTC()
	if k.activeID == keyID {
		k.activeID = ""
	}
	return k.persistIfBoundLocked()
}

// Retire 手动将指定密钥退役。只有 active 密钥可退役；
// 退役后 active 槽清空，必须先 Rotate 才能再次 Seal。
// retired 密钥在被显式删除/吊销前，仍可解封其历史密文。
func (k *Keyring) Retire(keyID string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	entry, ok := k.keys[keyID]
	if !ok {
		return newErr(KindUnknownKey, "retire", keyID, k.recipient,
			"cannot retire: key id not found in keyring", nil)
	}
	if entry.State != StateActive {
		return newErr(KindState, "retire", keyID, k.recipient,
			"only an active key can be retired", nil)
	}
	entry.State = StateRetired
	entry.RotatedAt = time.Now().UTC()
	if k.activeID == keyID {
		k.activeID = ""
	}
	return k.persistIfBoundLocked()
}

// ActiveKeyID 返回当前 active 密钥 ID（无则空串）。
func (k *Keyring) ActiveKeyID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.activeID
}

// Recipient 返回密钥环所属接收方标识。
func (k *Keyring) Recipient() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.recipient
}

// Snapshot 导出不含密钥材料的诊断视图（ID、状态、时间戳），按 ID 排序。
func (k *Keyring) Snapshot() []KeyInfo {
	k.mu.RLock()
	defer k.mu.RUnlock()

	out := make([]KeyInfo, 0, len(k.keys))
	for _, e := range k.keys {
		out = append(out, KeyInfo{
			ID:        e.ID,
			State:     e.State,
			CreatedAt: e.CreatedAt,
			RotatedAt: e.RotatedAt,
			RevokedAt: e.RevokedAt,
		})
	}
	sortKeyInfos(out)
	return out
}

// Save 将密钥环原子写入持久化文件（0600 权限），并把该文件绑定到密钥环，
// 此后 Rotate/Revoke/Retire 会自动同步落盘。
func (k *Keyring) Save(path string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if err := k.persistLocked(path); err != nil {
		return err
	}
	k.path = path
	return nil
}

// persistIfBoundLocked 在密钥环已绑定持久化文件时落盘；调用方必须持有写锁。
func (k *Keyring) persistIfBoundLocked() error {
	if k.path == "" {
		return nil
	}
	return k.persistLocked(k.path)
}
