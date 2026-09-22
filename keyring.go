package keyring

import (
	"sort"
	"sync"
	"time"
)

// KeyState 表示密钥的生命周期状态。
type KeyState string

const (
	// StateActive 密钥可用于新封装，也可解封其历史密文。
	StateActive KeyState = "active"
	// StateRevoked 密钥已吊销：禁止新封装，拒绝解封其历史密文。
	StateRevoked KeyState = "revoked"
)

// KeyEntry 是单个密钥的内部条目（含密钥材料，禁止导出）。
type KeyEntry struct {
	ID        string
	Version   int
	State     KeyState
	Key       []byte
	CreatedAt int64
	RevokedAt int64
}

// KeyInfo 是可供外部诊断/导出的元数据，绝不含密钥材料。
type KeyInfo struct {
	ID        string   `json:"id"`
	Version   int      `json:"version"`
	State     KeyState `json:"state"`
	CreatedAt int64    `json:"created_at"`
	RevokedAt int64    `json:"revoked_at,omitempty"`
}

// KeyRing 是并发安全的本地密钥环，支持多代密钥并存。
type KeyRing struct {
	mu          sync.RWMutex
	entries     map[string]*KeyEntry
	current     string
	nextVersion int
	clock       func() int64
}

// New 创建一个空密钥环（时间源取系统时钟）。
func New() *KeyRing {
	return NewWithClock(func() int64 { return time.Now().Unix() })
}

// NewWithClock 使用注入的时间源创建密钥环，便于测试。
func NewWithClock(clock func() int64) *KeyRing {
	return &KeyRing{
		entries:     make(map[string]*KeyEntry),
		nextVersion: 1,
		clock:       clock,
	}
}

// Rotate 生成新一代密钥并设为当前有效密钥；旧密钥保留为 active。
func (r *KeyRing) Rotate() (*KeyInfo, error) {
	// 随机数生成放在锁外，避免 I/O 阻塞进入临界区。
	key, id, err := newAESGCMKey()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.entries[id]; exists {
		// 极小概率的随机标识碰撞：拒绝，绝不覆盖既有密钥。
		return nil, wrapErr("keyring.rotate", id, ErrMalformed, "密钥标识冲突")
	}
	entry := &KeyEntry{
		ID:        id,
		Version:   r.nextVersion,
		State:     StateActive,
		Key:       key,
		CreatedAt: r.clock(),
	}
	r.nextVersion++
	r.entries[id] = entry
	r.current = id
	info := entry.info()
	return &info, nil
}

// Revoke 吊销指定密钥。若吊销的是当前密钥，则不再存在可用于新封装的密钥。
func (r *KeyRing) Revoke(id string) (*KeyInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[id]
	if !ok {
		return nil, wrapErr("keyring.revoke", id, ErrUnknownKey, "密钥标识不存在")
	}
	if entry.State != StateRevoked {
		entry.State = StateRevoked
		entry.RevokedAt = r.clock()
	}
	if r.current == id {
		r.current = ""
	}
	info := entry.info()
	return &info, nil
}

// CurrentKeyID 返回当前有效密钥标识；空环或当前密钥已吊销时返回 false。
func (r *KeyRing) CurrentKeyID() (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.current == "" {
		return "", false
	}
	return r.current, true
}

// Info 返回指定密钥的公开元数据。
func (r *KeyRing) Info(id string) (KeyInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[id]
	if !ok {
		return KeyInfo{}, false
	}
	return e.info(), true
}

// ListInfos 按版本顺序返回全部密钥的公开元数据（不含密钥材料）。
func (r *KeyRing) ListInfos() []KeyInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]KeyInfo, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.info())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

func (e *KeyEntry) info() KeyInfo {
	return KeyInfo{
		ID:        e.ID,
		Version:   e.Version,
		State:     e.State,
		CreatedAt: e.CreatedAt,
		RevokedAt: e.RevokedAt,
	}
}

// Seal 使用当前有效密钥为指定接收方封装明文，返回线格式密文。
func (r *KeyRing) Seal(recipient string, plaintext []byte) ([]byte, error) {
	r.mu.RLock()
	if r.current == "" {
		r.mu.RUnlock()
		return nil, wrapErr("keyring.seal", "", ErrNoCurrentKey, "密钥环中没有当前有效密钥，请先轮换生成")
	}
	cur := r.entries[r.current]
	if cur == nil {
		r.mu.RUnlock()
		return nil, wrapErr("keyring.seal", r.current, ErrUnknownKey, "当前密钥标识在环中缺失")
	}
	if cur.State == StateRevoked {
		id := cur.ID
		r.mu.RUnlock()
		return nil, wrapErr("keyring.seal", id, ErrKeyRevoked, "当前密钥已被吊销，禁止新封装")
	}
	// 在锁内复制密钥材料与标识，密码学操作放到锁外执行，避免长临界区。
	keyCopy := append([]byte(nil), cur.Key...)
	kid := cur.ID
	r.mu.RUnlock()

	env := &Envelope{Header: Header{KeyID: kid, Recipient: recipient}}
	if err := seal(keyCopy, env, plaintext); err != nil {
		return nil, err
	}
	return encodeEnvelope(env), nil
}

// Open 使用密文头部声明的密钥解封，返回明文与实际使用的密钥标识。
func (r *KeyRing) Open(recipient string, data []byte) ([]byte, string, error) {
	const op = "keyring.open"
	env, err := decodeEnvelope(data)
	if err != nil {
		return nil, "", err
	}
	r.mu.RLock()
	entry, ok := r.entries[env.Header.KeyID]
	if !ok {
		r.mu.RUnlock()
		return nil, env.Header.KeyID, wrapErr(op, env.Header.KeyID, ErrUnknownKey, "密文密钥标识在环中不存在")
	}
	if entry.State == StateRevoked {
		id := entry.ID
		r.mu.RUnlock()
		return nil, id, wrapErr(op, id, ErrKeyRevoked, "密钥已吊销，拒绝解封其历史密文")
	}
	keyCopy := append([]byte(nil), entry.Key...)
	r.mu.RUnlock()

	pt, err := open(keyCopy, env, recipient)
	if err != nil {
		return nil, env.Header.KeyID, err
	}
	return pt, env.Header.KeyID, nil
}
