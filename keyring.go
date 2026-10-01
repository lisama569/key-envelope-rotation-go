package keyring

import (
	"sort"
	"sync"
	"time"
)

// KeyState 表示密钥的生命周期阶段。
type KeyState string

const (
	// StateCurrent 当前世代：唯一可用于新封装（Seal）的密钥，同时可解封其历史密文。
	StateCurrent KeyState = "current"
	// StateRetained 保留世代：轮换后退役的旧代，仅用于解封其历史密文，不能用于新封装。
	StateRetained KeyState = "retained"
	// StateRevoked 已吊销：既不能用于新封装，其历史密文也被稳定、明确地拒绝。
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

// Stats 是密钥环的计数视图，用于运维诊断：一眼看清各生命周期阶段的世代数。
type Stats struct {
	Total    int `json:"total"`    // 环内仍保留材料的世代数（current + retained + revoked）
	Current  int `json:"current"`  // 当前用于新封装的世代数（0 或 1）
	Retained int `json:"retained"` // 仅用于解历史密文的保留世代数
	Revoked  int `json:"revoked"`  // 已吊销但材料尚未清理的世代数
	Retired  int `json:"retired"`  // 已被清理（材料删除、仅存墓碑）的世代数
}

// KeyRing 是并发安全的本地密钥环，支持多代密钥并存。
type KeyRing struct {
	mu          sync.RWMutex
	entries     map[string]*KeyEntry
	retired     map[string]int64 // 已清理世代的墓碑：id -> 清理时间
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
		retired:     make(map[string]int64),
		nextVersion: 1,
		clock:       clock,
	}
}

// Rotate 生成新一代密钥并设为当前世代；上一代从 current 降级为 retained，
// 此后只用于解封其历史密文，不再用于新封装。
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
	if _, tombstoned := r.retired[id]; tombstoned {
		return nil, wrapErr("keyring.rotate", id, ErrMalformed, "密钥标识与已清理世代冲突")
	}
	if r.current != "" {
		if old := r.entries[r.current]; old != nil && old.State == StateCurrent {
			old.State = StateRetained
		}
	}
	entry := &KeyEntry{
		ID:        id,
		Version:   r.nextVersion,
		State:     StateCurrent,
		Key:       key,
		CreatedAt: r.clock(),
	}
	r.nextVersion++
	r.entries[id] = entry
	r.current = id
	info := entry.info()
	return &info, nil
}

// Revoke 吊销指定密钥。若吊销的是当前世代，则不再存在可用于新封装的密钥。
func (r *KeyRing) Revoke(id string) (*KeyInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[id]
	if !ok {
		if _, wasRetired := r.retired[id]; wasRetired {
			return nil, wrapErr("keyring.revoke", id, ErrKeyRetired, "密钥世代已被清理，无法吊销")
		}
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

// Retire 按代清理指定密钥：删除密钥材料并留下墓碑（tombstone），用于控制密钥环长期增长。
// 当前正在生效的世代受保护，不允许清理。清理后：
//   - 该世代从 ListInfos/Info 中消失，但仍计入 Stats.Retired；
//   - 用它封装过的历史密文解封时得到稳定、可解释的 key_retired 判定，
//     绝不会被报成普通格式错误，也绝不会误用其他密钥解出内容。
func (r *KeyRing) Retire(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[id]
	if !ok {
		if _, wasRetired := r.retired[id]; wasRetired {
			return wrapErr("keyring.retire", id, ErrKeyRetired, "密钥世代此前已被清理")
		}
		return wrapErr("keyring.retire", id, ErrUnknownKey, "密钥标识不存在")
	}
	if entry.State == StateCurrent || r.current == id {
		return wrapErr("keyring.retire", id, ErrCurrentKeyProtected,
			"当前正在生效的密钥世代不允许清理，请先轮换到新一代")
	}
	delete(r.entries, id)
	r.retired[id] = r.clock()
	return nil
}

// Stats 返回各生命周期阶段的世代计数（含已清理世代的墓碑数）。
func (r *KeyRing) Stats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var s Stats
	for _, e := range r.entries {
		s.Total++
		switch e.State {
		case StateCurrent:
			s.Current++
		case StateRetained:
			s.Retained++
		case StateRevoked:
			s.Revoked++
		}
	}
	s.Retired = len(r.retired)
	return s
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
	if cur.State != StateCurrent {
		id := cur.ID
		r.mu.RUnlock()
		if cur.State == StateRevoked {
			return nil, wrapErr("keyring.seal", id, ErrKeyRevoked, "当前密钥已被吊销，禁止新封装")
		}
		return nil, wrapErr("keyring.seal", id, ErrKeyRetired, "当前密钥世代已被清理，禁止新封装")
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
		_, retired := r.retired[env.Header.KeyID]
		r.mu.RUnlock()
		if retired {
			return nil, env.Header.KeyID, wrapErr(op, env.Header.KeyID, ErrKeyRetired,
				"密钥世代已被清理，其历史密文无法解封")
		}
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
