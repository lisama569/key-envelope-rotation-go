package keyring

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// KeyState 表示密钥的生命周期状态。
type KeyState string

const (
	// StateActive 当前生效代：可用于新封装，也可解封其历史密文。全环至多一把。
	StateActive KeyState = "active"
	// StateRetained 保留的旧代：禁止新封装，仅用于解封其历史密文。
	StateRetained KeyState = "retained"
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
	Current   bool     `json:"current"`
	CreatedAt int64    `json:"created_at"`
	RevokedAt int64    `json:"revoked_at,omitempty"`
}

// Stats 是密钥环的分阶段统计，用于诊断“还剩多少代被保留”。
type Stats struct {
	Total    int `json:"total"`    // 环内现存密钥总数（不含已清理）
	Active   int `json:"active"`   // 当前生效代数量（0 或 1）
	Retained int `json:"retained"` // 保留旧代数量
	Revoked  int `json:"revoked"`  // 已吊销数量
	Pruned   int `json:"pruned"`   // 已清理（留墓碑）数量
}

// KeyRing 是并发安全的本地密钥环，支持多代密钥并存。
type KeyRing struct {
	mu          sync.RWMutex
	entries     map[string]*KeyEntry
	pruned      map[string]int64 // 已清理密钥的墓碑：标识 -> 清理时间，保证判定稳定可解释
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
		pruned:      make(map[string]int64),
		nextVersion: 1,
		clock:       clock,
	}
}

// Rotate 生成新一代密钥并设为当前有效密钥；此前的当前代降级为 retained（仅解封历史密文）。
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
	if _, wasPruned := r.pruned[id]; wasPruned {
		// 与已清理墓碑碰撞同样拒绝，避免清理判定被混淆。
		return nil, wrapErr("keyring.rotate", id, ErrMalformed, "密钥标识与已清理墓碑冲突")
	}
	// 旧当前代降级为保留代：从此刻起它不再用于新封装。
	if prev, ok := r.entries[r.current]; ok && prev.State == StateActive {
		prev.State = StateRetained
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
	info := entry.info(true)
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
	info := entry.info(false)
	return &info, nil
}

// Prune 按代清理指定密钥：从环中移除其材料并留下墓碑。
// 当前正在生效的那一代不允许清理；清理后其历史密文得到 ReasonPruned 的稳定拒绝。
// 返回被清理密钥在清理前的元数据快照。
func (r *KeyRing) Prune(id string) (*KeyInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[id]
	if !ok {
		if _, wasPruned := r.pruned[id]; wasPruned {
			return nil, wrapErr("keyring.prune", id, ErrKeyPruned, "密钥已被清理，无需重复操作")
		}
		return nil, wrapErr("keyring.prune", id, ErrUnknownKey, "密钥标识不存在")
	}
	if id == r.current {
		return nil, wrapErr("keyring.prune", id, ErrKeyIsCurrent, "当前生效密钥不允许清理，请先轮换")
	}
	info := entry.info(false)
	delete(r.entries, id)
	r.pruned[id] = r.clock()
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
	return e.info(id == r.current), true
}

// ListInfos 按版本顺序返回全部密钥的公开元数据（不含密钥材料）。
func (r *KeyRing) ListInfos() []KeyInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]KeyInfo, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.info(e.ID == r.current))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

// Stats 返回分阶段统计：当前生效、保留、吊销、已清理各多少代。
func (r *KeyRing) Stats() Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st := Stats{Total: len(r.entries), Pruned: len(r.pruned)}
	for _, e := range r.entries {
		switch e.State {
		case StateActive:
			st.Active++
		case StateRetained:
			st.Retained++
		case StateRevoked:
			st.Revoked++
		}
	}
	return st
}

func (e *KeyEntry) info(current bool) KeyInfo {
	return KeyInfo{
		ID:        e.ID,
		Version:   e.Version,
		State:     e.State,
		Current:   current,
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
	if cur.State != StateActive {
		id := cur.ID
		state := cur.State
		r.mu.RUnlock()
		return nil, wrapErr("keyring.seal", id, ErrNoCurrentKey,
			fmt.Sprintf("当前指针指向的密钥处于 %s 阶段，禁止新封装", state))
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
		_, wasPruned := r.pruned[env.Header.KeyID]
		r.mu.RUnlock()
		if wasPruned {
			// 已清理密钥：稳定、可解释的拒绝，绝不落入通用格式错误，也绝不尝试其他密钥。
			return nil, env.Header.KeyID, wrapErr(op, env.Header.KeyID, ErrKeyPruned,
				"密钥已按代清理，其历史密文不可再解封")
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
