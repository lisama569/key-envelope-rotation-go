package keyring

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// 持久化快照格式版本：
//
//	1 —— 旧版：无 FormatVersion 字段，状态仅有 active/revoked；
//	2 —— 当前：生命周期细化为 current/retained/revoked，并记录已清理世代的墓碑。
const (
	snapshotFormatV1 = 1
	snapshotFormatV2 = 2
)

// storedKey 是持久化用的密钥条目表示（含材料，仅用于本地落盘，禁止用于诊断导出）。
type storedKey struct {
	ID        string `json:"id"`
	Version   int    `json:"version"`
	State     string `json:"state"`
	Key       []byte `json:"key"`
	CreatedAt int64  `json:"created_at"`
	RevokedAt int64  `json:"revoked_at,omitempty"`
}

// storedTombstone 记录一个已清理世代：材料已删除，仅保留标识用于稳定、可解释地拒绝其历史密文。
type storedTombstone struct {
	ID        string `json:"id"`
	RetiredAt int64  `json:"retired_at"`
}

// storedState 是密钥环的完整持久化快照。
type storedState struct {
	FormatVersion int               `json:"format_version,omitempty"`
	CurrentID     string            `json:"current_id"`
	NextVer       int               `json:"next_version"`
	Keys          []*storedKey      `json:"keys"`
	Retired       []storedTombstone `json:"retired,omitempty"`
}

// ExportState 导出含密钥材料的完整状态快照（仅用于本地持久化/迁移）。
// 诊断用途请使用 ListInfos/Info/Stats，它们不含密钥材料。
func (r *KeyRing) ExportState() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st := storedState{
		FormatVersion: snapshotFormatV2,
		CurrentID:     r.current,
		NextVer:       r.nextVersion,
		Keys:          make([]*storedKey, 0, len(r.entries)),
		Retired:       make([]storedTombstone, 0, len(r.retired)),
	}
	for _, e := range r.entries {
		st.Keys = append(st.Keys, &storedKey{
			ID:        e.ID,
			Version:   e.Version,
			State:     string(e.State),
			Key:       append([]byte(nil), e.Key...),
			CreatedAt: e.CreatedAt,
			RevokedAt: e.RevokedAt,
		})
	}
	for id, at := range r.retired {
		st.Retired = append(st.Retired, storedTombstone{ID: id, RetiredAt: at})
	}
	data, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("导出密钥环状态失败: %w", err)
	}
	return data, nil
}

// LoadState 从快照恢复密钥环，与环内既有内容合并；任何与既有内容冲突或快照内部
// 自相矛盾的情况都会被明确拒绝（malformed），绝不恢复出状态不自洽的密钥环。
// 旧版（format_version 缺失的 v1）快照可正常加载：active 世代按“是否为当前”
// 归一化为 current/retained。
func (r *KeyRing) LoadState(data []byte) error {
	const op = "keyring.load"
	var st storedState
	if err := json.Unmarshal(data, &st); err != nil {
		return wrapErr(op, "", ErrMalformed, "状态快照JSON无法解析: "+err.Error())
	}

	// 缺省 format_version 视为 v1；只接受已知版本。
	format := st.FormatVersion
	if format == 0 {
		format = snapshotFormatV1
	} else if format != snapshotFormatV1 && format != snapshotFormatV2 {
		return wrapErr(op, "", ErrUnsupportedVersion,
			fmt.Sprintf("不支持的快照格式版本: %d", st.FormatVersion))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	maxVer := r.nextVersion
	seenID := make(map[string]bool, len(st.Keys))
	seenVer := make(map[int]bool, len(st.Keys))
	parsed := make(map[string]*KeyEntry, len(st.Keys))

	for _, k := range st.Keys {
		if k == nil || k.ID == "" {
			return wrapErr(op, "", ErrMalformed, "存在缺少标识的密钥条目")
		}
		if seenID[k.ID] {
			return wrapErr(op, k.ID, ErrMalformed, "快照内密钥标识重复")
		}
		seenID[k.ID] = true
		if k.Version <= 0 {
			return wrapErr(op, k.ID, ErrMalformed, fmt.Sprintf("版本号非法: %d", k.Version))
		}
		if seenVer[k.Version] {
			return wrapErr(op, k.ID, ErrMalformed, fmt.Sprintf("快照内版本号重复: %d", k.Version))
		}
		seenVer[k.Version] = true
		if len(k.Key) != keySize {
			return wrapErr(op, k.ID, ErrMalformed, fmt.Sprintf("密钥材料长度非法: %d", len(k.Key)))
		}
		if _, exists := r.entries[k.ID]; exists {
			return wrapErr(op, k.ID, ErrMalformed, "密钥标识与环内既有条目冲突")
		}
		if _, tombstoned := r.retired[k.ID]; tombstoned {
			return wrapErr(op, k.ID, ErrMalformed, "密钥标识与环内已清理世代的墓碑冲突")
		}

		state, err := normalizeSnapshotState(op, k, format, st.CurrentID)
		if err != nil {
			return err
		}
		parsed[k.ID] = &KeyEntry{
			ID:        k.ID,
			Version:   k.Version,
			State:     state,
			Key:       append([]byte(nil), k.Key...),
			CreatedAt: k.CreatedAt,
			RevokedAt: k.RevokedAt,
		}
		if k.Version >= maxVer {
			maxVer = k.Version + 1
		}
	}

	// v2 墓碑：去重、不得与存活条目矛盾。
	retired := make(map[string]int64, len(st.Retired))
	if format == snapshotFormatV2 {
		for _, t := range st.Retired {
			if t.ID == "" {
				return wrapErr(op, "", ErrMalformed, "存在缺少标识的墓碑条目")
			}
			if seenID[t.ID] {
				return wrapErr(op, t.ID, ErrMalformed, "同一世代既在密钥列表中又被标记为已清理")
			}
			if _, dup := retired[t.ID]; dup {
				return wrapErr(op, t.ID, ErrMalformed, "墓碑标识重复")
			}
			if _, live := r.entries[t.ID]; live {
				return wrapErr(op, t.ID, ErrMalformed, "墓碑标识与环内既有存活条目冲突")
			}
			if _, exists := r.retired[t.ID]; exists {
				return wrapErr(op, t.ID, ErrMalformed, "墓碑标识与环内既有墓碑冲突")
			}
			retired[t.ID] = t.RetiredAt
		}
	}

	if st.CurrentID != "" {
		cur, ok := parsed[st.CurrentID]
		if !ok {
			if _, wasRetired := retired[st.CurrentID]; wasRetired {
				return wrapErr(op, st.CurrentID, ErrKeyRetired, "快照当前密钥世代已被清理")
			}
			return wrapErr(op, st.CurrentID, ErrUnknownKey, "快照当前密钥标识不在密钥列表中")
		}
		if cur.State == StateRevoked {
			return wrapErr(op, st.CurrentID, ErrKeyRevoked, "快照当前密钥已被吊销")
		}
		if cur.State != StateCurrent {
			return wrapErr(op, st.CurrentID, ErrMalformed, "快照当前密钥的生命周期阶段不是 current")
		}
	}

	if st.NextVer > maxVer {
		maxVer = st.NextVer
	}

	// 全部校验通过后才提交，失败不会对现有密钥环产生任何改动。
	for id, e := range parsed {
		r.entries[id] = e
	}
	for id, at := range retired {
		r.retired[id] = at
	}
	if st.CurrentID != "" {
		r.current = st.CurrentID
	}
	r.nextVersion = maxVer
	return nil
}

// normalizeSnapshotState 将快照中的状态字符串归一化为内部生命周期阶段，
// 并处理旧版（v1：active/revoked）到新语义（current/retained/revoked）的兼容映射。
func normalizeSnapshotState(op string, k *storedKey, format int, currentID string) (KeyState, error) {
	switch format {
	case snapshotFormatV1:
		switch KeyState(k.State) {
		case "active":
			if k.RevokedAt != 0 {
				return "", wrapErr(op, k.ID, ErrMalformed, "active 世代携带吊销时间戳，状态自相矛盾")
			}
			if k.ID == currentID {
				return StateCurrent, nil
			}
			return StateRetained, nil
		case StateRevoked:
			return StateRevoked, nil
		default:
			return "", wrapErr(op, k.ID, ErrMalformed, "未知的密钥状态: "+k.State)
		}
	default: // v2
		switch KeyState(k.State) {
		case StateCurrent, StateRetained, StateRevoked:
			state := KeyState(k.State)
			if state == StateRevoked {
				return state, nil
			}
			if k.RevokedAt != 0 {
				return "", wrapErr(op, k.ID, ErrMalformed, "未吊销世代携带吊销时间戳，状态自相矛盾")
			}
			if state == StateCurrent && k.ID != currentID {
				return "", wrapErr(op, k.ID, ErrMalformed, "标记为 current 的世代与当前指针不一致")
			}
			return state, nil
		default:
			return "", wrapErr(op, k.ID, ErrMalformed, "未知的密钥状态: "+k.State)
		}
	}
}

// SaveToFile 将密钥环状态以 0600 权限崩溃安全地写入文件：
//   - 上级目录不存在时自动创建（0700）；
//   - 先写同目录临时文件并 fsync 落盘，再通过 rename 原子替换目标文件，
//     最后 fsync 目录保证替换本身持久化；
//   - 任意步骤失败时原文件保持原样、内容不被破坏。
func (r *KeyRing) SaveToFile(path string) error {
	data, err := r.ExportState()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建状态文件目录失败: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".keyring-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时状态文件失败: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写入状态文件失败: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("设置状态文件权限失败: %w", err)
	}
	if err := tmp.Sync(); err != nil { // 数据先落盘，再允许替换
		tmp.Close()
		return fmt.Errorf("同步状态文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭状态文件失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil { // 原子替换：失败时原文件不受影响
		return fmt.Errorf("替换状态文件失败: %w", err)
	}
	committed = true
	if err := fsyncDir(dir); err != nil {
		return fmt.Errorf("同步状态目录失败（文件已替换）: %w", err)
	}
	return nil
}

// LoadKeyRingFromFile 从文件加载密钥环；文件不存在时返回包装了 os.ErrNotExist 的错误。
func LoadKeyRingFromFile(path string) (*KeyRing, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取状态文件失败: %w", err)
	}
	r := New()
	if err := r.LoadState(data); err != nil {
		return nil, err
	}
	return r, nil
}
