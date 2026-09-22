package keyring

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// storedState 是密钥环的完整持久化快照。
type storedState struct {
	CurrentID string       `json:"current_id"`
	NextVer   int          `json:"next_version"`
	Keys      []*storedKey `json:"keys"`
}

// ExportState 导出含密钥材料的完整状态快照（仅用于本地持久化/迁移）。
// 诊断用途请使用 ListInfos/Info，它们不含密钥材料。
func (r *KeyRing) ExportState() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	st := storedState{CurrentID: r.current, NextVer: r.nextVersion, Keys: make([]*storedKey, 0, len(r.entries))}
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
	data, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("导出密钥环状态失败: %w", err)
	}
	return data, nil
}

// LoadState 从快照恢复密钥环，与环内既有内容合并；重复标识按冲突拒绝。
func (r *KeyRing) LoadState(data []byte) error {
	const op = "keyring.load"
	var st storedState
	if err := json.Unmarshal(data, &st); err != nil {
		return wrapErr(op, "", ErrMalformed, "状态快照JSON无法解析: "+err.Error())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	maxVer := r.nextVersion
	for _, k := range st.Keys {
		if k == nil || k.ID == "" {
			return wrapErr(op, "", ErrMalformed, "存在缺少标识的密钥条目")
		}
		state := KeyState(k.State)
		if state != StateActive && state != StateRevoked {
			return wrapErr(op, k.ID, ErrMalformed, "未知的密钥状态: "+k.State)
		}
		if len(k.Key) != keySize {
			return wrapErr(op, k.ID, ErrMalformed, fmt.Sprintf("密钥材料长度非法: %d", len(k.Key)))
		}
		if _, exists := r.entries[k.ID]; exists {
			return wrapErr(op, k.ID, ErrMalformed, "密钥标识与环内既有条目冲突")
		}
		r.entries[k.ID] = &KeyEntry{
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
	if st.CurrentID != "" {
		cur, ok := r.entries[st.CurrentID]
		if !ok {
			return wrapErr(op, st.CurrentID, ErrUnknownKey, "快照当前密钥标识不在密钥列表中")
		}
		if cur.State == StateRevoked {
			return wrapErr(op, st.CurrentID, ErrKeyRevoked, "快照当前密钥已被吊销")
		}
		r.current = st.CurrentID
	}
	if st.NextVer > maxVer {
		maxVer = st.NextVer
	}
	r.nextVersion = maxVer
	return nil
}

// SaveToFile 将密钥环状态以 0600 权限原子写入文件（临时文件 + 重命名）。
func (r *KeyRing) SaveToFile(path string) error {
	data, err := r.ExportState()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keyring-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时状态文件失败: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("写入状态文件失败: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("设置状态文件权限失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭状态文件失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("替换状态文件失败: %w", err)
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
