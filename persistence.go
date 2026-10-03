package keyring

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// storedTombstone 是已清理密钥的墓碑记录，保证重载后清理判定依然稳定。
type storedTombstone struct {
	ID       string `json:"id"`
	PrunedAt int64  `json:"pruned_at"`
}

// storedState 是密钥环的完整持久化快照。
type storedState struct {
	CurrentID string            `json:"current_id"`
	NextVer   int               `json:"next_version"`
	Keys      []*storedKey      `json:"keys"`
	Pruned    []storedTombstone `json:"pruned,omitempty"`
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
	for id, at := range r.pruned {
		st.Pruned = append(st.Pruned, storedTombstone{ID: id, PrunedAt: at})
	}
	sort.Slice(st.Pruned, func(i, j int) bool { return st.Pruned[i].ID < st.Pruned[j].ID })
	data, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("导出密钥环状态失败: %w", err)
	}
	return data, nil
}

// LoadState 从快照恢复密钥环，与环内既有内容合并；重复标识或重复版本按冲突拒绝。
//
// 兼容旧版快照：旧格式中所有未吊销密钥都记为 "active"，加载时仅当前指针
// 指向的密钥保持 active，其余按新语义降级为 retained。缺少 pruned 字段
// 视为无清理记录。旧格式中吊销密钥同样带有有效吊销时间，不受下述一致性校验误伤。
//
// 加载前对快照做完整自洽性校验，任何一项不过即整体拒绝（返回 malformed 归类错误），
// 环内既有的密钥、阶段、统计与清理墓碑一个字节都不变：
//   - 版本号必须为正整数，且在（快照 ∪ 环）内唯一，不允许两代密钥共用版本号；
//   - 阶段与吊销时间必须一致：revoked 密钥必须携带有效（正数）吊销时间；
//     active/retained 密钥携带吊销时间属于字段冲突；
//   - 其他既有矛盾：当前指针指向非 active/已清理/不存在的密钥、快照内标识重复、
//     密钥与墓碑冲突、未知状态枚举、版本计数回退、密钥材料长度非法等。
func (r *KeyRing) LoadState(data []byte) error {
	const op = "keyring.load"
	var st storedState
	if err := json.Unmarshal(data, &st); err != nil {
		return wrapErr(op, "", ErrMalformed, "状态快照JSON无法解析: "+err.Error())
	}

	// 先在不触碰环的情况下做完整快照自洽性校验，全部通过后才合并。
	seen := make(map[string]bool, len(st.Keys))
	seenVer := make(map[int]string, len(st.Keys)) // version -> 首个声明该版本的密钥标识
	snapMaxVer := 0
	for _, k := range st.Keys {
		if k == nil || k.ID == "" {
			return wrapErr(op, "", ErrMalformed, "存在缺少标识的密钥条目")
		}
		if seen[k.ID] {
			return wrapErr(op, k.ID, ErrMalformed, "快照内密钥标识重复")
		}
		seen[k.ID] = true
		state := KeyState(k.State)
		if state != StateActive && state != StateRetained && state != StateRevoked {
			return wrapErr(op, k.ID, ErrMalformed, "未知的密钥状态: "+k.State)
		}
		// 版本号必须是合法正数，且快照内唯一：否则无法区分代际先后，排序/统计都会错乱。
		if k.Version <= 0 {
			return wrapErr(op, k.ID, ErrMalformed,
				fmt.Sprintf("密钥版本号非法: %d，版本号必须为正整数", k.Version))
		}
		if other, dup := seenVer[k.Version]; dup {
			return wrapErr(op, k.ID, ErrMalformed,
				fmt.Sprintf("快照内密钥版本号重复: version=%d（%s 与 %s），无法区分代际", k.Version, other, k.ID))
		}
		seenVer[k.Version] = k.ID
		// 阶段与吊销时间必须一致：只有 revoked 密钥允许携带吊销时间，且时间必须是有效正数；
		// active/retained 携带吊销时间、或 revoked 缺少有效吊销时间，都属于字段冲突。
		if state == StateRevoked {
			if k.RevokedAt <= 0 {
				return wrapErr(op, k.ID, ErrMalformed,
					fmt.Sprintf("密钥状态为 revoked 但缺少有效吊销时间: revoked_at=%d", k.RevokedAt))
			}
		} else if k.RevokedAt != 0 {
			return wrapErr(op, k.ID, ErrMalformed,
				fmt.Sprintf("密钥状态为 %s 却携带吊销时间 revoked_at=%d，阶段与吊销时间冲突", state, k.RevokedAt))
		}
		if len(k.Key) != keySize {
			return wrapErr(op, k.ID, ErrMalformed, fmt.Sprintf("密钥材料长度非法: %d", len(k.Key)))
		}
		// 当前指针指向的密钥在快照中必须显式为 active，否则状态自相矛盾。
		if k.ID == st.CurrentID && state != StateActive {
			return wrapErr(op, k.ID, ErrMalformed,
				fmt.Sprintf("快照当前密钥状态为 %s，与当前指针矛盾", state))
		}
		if k.Version > snapMaxVer {
			snapMaxVer = k.Version
		}
	}
	if len(st.Keys) > 0 && st.NextVer < snapMaxVer+1 {
		return wrapErr(op, "", ErrMalformed,
			fmt.Sprintf("版本计数回退: next_version=%d 小于已用最大版本 %d", st.NextVer, snapMaxVer))
	}
	tombSeen := make(map[string]bool, len(st.Pruned))
	for _, tb := range st.Pruned {
		if tb.ID == "" {
			return wrapErr(op, "", ErrMalformed, "存在缺少标识的清理墓碑")
		}
		if tombSeen[tb.ID] {
			return wrapErr(op, tb.ID, ErrMalformed, "快照内清理墓碑重复")
		}
		tombSeen[tb.ID] = true
		if seen[tb.ID] {
			return wrapErr(op, tb.ID, ErrMalformed, "密钥条目与清理墓碑冲突")
		}
		if tb.ID == st.CurrentID {
			return wrapErr(op, tb.ID, ErrMalformed, "当前指针指向已清理密钥，状态矛盾")
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// 与环内既有内容的冲突也在合并前统一检查，保证加载要么整体生效要么整体拒绝。
	ringVer := make(map[int]string, len(r.entries))
	for _, e := range r.entries {
		ringVer[e.Version] = e.ID
	}
	for _, k := range st.Keys {
		if _, exists := r.entries[k.ID]; exists {
			return wrapErr(op, k.ID, ErrMalformed, "密钥标识与环内既有条目冲突")
		}
		if _, wasPruned := r.pruned[k.ID]; wasPruned {
			return wrapErr(op, k.ID, ErrMalformed, "密钥标识与环内已清理墓碑冲突")
		}
		// 版本号在（快照 ∪ 环）内也必须唯一：合并后不得出现两代密钥共用一个版本号。
		if other, dup := ringVer[k.Version]; dup {
			return wrapErr(op, k.ID, ErrMalformed,
				fmt.Sprintf("密钥版本号与环内既有密钥重复: version=%d（%s 与 %s），无法区分代际", k.Version, other, k.ID))
		}
	}
	maxVer := r.nextVersion
	if st.NextVer > maxVer {
		maxVer = st.NextVer
	}
	if st.CurrentID != "" {
		// 当前指针校验也在合并前完成：必须能在（快照 ∪ 环）中解析到一把
		// 合并后处于 active 阶段的密钥。
		if cur, ok := r.entries[st.CurrentID]; ok {
			if cur.State != StateActive {
				return wrapErr(op, st.CurrentID, ErrMalformed,
					fmt.Sprintf("快照当前密钥在环中处于 %s 阶段，状态不自洽", cur.State))
			}
		} else if !seen[st.CurrentID] {
			return wrapErr(op, st.CurrentID, ErrUnknownKey, "快照当前密钥标识不在密钥列表中")
		}
		// 当前标识在快照密钥中的情形已在无锁校验阶段确认其快照状态为 active。
	}
	for _, k := range st.Keys {
		state := KeyState(k.State)
		// 旧版快照兼容：非当前的 active 密钥按新语义降级为 retained。
		if state == StateActive && k.ID != st.CurrentID {
			state = StateRetained
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
	for _, tb := range st.Pruned {
		if _, exists := r.pruned[tb.ID]; !exists {
			r.pruned[tb.ID] = tb.PrunedAt
		}
	}
	if st.CurrentID != "" {
		r.current = st.CurrentID
	}
	r.nextVersion = maxVer
	return nil
}

// SaveToFile 将密钥环状态以 0600 权限原子写入文件。
//
// 崩溃安全保证：上级目录不存在时自动创建；先写临时文件并 fsync，
// 再通过 rename 原子替换目标，最后 fsync 目录确保持久。替换失败时
// 原有文件保持可用、内容不被破坏。
func (r *KeyRing) SaveToFile(path string) error {
	data, err := r.ExportState()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建状态文件上级目录失败: %w", err)
	}
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
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("落盘临时状态文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭状态文件失败: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		// rename 未生效，原文件（若存在）内容不受影响。
		return fmt.Errorf("替换状态文件失败: %w", err)
	}
	// fsync 目录，保证 rename 结果在崩溃后依然可见。
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
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
