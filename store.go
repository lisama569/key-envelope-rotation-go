package keyenvelope

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// persistedKeyring 是密钥环的磁盘表示（JSON）。
//
// 安全约定：该文件包含原始密钥材料，必须以 0600 权限保存；
// 对外诊断/导出一律走 Keyring.Snapshot()，其 KeyInfo 不含任何材料。
type persistedKeyring struct {
	// FormatVersion 为持久化结构版本，区别于密文内容版本。
	FormatVersion int            `json:"format_version"`
	Recipient     string         `json:"recipient"`
	ActiveID      string         `json:"active_id"`
	Keys          []persistedKey `json:"keys"`
}

type persistedKey struct {
	ID        string    `json:"id"`
	State     KeyState  `json:"state"`
	Raw       []byte    `json:"raw"`
	CreatedAt time.Time `json:"created_at"`
	RotatedAt time.Time `json:"rotated_at,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

const persistedFormatVersion = 1

// persistLocked 必须在持有写锁时调用：把内存态序列化到 path。
// 采用“同目录临时文件 + fsync + rename”保证原子替换，避免崩溃产生半截文件。
func (k *Keyring) persistLocked(path string) error {
	const op = "keyring.save"
	if path == "" {
		return newErr(KindIO, op, "", k.recipient, "empty persistence path", nil)
	}

	pk := persistedKeyring{
		FormatVersion: persistedFormatVersion,
		Recipient:     k.recipient,
		ActiveID:      k.activeID,
		Keys:          make([]persistedKey, 0, len(k.keys)),
	}
	for _, e := range k.keys {
		pk.Keys = append(pk.Keys, persistedKey{
			ID:        e.ID,
			State:     e.State,
			Raw:       append([]byte(nil), e.Raw...),
			CreatedAt: e.CreatedAt,
			RotatedAt: e.RotatedAt,
			RevokedAt: e.RevokedAt,
		})
	}
	data, err := json.MarshalIndent(&pk, "", "  ")
	if err != nil {
		return newErr(KindIO, op, "", k.recipient, "json marshal failed", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return newErr(KindIO, op, "", k.recipient, "create keyring directory failed", err)
	}
	tmp, err := os.CreateTemp(dir, ".keyring-*.tmp")
	if err != nil {
		return newErr(KindIO, op, "", k.recipient, "create temp file failed", err)
	}
	tmpName := tmp.Name()
	// 任何失败路径都清理临时文件；成功路径下 rename 会使其消失。
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return newErr(KindIO, op, "", k.recipient, "chmod 0600 failed", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return newErr(KindIO, op, "", k.recipient, "write temp file failed", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return newErr(KindIO, op, "", k.recipient, "fsync temp file failed", err)
	}
	if err := tmp.Close(); err != nil {
		return newErr(KindIO, op, "", k.recipient, "close temp file failed", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return newErr(KindIO, op, "", k.recipient, "atomic rename failed", err)
	}
	return nil
}

// LoadKeyring 从持久化文件加载密钥环，并校验接收方与文件内容一致。
// 加载过程会严格复核生命周期不变量，任何不一致都作为 KindIO/KindState 拒绝。
func LoadKeyring(path, recipient string) (*Keyring, error) {
	const op = "keyring.load"
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, newErr(KindIO, op, "", recipient, "keyring file does not exist: "+path, err)
		}
		return nil, newErr(KindIO, op, "", recipient, "read keyring file failed", err)
	}

	var pk persistedKeyring
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, newErr(KindIO, op, "", recipient, "keyring file is not valid JSON", err)
	}
	if pk.FormatVersion != persistedFormatVersion {
		return nil, newErr(KindIO, op, "", recipient,
			"unsupported persisted format version", nil)
	}
	if pk.Recipient == "" {
		return nil, newErr(KindIO, op, "", recipient, "persisted keyring has empty recipient", nil)
	}
	if pk.Recipient != recipient {
		return nil, newErr(KindRecipientMismatch, op, pk.ActiveID, recipient,
			"persisted recipient does not match requested recipient", nil)
	}

	kr := &Keyring{
		recipient: pk.Recipient,
		keys:      make(map[string]*keyEntry, len(pk.Keys)),
		activeID:  pk.ActiveID,
		path:      path,
	}
	for i := range pk.Keys {
		p := pk.Keys[i]
		if p.ID == "" {
			return nil, newErr(KindIO, op, "", recipient, "persisted key with empty id", nil)
		}
		if _, dup := kr.keys[p.ID]; dup {
			return nil, newErr(KindIO, op, p.ID, recipient, "duplicate key id in keyring file", nil)
		}
		switch p.State {
		case StateActive, StateRetired, StateRevoked:
		default:
			return nil, newErr(KindState, op, p.ID, recipient, "unknown key state in keyring file", nil)
		}
		if len(p.Raw) != aes256KeyLen {
			return nil, newErr(KindState, op, p.ID, recipient, "persisted key has wrong length", nil)
		}
		kr.keys[p.ID] = &keyEntry{
			ID:        p.ID,
			State:     p.State,
			Raw:       append([]byte(nil), p.Raw...),
			CreatedAt: p.CreatedAt,
			RotatedAt: p.RotatedAt,
			RevokedAt: p.RevokedAt,
		}
	}
	// 复核 active 不变量：activeID 为空，或指向唯一 active entry。
	if kr.activeID != "" {
		e, ok := kr.keys[kr.activeID]
		if !ok {
			return nil, newErr(KindState, op, kr.activeID, recipient,
				"active_id points at missing key", nil)
		}
		if e.State != StateActive {
			return nil, newErr(KindState, op, kr.activeID, recipient,
				"active_id points at non-active key", nil)
		}
	}
	for id, e := range kr.keys {
		if e.State == StateActive && id != kr.activeID {
			return nil, newErr(KindState, op, id, recipient,
				"more than one active key in keyring file", nil)
		}
	}
	return kr, nil
}

// loadFromFile 保留与内部命名一致的入口（骨架期声明）。
func loadFromFile(path, recipient string) (*Keyring, error) {
	return LoadKeyring(path, recipient)
}
