package keyring

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// TestPhaseTransitions 验证轮换后阶段迁移：当前代 active，旧代降级 retained，
// 诊断信息可直接区分，retained 仅用于解历史密文。
func TestPhaseTransitions(t *testing.T) {
	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("gen-1"))

	if k1.State != StateActive || !k1.Current {
		t.Fatalf("首代应为 active 当前代: %+v", k1)
	}
	k2, _ := r.Rotate()
	c2, _ := r.Seal("alice", []byte("gen-2"))

	i1, _ := r.Info(k1.ID)
	i2, _ := r.Info(k2.ID)
	t.Logf("[phase] 轮换后: key=%s state=%s current=%v; key=%s state=%s current=%v",
		k1.ID, i1.State, i1.Current, k2.ID, i2.State, i2.Current)
	if i1.State != StateRetained || i1.Current {
		t.Fatalf("旧代应降级为 retained 且非当前: %+v", i1)
	}
	if i2.State != StateActive || !i2.Current {
		t.Fatalf("新代应为 active 当前代: %+v", i2)
	}

	// retained 旧代可解历史密文
	pt, kid, err := r.Open("alice", c1)
	if err != nil || kid != k1.ID || string(pt) != "gen-1" {
		t.Fatalf("retained 旧代历史密文解封失败: pt=%q kid=%s err=%v", pt, kid, err)
	}
	t.Logf("[phase] retained key=%s 历史密文解封成功", kid)

	// 新封装只用当前代，retained 代不会被用于新封装
	env, _ := decodeEnvelope(c2)
	if env.Header.KeyID != k2.ID {
		t.Fatalf("新封装误用旧代 key=%s，期望 %s", env.Header.KeyID, k2.ID)
	}

	st := r.Stats()
	t.Logf("[phase] 统计: %+v", st)
	if st.Total != 2 || st.Active != 1 || st.Retained != 1 || st.Revoked != 0 || st.Pruned != 0 {
		t.Fatalf("阶段统计错误: %+v", st)
	}
}

// TestPruneLifecycle 验证按代清理的边界与后果。
func TestPruneLifecycle(t *testing.T) {
	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("under-k1"))
	k2, _ := r.Rotate()
	c2, _ := r.Seal("alice", []byte("under-k2"))

	st := r.Stats()
	t.Logf("[prune] 清理前: retained=%d total=%d", st.Retained, st.Total)

	// 当前生效代不允许清理
	_, err := r.Prune(k2.ID)
	expectFail(t, "prune-current", k2.ID, err, ReasonCurrentKey)

	// 不存在的标识
	_, err = r.Prune("k-never-existed")
	expectFail(t, "prune-unknown", "k-never-existed", err, ReasonUnknownKey)

	// 清理 retained 旧代
	removed, err := r.Prune(k1.ID)
	if err != nil {
		t.Fatalf("清理 retained 旧代应成功: %v", err)
	}
	t.Logf("[prune] 已清理 key=%s version=%d 清理前状态=%s", removed.ID, removed.Version, removed.State)
	if _, ok := r.Info(k1.ID); ok {
		t.Fatal("清理后密钥不应再出现在诊断信息中")
	}

	// 历史密文得到稳定、可解释的 pruned 判定：不是 malformed，不是 unknown_key
	_, _, err = r.Open("alice", c1)
	expectFail(t, "open-pruned", k1.ID, err, ReasonPruned)
	if errors.Is(err, ErrMalformed) || errors.Is(err, ErrUnknownKey) {
		t.Fatalf("清理后的判定不得落入 malformed/unknown_key: %v", err)
	}

	// 重复清理同一标识：判定同样稳定
	_, err = r.Prune(k1.ID)
	expectFail(t, "prune-again", k1.ID, err, ReasonPruned)

	// 未清理的当前代不受影响，新封装与解封正常
	if pt, kid, err := r.Open("alice", c2); err != nil || kid != k2.ID || string(pt) != "under-k2" {
		t.Fatalf("当前代密文受清理牵连: %v", err)
	}
	if _, err := r.Seal("alice", []byte("still-works")); err != nil {
		t.Fatalf("清理旧代后新封装应正常: %v", err)
	}

	st = r.Stats()
	t.Logf("[prune] 清理后: %+v", st)
	if st.Total != 1 || st.Retained != 0 || st.Active != 1 || st.Pruned != 1 {
		t.Fatalf("清理后统计错误: %+v", st)
	}
}

// TestPruneRevokedKey 验证已吊销密钥也可被清理，且清理后判定由 revoked 变为 pruned。
func TestPruneRevokedKey(t *testing.T) {
	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("x"))
	if _, err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Revoke(k1.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err := r.Open("alice", c1)
	expectFail(t, "open-revoked-before-prune", k1.ID, err, ReasonRevoked)

	if _, err := r.Prune(k1.ID); err != nil {
		t.Fatalf("清理已吊销密钥应成功: %v", err)
	}
	_, _, err = r.Open("alice", c1)
	expectFail(t, "open-pruned-after-revoke", k1.ID, err, ReasonPruned)
}

// TestConcurrentPruneSealOpenRotate 并发清理与封装/解封/轮换：任何时刻不出现
// 状态撕裂、不抽走当前密钥、不跨密钥误用；竞态检测下运行。
func TestConcurrentPruneSealOpenRotate(t *testing.T) {
	r := New()
	// 预置 4 代：k1..k3 终将成为 retained，k4 为当前
	ids := make([]string, 0, 4)
	cts := make(map[string][]byte)
	for i := 0; i < 4; i++ {
		info, err := r.Rotate()
		if err != nil {
			t.Fatal(err)
		}
		ct, err := r.Seal("alice", []byte("gen-"+info.ID))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, info.ID)
		cts[info.ID] = ct
	}
	prunable := ids[:2] // 将被并发清理
	kept := ids[2:]     // 保留：k3 retained + k4 当前

	var wg sync.WaitGroup
	var failMu sync.Mutex
	fail := func(format string, args ...any) {
		failMu.Lock()
		defer failMu.Unlock()
		t.Errorf(format, args...)
	}

	// 并发清理者：只允许清非当前代；清理结果只能是成功或 current_key（轮换竞态下
	// 目标恰好成为当前的瞬间不可能发生，因为清理目标不是最新代，但保留防御）
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, id := range prunable {
			if _, err := r.Prune(id); err != nil {
				fail("[prune] key=%s 清理出现非预期错误: %v", id, err)
			} else {
				t.Logf("[prune] 并发清理 key=%s 成功", id)
			}
		}
	}()

	// 并发轮换者
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 4; i++ {
			if _, err := r.Rotate(); err != nil {
				fail("[rotate] 并发轮换失败: %v", err)
			}
		}
	}()

	// 并发封装者
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				ct, err := r.Seal("alice", []byte(fmt.Sprintf("w%d-%d", w, i)))
				if err != nil {
					if reasonOf(err) != ReasonNoCurrentKey {
						fail("[seal] 并发封装非预期错误: %v", err)
					}
					continue
				}
				env, err := decodeEnvelope(ct)
				if err != nil {
					fail("[seal] 密文无法解码: %v", err)
					continue
				}
				// 新封装绝不使用将被清理的代
				for _, id := range prunable {
					if env.Header.KeyID == id {
						fail("[seal] 新封装误用了待清理密钥 key=%s", id)
					}
				}
			}
		}(w)
	}

	// 并发解封者：被清理代的密文只能成功（清理前）或 pruned（清理后），
	// 绝不允许 malformed/tampered/跨密钥误用；保留代与当前代必须始终成功。
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				for _, id := range prunable {
					pt, kid, err := r.Open("alice", cts[id])
					if err != nil {
						if reasonOf(err) != ReasonPruned {
							fail("[open] key=%s 清理窗口内出现非 pruned 错误: %v", id, err)
						}
						continue
					}
					if kid != id || string(pt) != "gen-"+id {
						fail("[open] key=%s 解封结果错位: kid=%s pt=%q", id, kid, pt)
					}
				}
				for _, id := range kept {
					if _, kid, err := r.Open("alice", cts[id]); err != nil || kid != id {
						fail("[open] 保留代 key=%s 解封受影响: kid=%s err=%v", id, kid, err)
					}
				}
			}
		}()
	}
	wg.Wait()

	// 并发结束后判定必须稳定：已清理代 -> pruned，保留代 -> 正常
	for _, id := range prunable {
		_, _, err := r.Open("alice", cts[id])
		expectFail(t, "open-after-concurrent-prune", id, err, ReasonPruned)
	}
	for _, id := range kept {
		if _, kid, err := r.Open("alice", cts[id]); err != nil || kid != id {
			t.Fatalf("并发结束后保留代 key=%s 解封失败: %v", id, err)
		}
	}
	st := r.Stats()
	t.Logf("[concurrent] 结束统计: %+v", st)
	if st.Pruned != len(prunable) {
		t.Fatalf("清理墓碑数量错误: %+v", st)
	}
}

// TestSaveToFileCreatesParentDirs 上级目录不存在时也要能保存并重载。
func TestSaveToFileCreatesParentDirs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deeper", "ring.json")

	r := New()
	k, _ := r.Rotate()
	ct, _ := r.Seal("alice", []byte("deep-save"))
	if err := r.SaveToFile(path); err != nil {
		t.Fatalf("上级目录不存在时保存应成功: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("状态文件缺失或权限错误: %v %v", fi, err)
	}

	r2, err := LoadKeyRingFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pt, kid, err := r2.Open("alice", ct)
	if err != nil || kid != k.ID || string(pt) != "deep-save" {
		t.Fatalf("深层目录保存后重载解封失败: %v", err)
	}
	t.Logf("[persist] 上级目录自动创建并保存重载成功: %s", path)

	// 再次保存（覆盖已有文件）后原内容被原子替换，新状态可读
	if _, err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveToFile(path); err != nil {
		t.Fatalf("覆盖保存应成功: %v", err)
	}
	r3, err := LoadKeyRingFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(r3.ListInfos()); got != 2 {
		t.Fatalf("覆盖保存后重载代数错误: %d", got)
	}
}

// TestPruneAndPhasePersistedAcrossReload 清理结果与细分阶段在落盘重载后原样恢复。
func TestPruneAndPhasePersistedAcrossReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ring.json")

	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("pruned-gen"))
	k2, _ := r.Rotate()
	c2, _ := r.Seal("alice", []byte("retained-gen"))
	k3, _ := r.Rotate()
	if _, err := r.Prune(k1.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveToFile(path); err != nil {
		t.Fatal(err)
	}

	r2, err := LoadKeyRingFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 阶段恢复：k2 retained，k3 active 当前
	i2, _ := r2.Info(k2.ID)
	i3, _ := r2.Info(k3.ID)
	t.Logf("[persist] 重载后: key=%s state=%s; key=%s state=%s current=%v",
		k2.ID, i2.State, k3.ID, i3.State, i3.Current)
	if i2.State != StateRetained || i3.State != StateActive || !i3.Current {
		t.Fatalf("重载后阶段未恢复: %+v %+v", i2, i3)
	}
	// 清理结果恢复：已清理代仍是 pruned 而非 unknown_key
	_, _, err = r2.Open("alice", c1)
	expectFail(t, "open-pruned-after-reload", k1.ID, err, ReasonPruned)
	// retained 代历史密文照常
	if pt, kid, err := r2.Open("alice", c2); err != nil || kid != k2.ID || string(pt) != "retained-gen" {
		t.Fatalf("重载后 retained 代解封失败: %v", err)
	}
	st := r2.Stats()
	t.Logf("[persist] 重载后统计: %+v", st)
	if st.Pruned != 1 || st.Retained != 1 || st.Active != 1 {
		t.Fatalf("重载后统计错误: %+v", st)
	}
}

// legacySnapshot 构造旧版（无 retained 阶段、无 pruned 字段）格式的快照 JSON。
func legacySnapshot(currentID string, nextVer int, keys ...*storedKey) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"current_id":%q,"next_version":%d,"keys":[`, currentID, nextVer)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":%q,"version":%d,"state":%q,"key":%q,"created_at":%d}`,
			k.ID, k.Version, k.State, base64.StdEncoding.EncodeToString(k.Key), k.CreatedAt)
	}
	b.WriteString("]}")
	return b.String()
}

// TestLegacySnapshotCompat 旧版快照继续可读：非当前的 active 密钥按新语义
// 判定为 retained，清理字段缺失视为无清理记录。
func TestLegacySnapshotCompat(t *testing.T) {
	mk := func(id string, ver int, state string) *storedKey {
		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(len(id) + i)
		}
		return &storedKey{ID: id, Version: ver, State: state, Key: key, CreatedAt: 1000 + int64(ver)}
	}
	snap := legacySnapshot("k-legacy-2", 3,
		mk("k-legacy-1", 1, "active"), // 旧格式中保留旧代也记为 active
		mk("k-legacy-2", 2, "active"),
	)
	t.Logf("[legacy] 输入快照: %s", snap)

	r := New()
	if err := r.LoadState([]byte(snap)); err != nil {
		t.Fatalf("旧版快照必须可读: %v", err)
	}
	i1, _ := r.Info("k-legacy-1")
	i2, _ := r.Info("k-legacy-2")
	t.Logf("[legacy] 加载后: k-legacy-1 state=%s current=%v; k-legacy-2 state=%s current=%v",
		i1.State, i1.Current, i2.State, i2.Current)
	if i1.State != StateRetained {
		t.Fatalf("旧快照中非当前 active 密钥应判定为 retained，实际 %s", i1.State)
	}
	if i2.State != StateActive || !i2.Current {
		t.Fatalf("旧快照当前密钥应为 active 当前代，实际 %+v", i2)
	}
	// 加载后行为自洽：新封装用当前代，旧代密文可解
	ct, err := r.Seal("alice", []byte("after-legacy-load"))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := decodeEnvelope(ct)
	if env.Header.KeyID != "k-legacy-2" {
		t.Fatalf("旧快照加载后新封装密钥错误: %s", env.Header.KeyID)
	}
	if _, kid, err := r.Open("alice", ct); err != nil || kid != "k-legacy-2" {
		t.Fatalf("旧快照加载后解封失败: %v", err)
	}
	// 版本计数不回退：再轮换版本号必须大于旧快照最大版本
	nk, _ := r.Rotate()
	if nk.Version != 3 {
		t.Fatalf("旧快照加载后版本计数错误: %d", nk.Version)
	}
}

// TestContradictorySnapshotRejected 自相矛盾或字段冲突的快照必须明确拒绝，
// 且不得把环恢复成不自洽状态。
func TestContradictorySnapshotRejected(t *testing.T) {
	mk := func(id string, ver int, state string) *storedKey {
		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(ver + i)
		}
		return &storedKey{ID: id, Version: ver, State: state, Key: key, CreatedAt: 1}
	}
	keyJSON := func(k *storedKey) string {
		return fmt.Sprintf(`{"id":%q,"version":%d,"state":%q,"key":%q,"created_at":1}`,
			k.ID, k.Version, k.State, base64.StdEncoding.EncodeToString(k.Key))
	}
	k1 := mk("k-a", 1, "active")
	k2 := mk("k-b", 2, "active")

	cases := map[string]string{
		// 当前指针指向 retained 密钥
		"current-is-retained": `{"current_id":"k-a","next_version":3,"keys":[` +
			strings.Replace(keyJSON(k1), `"active"`, `"retained"`, 1) + `,` + keyJSON(k2) + `]}`,
		// 当前指针指向 revoked 密钥
		"current-is-revoked": `{"current_id":"k-a","next_version":3,"keys":[` +
			strings.Replace(keyJSON(k1), `"active"`, `"revoked"`, 1) + `,` + keyJSON(k2) + `]}`,
		// 快照内标识重复
		"duplicate-key-id": `{"current_id":"k-b","next_version":3,"keys":[` + keyJSON(k1) + `,` + keyJSON(k1) + `,` + keyJSON(k2) + `]}`,
		// 密钥与墓碑冲突
		"key-tombstone-conflict": `{"current_id":"k-b","next_version":3,"keys":[` + keyJSON(k1) + `,` + keyJSON(k2) + `],"pruned":[{"id":"k-a","pruned_at":5}]}`,
		// 当前指针指向已清理密钥
		"current-is-pruned": `{"current_id":"k-c","next_version":3,"keys":[` + keyJSON(k1) + `,` + keyJSON(k2) + `],"pruned":[{"id":"k-c","pruned_at":5}]}`,
		// 版本计数回退
		"version-rollback": `{"current_id":"k-b","next_version":1,"keys":[` + keyJSON(k1) + `,` + keyJSON(k2) + `]}`,
		// 未知状态枚举
		"unknown-state": `{"current_id":"k-b","next_version":3,"keys":[` +
			strings.Replace(keyJSON(k1), `"active"`, `"archived"`, 1) + `,` + keyJSON(k2) + `]}`,
		// 墓碑标识重复
		"duplicate-tombstone": `{"current_id":"k-b","next_version":3,"keys":[` + keyJSON(k1) + `,` + keyJSON(k2) + `],"pruned":[{"id":"k-x","pruned_at":1},{"id":"k-x","pruned_at":2}]}`,
	}
	for name, snap := range cases {
		r := New()
		if _, err := r.Rotate(); err != nil {
			t.Fatal(err)
		}
		before := len(r.ListInfos())
		err := r.LoadState([]byte(snap))
		expectFail(t, "load-contradictory/"+name, "", err, ReasonMalformed)
		if got := len(r.ListInfos()); got != before {
			t.Fatalf("case=%s 拒绝矛盾快照后环内容被污染: before=%d after=%d", name, before, got)
		}
	}
}

// TestSaveFailureKeepsOriginalFile 保存链路失败时，原有状态文件必须仍然可用、内容不被破坏。
func TestSaveFailureKeepsOriginalFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 绕过目录权限，无法模拟写入失败")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ring.json")

	r := New()
	k1, _ := r.Rotate()
	ct, _ := r.Seal("alice", []byte("original-content"))
	if err := r.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)

	// 使目录只读：临时文件创建失败，保存必须报错且原文件字节不变
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	err := r.SaveToFile(path)
	if err == nil {
		t.Fatal("目录只读时保存必须失败")
	}
	t.Logf("[persist] 只读目录保存被拒绝: %v", err)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("保存失败后原状态文件内容被破坏")
	}

	// 原文件仍可正常加载、解封
	r2, err := LoadKeyRingFromFile(path)
	if err != nil {
		t.Fatalf("保存失败后原文件必须仍可用: %v", err)
	}
	if pt, kid, err := r2.Open("alice", ct); err != nil || kid != k1.ID || string(pt) != "original-content" {
		t.Fatalf("保存失败后原文件解封失败: %v", err)
	}
	t.Logf("[persist] 保存失败后原文件完好，key=%s 解封正常", k1.ID)
}

// TestSaveToExistingDirectoryPath 目标路径被非空目录占用时替换失败，返回明确错误。
func TestSaveToExistingDirectoryPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "occupied")
	if err := os.MkdirAll(filepath.Join(path, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := New()
	if _, err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveToFile(path); err == nil {
		t.Fatal("目标被非空目录占用时保存必须失败")
	} else {
		t.Logf("[persist] 替换失败被明确报告: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
		t.Fatalf("替换失败后原目录必须保持原样: %v %v", fi, err)
	}
}
