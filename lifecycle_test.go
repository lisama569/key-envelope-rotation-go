package keyring

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLifecycleStages 验证轮换后旧代降级为 retained，只有 current 能新封装。
func TestLifecycleStages(t *testing.T) {
	clock := func() int64 { return 1000 }
	r := NewWithClock(clock)

	k1, err := r.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if k1.State != StateCurrent {
		t.Fatalf("首次轮换后应为 current，实际=%s", k1.State)
	}
	c1, _ := r.Seal("alice", []byte("gen-1"))

	k2, err := r.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if k2.State != StateCurrent {
		t.Fatalf("新一代应为 current，实际=%s", k2.State)
	}
	i1, ok := r.Info(k1.ID)
	if !ok || i1.State != StateRetained {
		t.Fatalf("旧代应降级为 retained: %+v ok=%v", i1, ok)
	}
	t.Logf("[阶段迁移] key=%s v1 -> retained, key=%s v2 -> current", k1.ID, k2.ID)

	k3, _ := r.Rotate()
	i2, _ := r.Info(k2.ID)
	if i2.State != StateRetained {
		t.Fatalf("再次轮换后 k2 应为 retained，实际=%s", i2.State)
	}
	if cur, ok := r.CurrentKeyID(); !ok || cur != k3.ID {
		t.Fatalf("当前指针错误: %q ok=%v", cur, ok)
	}

	// 历史密文仍可由 retained 旧代解封
	pt, kid, err := r.Open("alice", c1)
	if err != nil || kid != k1.ID || string(pt) != "gen-1" {
		t.Fatalf("retained 旧代解封失败: kid=%s err=%v", kid, err)
	}
	t.Logf("[阶段迁移] retained key=%s 历史密文解封正常, 明文=%q", kid, pt)

	// 诊断视图中每个世代阶段一目了然，且恰好一个 current
	st := r.Stats()
	if st != (Stats{Total: 3, Current: 1, Retained: 2, Revoked: 0, Retired: 0}) {
		t.Fatalf("计数视图错误: %+v", st)
	}
	dump, _ := json.Marshal(r.ListInfos())
	t.Logf("[诊断] 阶段视图=%s 计数=%+v", dump, st)

	// 吊销 retained 旧代：其密文被稳定拒绝，阶段变 revoked
	if _, err := r.Revoke(k1.ID); err != nil {
		t.Fatal(err)
	}
	_, _, err = r.Open("alice", c1)
	expectFail(t, "open-revoked-retained", k1.ID, err, ReasonRevoked)
	if got := r.Stats(); got.Revoked != 1 || got.Retained != 1 {
		t.Fatalf("吊销后计数错误: %+v", got)
	}
}

// TestRetireGeneration 验证按代清理：当前代受保护，清理后历史密文得到 key_retired 判定。
func TestRetireGeneration(t *testing.T) {
	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("will-be-retired"))
	k2, _ := r.Rotate()
	c2, _ := r.Seal("alice", []byte("still-here"))

	// 当前世代不允许清理
	err := r.Retire(k2.ID)
	expectFail(t, "retire-current", k2.ID, err, ReasonCurrentKeyProtected)
	t.Logf("[清理] 当前 key=%s 受保护，拒绝清理", k2.ID)

	// 清理旧代
	if err := r.Retire(k1.ID); err != nil {
		t.Fatalf("清理旧代失败: %v", err)
	}
	t.Logf("[清理] retained key=%s 已清理（材料删除，留下墓碑）", k1.ID)

	// 诊断：旧代从 Info/ListInfos 消失，但墓碑计数可见
	if _, ok := r.Info(k1.ID); ok {
		t.Fatal("已清理世代不应再出现在 Info 中")
	}
	for _, info := range r.ListInfos() {
		if info.ID == k1.ID {
			t.Fatal("已清理世代不应再出现在 ListInfos 中")
		}
	}
	st := r.Stats()
	if st.Total != 1 || st.Retired != 1 || st.Current != 1 {
		t.Fatalf("清理后计数错误: %+v", st)
	}
	t.Logf("[清理后诊断] 剩余世代=%d, 墓碑=%d, 视图=%+v", st.Total, st.Retired, r.ListInfos())

	// 被清理世代的历史密文：稳定的 key_retired，不是 malformed/tampered，也不会误用 k2
	_, _, err = r.Open("alice", c1)
	expectFail(t, "open-retired", k1.ID, err, ReasonKeyRetired)

	// 其他世代密文不受牵连
	pt, kid, err := r.Open("alice", c2)
	if err != nil || kid != k2.ID || string(pt) != "still-here" {
		t.Fatalf("清理旧代牵连当前代密文: pt=%q kid=%s err=%v", pt, kid, err)
	}
	t.Logf("[清理] key=%s 密文仍正常解封，跨代无误用", k2.ID)

	// 幂等/未知标识的边界
	err = r.Retire(k1.ID)
	expectFail(t, "retire-again", k1.ID, err, ReasonKeyRetired)
	err = r.Retire("k-never-existed")
	expectFail(t, "retire-unknown", "k-never-existed", err, ReasonUnknownKey)

	// 清理已吊销世代同样允许
	if _, err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Revoke(k2.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.Retire(k2.ID); err != nil {
		t.Fatalf("清理已吊销世代应成功: %v", err)
	}
}

// TestConcurrentRetireRotateSealOpen 并发清理/轮换/封解封下不得出现状态撕裂或跨密钥误用。
func TestConcurrentRetireRotateSealOpen(t *testing.T) {
	r := New()
	k0, _ := r.Rotate()

	const workers = 12
	const rounds = 150
	var wg sync.WaitGroup
	var mu sync.Mutex
	sealedList := make(map[string][][]byte) // kid -> 密文列表
	var failMu sync.Mutex
	failReasons := map[Reason]int{}
	addFail := func(rc Reason) {
		failMu.Lock()
		failReasons[rc]++
		failMu.Unlock()
	}

	// 轮换者：每次轮换后，上一代随即可能被清理者回收
	wg.Add(1)
	go func() {
		defer wg.Done()
		var prev string
		for i := 0; i < 10; i++ {
			info, err := r.Rotate()
			if err != nil {
				addFail(reasonOf(err))
				continue
			}
			if prev != "" {
				if err := r.Retire(prev); err != nil {
					// 仅允许“已被清理/已不存在”这类确定性结果
					rc := reasonOf(err)
					if rc != ReasonKeyRetired && rc != ReasonUnknownKey {
						failMu.Lock()
						t.Errorf("轮换后清理旧代出现非预期错误: %v", err)
						failMu.Unlock()
					}
					addFail(rc)
				} else {
					t.Logf("[并发清理] key=%s 已回收, 新当前 key=%s", prev, info.ID)
				}
			}
			prev = info.ID
			time.Sleep(time.Millisecond)
		}
	}()

	// 独立清理者：随机清理所有非当前世代
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			cur, _ := r.CurrentKeyID()
			for _, info := range r.ListInfos() {
				if info.ID != cur && (info.State == StateRetained || info.State == StateRevoked) {
					if err := r.Retire(info.ID); err != nil {
						rc := reasonOf(err)
						if rc != ReasonCurrentKeyProtected && rc != ReasonKeyRetired && rc != ReasonUnknownKey {
							failMu.Lock()
							t.Errorf("并发清理出现非预期错误: %v", err)
							failMu.Unlock()
						}
						addFail(rc)
					}
				}
			}
			time.Sleep(time.Millisecond)
		}
	}()

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				pt := []byte(fmt.Sprintf("worker-%d-msg-%d", w, i))
				ct, err := r.Seal("alice", pt)
				if err != nil {
					addFail(reasonOf(err))
					continue
				}
				env, derr := decodeEnvelope(ct)
				if derr != nil {
					failMu.Lock()
					t.Errorf("并发封装密文无法解码: %v", derr)
					failMu.Unlock()
					continue
				}
				mu.Lock()
				sealedList[env.Header.KeyID] = append(sealedList[env.Header.KeyID], ct)
				mu.Unlock()

				// 立即解封：要么成功且 kid 严格匹配，要么得到可解释的确定性拒绝
				gpt, gkid, gerr := r.Open("alice", ct)
				if gerr != nil {
					rc := reasonOf(gerr)
					if rc != ReasonKeyRetired && rc != ReasonRevoked && rc != ReasonUnknownKey {
						failMu.Lock()
						t.Errorf("并发解封出现不可解释错误 kid=%s: %v", env.Header.KeyID, gerr)
						failMu.Unlock()
					}
					addFail(rc)
					continue
				}
				if gkid != env.Header.KeyID {
					failMu.Lock()
					t.Errorf("跨密钥误用: 密文 kid=%s 实际用 %s 解封", env.Header.KeyID, gkid)
					failMu.Unlock()
				}
				if string(gpt) != string(pt) {
					failMu.Lock()
					t.Errorf("解封明文错误: %q vs %q", gpt, pt)
					failMu.Unlock()
				}
			}
		}(w)
	}
	wg.Wait()

	if len(sealedList) == 0 {
		t.Fatal("并发场景下没有成功产生任何密文")
	}
	// 终态复核：仍在环内的密钥密文必须可解；已清理/吊销/缺失的必须确定性拒绝
	for kid, cts := range sealedList {
		for _, ct := range cts {
			pt, used, err := r.Open("alice", ct)
			if err != nil {
				rc := reasonOf(err)
				if rc != ReasonKeyRetired && rc != ReasonRevoked && rc != ReasonUnknownKey {
					t.Fatalf("终态复核 kid=%s 出现不可解释错误: %v", kid, err)
				}
				continue
			}
			if used != kid || !strings.HasPrefix(string(pt), "worker-") {
				t.Fatalf("终态复核结果错误: used=%s kid=%s pt=%q", used, kid, pt)
			}
		}
	}
	t.Logf("[并发结束] 初始key=%s, 失败分类=%v, 终态计数=%+v", k0.ID, failReasons, r.Stats())
}

// TestSaveCreatesMissingParentDir 上级目录不存在时也能保存并完整重载。
func TestSaveCreatesMissingParentDir(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "nested", "deep", "ring.json")

	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("gen-1"))
	k2, _ := r.Rotate()
	if _, err := r.Revoke(k1.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.Retire(k1.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveToFile(path); err != nil {
		t.Fatalf("上级目录不存在时保存失败: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("文件/权限错误: %v %v", fi, err)
	}

	r2, err := LoadKeyRingFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cur, ok := r2.CurrentKeyID()
	if !ok || cur != k2.ID {
		t.Fatalf("重载后当前世代错误: %q ok=%v", cur, ok)
	}
	// 生命周期阶段与清理结果原样恢复
	if i2, ok := r2.Info(k2.ID); !ok || i2.State != StateCurrent {
		t.Fatalf("重载后 current 阶段丢失: %+v", i2)
	}
	if _, ok := r2.Info(k1.ID); ok {
		t.Fatal("已清理世代重载后不应作为存活条目出现")
	}
	_, _, err = r2.Open("alice", c1)
	expectFail(t, "reload-open-retired", k1.ID, err, ReasonKeyRetired)
	st := r2.Stats()
	if st.Current != 1 || st.Retired != 1 || st.Total != 1 {
		t.Fatalf("重载后计数错误: %+v", st)
	}
	t.Logf("[目录自建+重载] path=%s 计数=%+v, 已清理 key=%s 判定稳定", path, st, k1.ID)
}

// TestSaveAtomicReplaceFailure rename 失败时原文件必须仍然可用、内容不被破坏。
func TestSaveAtomicReplaceFailure(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "ring.json")

	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("original"))
	if err := r.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// 把目标路径变成一个目录：rename 到目录必然失败（ENOTDIR/EISDIR）。
	dirAsFile := filepath.Join(base, "adir.json")
	if err := os.Mkdir(dirAsFile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveToFile(dirAsFile); err == nil {
		t.Fatal("目标为目录时保存必须失败")
	} else {
		t.Logf("[原子替换] 目标为目录，保存按预期失败: %v", err)
	}
	// 失败后目录仍可用，且原文件内容完好
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(orig) {
		t.Fatalf("替换失败后原文件被破坏: err=%v", err)
	}
	// 不残留临时文件
	matches, _ := filepath.Glob(filepath.Join(base, ".keyring-*.tmp"))
	if len(matches) != 0 {
		t.Fatalf("失败后残留临时文件: %v", matches)
	}
	// 原文件仍可加载、密文仍可解封
	r2, err := LoadKeyRingFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pt, kid, err := r2.Open("alice", c1)
	if err != nil || kid != k1.ID || string(pt) != "original" {
		t.Fatalf("原文件可用性受损: pt=%q kid=%s err=%v", pt, kid, err)
	}
	t.Logf("[原子替换] 失败后原文件完好且可加载, key=%s 明文=%q", kid, pt)
}

// TestLegacyV1SnapshotCompatibility 旧版（active/revoked）快照继续可读，阶段按新语义判定。
func TestLegacyV1SnapshotCompatibility(t *testing.T) {
	// 先用当前实现生成一把真实密钥材料与一条旧版密文，再手工构造 v1 快照。
	src := New()
	k1, _ := src.Rotate()
	c1, _ := src.Seal("alice", []byte("legacy-gen-1"))
	k2, _ := src.Rotate()
	c2, _ := src.Seal("alice", []byte("legacy-gen-2"))

	src.mu.RLock()
	m1 := append([]byte(nil), src.entries[k1.ID].Key...)
	m2 := append([]byte(nil), src.entries[k2.ID].Key...)
	src.mu.RUnlock()

	v1 := fmt.Sprintf(`{
  "current_id": %q,
  "next_version": 3,
  "keys": [
    {"id": %q, "version": 1, "state": "active", "key": %s, "created_at": 111},
    {"id": %q, "version": 2, "state": "active", "key": %s, "created_at": 222}
  ]
}`, k2.ID, k1.ID, json.RawMessage(mustJSON(t, m1)), k2.ID, json.RawMessage(mustJSON(t, m2)))

	r := New()
	if err := r.LoadState([]byte(v1)); err != nil {
		t.Fatalf("旧版快照加载失败: %v", err)
	}
	i1, _ := r.Info(k1.ID)
	i2, _ := r.Info(k2.ID)
	if i1.State != StateRetained || i2.State != StateCurrent {
		t.Fatalf("旧版 active 归一化错误: k1=%s k2=%s", i1.State, i2.State)
	}
	t.Logf("[旧快照兼容] active: 旧代 key=%s -> retained, 当前 key=%s -> current", k1.ID, k2.ID)

	// 旧代历史密文可解封；新封装用 current
	pt, kid, err := r.Open("alice", c1)
	if err != nil || kid != k1.ID || string(pt) != "legacy-gen-1" {
		t.Fatalf("旧快照旧代密文解封错误: %v", err)
	}
	c3, err := r.Seal("alice", []byte("after-legacy-load"))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := decodeEnvelope(c3)
	if env.Header.KeyID != k2.ID {
		t.Fatalf("旧快照加载后新封装误用密钥: %s", env.Header.KeyID)
	}
	if _, _, err := r.Open("alice", c2); err != nil {
		t.Fatalf("旧快照当前代密文应可解封: %v", err)
	}

	// 含吊销世代的旧快照：revoked 语义保持，且 current 不得指向吊销世代
	v1rev := fmt.Sprintf(`{
  "current_id": "",
  "next_version": 2,
  "keys": [
    {"id": %q, "version": 1, "state": "revoked", "key": %s, "created_at": 111, "revoked_at": 333}
  ]
}`, k1.ID, json.RawMessage(mustJSON(t, m1)))
	r2 := New()
	if err := r2.LoadState([]byte(v1rev)); err != nil {
		t.Fatalf("含吊销的旧快照应可加载: %v", err)
	}
	if info, _ := r2.Info(k1.ID); info.State != StateRevoked {
		t.Fatalf("旧快照 revoked 状态错误: %s", info.State)
	}
	_, _, err = r2.Open("alice", c1)
	expectFail(t, "legacy-revoked-open", k1.ID, err, ReasonRevoked)
}

func mustJSON(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRejectContradictorySnapshots 内部自相矛盾/字段冲突的快照必须被明确拒绝。
func TestRejectContradictorySnapshots(t *testing.T) {
	src := New()
	k, _ := src.Rotate()
	src.mu.RLock()
	material := append([]byte(nil), src.entries[k.ID].Key...)
	src.mu.RUnlock()
	keyJSON := string(mustJSON(t, material))

	cases := map[string]string{
		"unknown-format":       `{"format_version":99,"current_id":"","next_version":1,"keys":[]}`,
		"duplicate-id":         fmt.Sprintf(`{"format_version":2,"keys":[{"id":"dup","version":1,"state":"retained","key":%s},{"id":"dup","version":2,"state":"current","key":%s}],"current_id":"dup","next_version":3}`, keyJSON, keyJSON),
		"duplicate-version":    fmt.Sprintf(`{"format_version":2,"keys":[{"id":"a","version":1,"state":"retained","key":%s},{"id":"b","version":1,"state":"current","key":%s}],"current_id":"b","next_version":2}`, keyJSON, keyJSON),
		"bad-key-length":       fmt.Sprintf(`{"format_version":2,"keys":[{"id":"%s","version":1,"state":"current","key":"c2hvcnQ="}],"current_id":"%s"}`, k.ID, k.ID),
		"unknown-state":        fmt.Sprintf(`{"format_version":2,"keys":[{"id":"%s","version":1,"state":"frozen","key":%s}],"current_id":"%s"}`, k.ID, keyJSON, k.ID),
		"current-not-current":  fmt.Sprintf(`{"format_version":2,"keys":[{"id":"%s","version":1,"state":"retained","key":%s}],"current_id":"%s"}`, k.ID, keyJSON, k.ID),
		"current-revoked":      fmt.Sprintf(`{"format_version":2,"keys":[{"id":"%s","version":1,"state":"revoked","key":%s,"revoked_at":9}],"current_id":"%s"}`, k.ID, keyJSON, k.ID),
		"current-missing":      fmt.Sprintf(`{"format_version":2,"keys":[{"id":"other","version":1,"state":"current","key":%s}],"current_id":"ghost","next_version":2}`, keyJSON),
		"current-retired":      fmt.Sprintf(`{"format_version":2,"keys":[{"id":"other","version":1,"state":"current","key":%s}],"current_id":"ghost","next_version":2,"retired":[{"id":"ghost","retired_at":9}]}`, keyJSON),
		"tombstone-live":       fmt.Sprintf(`{"format_version":2,"keys":[{"id":"%s","version":1,"state":"current","key":%s}],"current_id":"%s","next_version":2,"retired":[{"id":"%s","retired_at":9}]}`, k.ID, keyJSON, k.ID, k.ID),
		"duplicate-tombstone":  fmt.Sprintf(`{"format_version":2,"keys":[{"id":"other","version":1,"state":"current","key":%s}],"current_id":"other","next_version":2,"retired":[{"id":"gone","retired_at":9},{"id":"gone","retired_at":10}]}`, keyJSON),
		"revoked-at-on-live":   fmt.Sprintf(`{"format_version":2,"keys":[{"id":"%s","version":1,"state":"current","key":%s,"revoked_at":9}],"current_id":"%s"}`, k.ID, keyJSON, k.ID),
		"v1-active-revoked-at": fmt.Sprintf(`{"keys":[{"id":"%s","version":1,"state":"active","key":%s,"revoked_at":9}],"current_id":"%s"}`, k.ID, keyJSON, k.ID),
	}

	for name, snap := range cases {
		r := New()
		err := r.LoadState([]byte(snap))
		if err == nil {
			t.Errorf("case=%s 自相矛盾的快照必须被拒绝", name)
			continue
		}
		var e *Error
		if !errors.As(err, &e) {
			t.Errorf("case=%s 错误必须归类为 *Error: %v", name, err)
			continue
		}
		t.Logf("[矛盾快照/%s] -> reason=%q, err=%v", name, e.Reason, err)
	}

	// 加载失败不得污染既有密钥环（原子提交）
	base := New()
	bk, _ := base.Rotate()
	before := base.Stats()
	_ = base.LoadState([]byte(cases["tombstone-live"]))
	after := base.Stats()
	if after != before {
		t.Fatalf("加载失败后密钥环被污染: before=%+v after=%+v", before, after)
	}
	if _, ok := base.Info(k.ID); ok {
		t.Fatal("加载失败后不应出现快照中的条目")
	}
	if cur, ok := base.CurrentKeyID(); !ok || cur != bk.ID {
		t.Fatalf("加载失败后当前指针被改动: %q ok=%v", cur, ok)
	}
	t.Logf("[矛盾快照] 拒绝后密钥环保持原状: %+v", after)
}

// TestV2RoundTripPreservesStages 完整 v2 往返：阶段、墓碑、计数一致。
func TestV2RoundTripPreservesStages(t *testing.T) {
	r := New()
	k1, _ := r.Rotate()
	k2, _ := r.Rotate()
	k3, _ := r.Rotate()
	_, _ = r.Revoke(k1.ID)
	if err := r.Retire(k1.ID); err != nil {
		t.Fatal(err)
	}

	data, err := r.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"format_version": 2`) {
		t.Fatalf("导出不是 v2 格式: %s", data)
	}
	// 诊断安全：Infos 视图不含 key 字段；快照含材料但仅供本地
	infoDump, _ := json.Marshal(r.ListInfos())
	if strings.Contains(string(infoDump), `"key"`) {
		t.Fatal("诊断视图中不得出现 key 字段")
	}

	r2 := New()
	if err := r2.LoadState(data); err != nil {
		t.Fatal(err)
	}
	i2, _ := r2.Info(k2.ID)
	i3, _ := r2.Info(k3.ID)
	if i2.State != StateRetained || i3.State != StateCurrent {
		t.Fatalf("往返阶段错误: k2=%s k3=%s", i2.State, i3.State)
	}
	if s := r2.Stats(); s != (Stats{Total: 2, Current: 1, Retained: 1, Revoked: 0, Retired: 1}) {
		t.Fatalf("往返计数错误: %+v", s)
	}
	t.Logf("[v2往返] 阶段与墓碑完整恢复: %+v", r2.Stats())
}

// TestLoadStateMergeSemantics 合并加载：空 current_id 不覆盖既有当前指针；冲突拒绝。
func TestLoadStateMergeSemantics(t *testing.T) {
	src := New()
	k1, _ := src.Rotate()
	k2, _ := src.Rotate()
	src.mu.RLock()
	m1 := append([]byte(nil), src.entries[k1.ID].Key...)
	m2 := append([]byte(nil), src.entries[k2.ID].Key...)
	src.mu.RUnlock()

	// 目标环已有自己的当前世代
	dst := New()
	dk, _ := dst.Rotate()

	// 快照带空 current_id 的 v2 数据（含一个 retained 世代）
	snap := fmt.Sprintf(`{"format_version":2,"current_id":"","next_version":3,
"keys":[{"id":"x1","version":1,"state":"retained","key":%s,"created_at":1}]}`,
		mustJSON(t, m1))
	if err := dst.LoadState([]byte(snap)); err != nil {
		t.Fatal(err)
	}
	if cur, ok := dst.CurrentKeyID(); !ok || cur != dk.ID {
		t.Fatalf("空 current_id 不应覆盖既有当前指针: %q ok=%v", cur, ok)
	}

	// 与既有条目标识冲突必须拒绝
	conflict := fmt.Sprintf(`{"format_version":2,"current_id":"","keys":[{"id":%q,"version":9,"state":"retained","key":%s}]}`,
		dk.ID, mustJSON(t, append([]byte(nil), dst.entries[dk.ID].Key...)))
	if err := dst.LoadState([]byte(conflict)); err == nil || reasonOf(err) != ReasonMalformed {
		t.Fatalf("与既有条目冲突应拒绝 malformed: %v", err)
	}

	// 给目标环制造一个墓碑（锁内直接构造），再加载同 id 的存活条目/墓碑都必须拒绝
	dst.mu.Lock()
	dst.retired["ghost-id"] = 123
	dst.mu.Unlock()
	liveGhost := fmt.Sprintf(`{"format_version":2,"current_id":"ghost-id","keys":[{"id":"ghost-id","version":10,"state":"current","key":%s}]}`, mustJSON(t, m2))
	if err := dst.LoadState([]byte(liveGhost)); err == nil || reasonOf(err) != ReasonMalformed {
		t.Fatalf("墓碑与存活条目冲突应拒绝: %v", err)
	}
	tombGhost := `{"format_version":2,"current_id":"","retired":[{"id":"ghost-id","retired_at":1}]}`
	if err := dst.LoadState([]byte(tombGhost)); err == nil || reasonOf(err) != ReasonMalformed {
		t.Fatalf("墓碑与既有墓碑冲突应拒绝: %v", err)
	}
	t.Logf("[合并加载] 空 current_id 保留当前 key=%s，标识冲突全部按 malformed 拒绝", dk.ID)
}
