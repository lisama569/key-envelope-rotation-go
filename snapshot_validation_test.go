package keyring

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// storedSnapshot 与持久化结构同源，便于测试直接构造合法/非法快照。
func mustMarshalSnapshot(t *testing.T, st *storedState) []byte {
	t.Helper()
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("构造快照失败: %v", err)
	}
	return data
}

// testKey 构造一条指定版本/阶段的密钥，revokedAt 为 0 时不带吊销时间。
func testKey(id string, ver int, state KeyState, revokedAt int64) *storedKey {
	key := make([]byte, keySize)
	for i := range key {
		key[i] = byte(ver*7 + i)
	}
	return &storedKey{
		ID:        id,
		Version:   ver,
		State:     string(state),
		Key:       key,
		CreatedAt: 1000 + int64(ver),
		RevokedAt: revokedAt,
	}
}

// ringDigest 在锁内生成环的确定性摘要：密钥、阶段、吊销时间、当前指针、
// 版本计数、清理墓碑全部包含，用于断言“拒绝不污染现有环”。
func ringDigest(r *KeyRing) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var b strings.Builder
	fmt.Fprintf(&b, "current=%q next=%d\n", r.current, r.nextVersion)
	for _, id := range ids {
		e := r.entries[id]
		fmt.Fprintf(&b, "key id=%s ver=%d state=%s created=%d revoked=%d keylen=%d\n",
			e.ID, e.Version, e.State, e.CreatedAt, e.RevokedAt, len(e.Key))
	}
	pids := make([]string, 0, len(r.pruned))
	for id := range r.pruned {
		pids = append(pids, id)
	}
	sort.Strings(pids)
	for _, id := range pids {
		fmt.Fprintf(&b, "tomb id=%s pruned_at=%d\n", id, r.pruned[id])
	}
	return b.String()
}

// TestSnapshotVersionValidation 覆盖版本号唯一性/合法性：
// 快照内重复、版本为 0、版本为负数、与环内既有代版本冲突，一律加载阶段拒绝。
func TestSnapshotVersionValidation(t *testing.T) {
	cases := map[string]struct {
		build func() []byte
		// ringSetup 在非空环上预置内容（用于验证与环内版本冲突）
		ringSetup func(r *KeyRing)
		msgHint   string // 错误说明应包含的归类关键词
	}{
		"duplicate-version-in-snapshot": {
			build: func() []byte {
				return mustMarshalSnapshot(t, &storedState{
					CurrentID: "k-b", NextVer: 6,
					Keys: []*storedKey{
						testKey("k-a", 5, StateRetained, 0),
						testKey("k-b", 5, StateActive, 0), // 与 k-a 同版本
					},
				})
			},
			msgHint: "版本号重复",
		},
		"zero-version": {
			build: func() []byte {
				return mustMarshalSnapshot(t, &storedState{
					CurrentID: "k-a", NextVer: 3,
					Keys: []*storedKey{testKey("k-a", 0, StateActive, 0)},
				})
			},
			msgHint: "版本号非法",
		},
		"negative-version": {
			build: func() []byte {
				return mustMarshalSnapshot(t, &storedState{
					CurrentID: "k-a", NextVer: 3,
					Keys: []*storedKey{testKey("k-a", -4, StateActive, 0)},
				})
			},
			msgHint: "版本号非法",
		},
		"duplicate-version-with-existing-ring": {
			ringSetup: func(r *KeyRing) {
				if _, err := r.Rotate(); err != nil { // 环内已有 version=1
					t.Fatal(err)
				}
			},
			build: func() []byte {
				// 新标识但版本号 1 与环内当前代冲突
				return mustMarshalSnapshot(t, &storedState{
					CurrentID: "", NextVer: 5,
					Keys: []*storedKey{testKey("k-foreign", 1, StateRetained, 0)},
				})
			},
			msgHint: "版本号与环内既有密钥重复",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := New()
			if tc.ringSetup != nil {
				tc.ringSetup(r)
			}
			before := ringDigest(r)
			statsBefore := r.Stats()
			err := r.LoadState(tc.build())
			if err == nil {
				t.Fatalf("[load-version/%s] 非法版本号快照必须被拒绝，实际加载成功", name)
			}
			if reasonOf(err) != ReasonMalformed {
				t.Fatalf("[load-version/%s] 拒绝原因应为 malformed，实际 reason=%q err=%v",
					name, reasonOf(err), err)
			}
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("[load-version/%s] errors.Is(ErrMalformed) 归类失败: %v", name, err)
			}
			if !strings.Contains(err.Error(), tc.msgHint) {
				t.Fatalf("[load-version/%s] 错误说明缺少归类关键词 %q: %v", name, tc.msgHint, err)
			}
			t.Logf("[load-version/%s] 按预期拒绝 -> reason=%q, err=%v", name, reasonOf(err), err)
			if got := ringDigest(r); got != before {
				t.Fatalf("[load-version/%s] 拒绝后环内容被污染:\nbefore=%s\nafter=%s", name, before, got)
			}
			if got := r.Stats(); got != statsBefore {
				t.Fatalf("[load-version/%s] 拒绝后统计被污染: before=%+v after=%+v",
					name, statsBefore, got)
			}
			t.Logf("[load-version/%s] 拒绝后环摘要与统计保持不变", name)
		})
	}
}

// TestSnapshotStateRevokedAtConsistency 覆盖阶段与吊销时间的字段冲突：
// retained/active（含当前代）携带吊销时间、revoked 缺少或携带非法吊销时间，一律拒绝。
func TestSnapshotStateRevokedAtConsistency(t *testing.T) {
	cases := map[string]struct {
		currentID string
		keys      []*storedKey
		msgHint   string
	}{
		"retained-with-revoked-at": {
			currentID: "k-b",
			keys: []*storedKey{
				testKey("k-a", 1, StateRetained, 999), // 保留代不该有吊销时间
				testKey("k-b", 2, StateActive, 0),
			},
			msgHint: "吊销时间冲突",
		},
		"current-active-with-revoked-at": {
			// 当前生效代被手工写上吊销时间：既生效又吊销，语义矛盾
			currentID: "k-a",
			keys:      []*storedKey{testKey("k-a", 1, StateActive, 999)},
			msgHint:   "吊销时间冲突",
		},
		"revoked-missing-revoked-at": {
			currentID: "k-b",
			keys: []*storedKey{
				testKey("k-a", 1, StateRevoked, 0), // 已吊销却没有吊销时间
				testKey("k-b", 2, StateActive, 0),
			},
			msgHint: "缺少有效吊销时间",
		},
		"revoked-with-negative-revoked-at": {
			currentID: "k-b",
			keys: []*storedKey{
				testKey("k-a", 1, StateRevoked, -7),
				testKey("k-b", 2, StateActive, 0),
			},
			msgHint: "缺少有效吊销时间",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			snap := mustMarshalSnapshot(t, &storedState{
				CurrentID: tc.currentID, NextVer: 3, Keys: tc.keys,
			})
			r := New()
			before := ringDigest(r)
			err := r.LoadState(snap)
			if err == nil {
				t.Fatalf("[load-conflict/%s] 阶段与吊销时间冲突的快照必须被拒绝，实际成功", name)
			}
			if reasonOf(err) != ReasonMalformed {
				t.Fatalf("[load-conflict/%s] 拒绝原因应为 malformed，实际 reason=%q err=%v",
					name, reasonOf(err), err)
			}
			if !strings.Contains(err.Error(), tc.msgHint) {
				t.Fatalf("[load-conflict/%s] 错误说明缺少归类关键词 %q: %v", name, tc.msgHint, err)
			}
			t.Logf("[load-conflict/%s] 按预期拒绝 -> reason=%q, err=%v", name, reasonOf(err), err)
			if got := ringDigest(r); got != before {
				t.Fatalf("[load-conflict/%s] 拒绝后空环被污染: after=%s", name, got)
			}
			t.Logf("[load-conflict/%s] 拒绝后环内容保持为空、未被合并", name)
		})
	}
}

// TestRejectedSnapshotLeavesPopulatedRingUntouched 在含多代密钥、吊销与墓碑的
// 非空环上加载多份矛盾快照，断言环的密钥、阶段、吊销时间、当前指针、版本计数、
// 清理墓碑与统计在拒绝后一个字节都不变（拒绝原子、不部分合并）。
func TestRejectedSnapshotLeavesPopulatedRingUntouched(t *testing.T) {
	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("gen-1"))
	k2, _ := r.Rotate()
	c2, _ := r.Seal("alice", []byte("gen-2"))
	if _, err := r.Revoke(k1.ID); err != nil { // k1: revoked 且带吊销时间
		t.Fatal(err)
	}
	if _, err := r.Rotate(); err != nil { // 第三代：k2 降级为 retained
		t.Fatal(err)
	}
	if _, err := r.Prune(k1.ID); err != nil { // k1 进入墓碑
		t.Fatal(err)
	}
	beforeDigest := ringDigest(r)
	beforeStats := r.Stats()
	curBefore, curOK := r.CurrentKeyID()

	badSnapshots := map[string][]byte{
		"dup-version": mustMarshalSnapshot(t, &storedState{
			CurrentID: "x-b", NextVer: 9,
			Keys: []*storedKey{
				testKey("x-a", 7, StateRetained, 0),
				testKey("x-b", 7, StateActive, 0),
			},
		}),
		"zero-version": mustMarshalSnapshot(t, &storedState{
			CurrentID: "x-a", NextVer: 9,
			Keys: []*storedKey{testKey("x-a", 0, StateActive, 0)},
		}),
		"retained-with-revoke-time": mustMarshalSnapshot(t, &storedState{
			CurrentID: "x-b", NextVer: 9,
			Keys: []*storedKey{
				testKey("x-a", 8, StateRetained, 123),
				testKey("x-b", 9, StateActive, 0),
			},
		}),
		"revoked-without-revoke-time": mustMarshalSnapshot(t, &storedState{
			CurrentID: "x-b", NextVer: 9,
			Keys: []*storedKey{
				testKey("x-a", 8, StateRevoked, 0),
				testKey("x-b", 9, StateActive, 0),
			},
		}),
		"version-collides-with-ring": mustMarshalSnapshot(t, &storedState{
			// 版本 3 已被环内当前代 k3 占用
			CurrentID: "", NextVer: 9,
			Keys: []*storedKey{testKey("x-a", 3, StateRetained, 0)},
		}),
		"id-already-in-ring": mustMarshalSnapshot(t, &storedState{
			CurrentID: "", NextVer: 9,
			Keys: []*storedKey{testKey(k2.ID, 8, StateRetained, 0)},
		}),
	}

	for name, snap := range badSnapshots {
		t.Run(name, func(t *testing.T) {
			err := r.LoadState(snap)
			expectFail(t, "load-atomic-reject/"+name, "", err, ReasonMalformed)
			if got := ringDigest(r); got != beforeDigest {
				t.Fatalf("拒绝后环内容被污染:\nbefore=%s\nafter=%s", beforeDigest, got)
			}
			if got := r.Stats(); got != beforeStats {
				t.Fatalf("拒绝后统计被污染: before=%+v after=%+v", beforeStats, got)
			}
			cur, ok := r.CurrentKeyID()
			if ok != curOK || cur != curBefore {
				t.Fatalf("拒绝后当前指针被污染: before=(%q,%v) after=(%q,%v)",
					curBefore, curOK, cur, ok)
			}
			// 行为不变：k3 密文照常可封解，k1 仍为 pruned
			if _, kid, err := r.Open("alice", c2); err != nil || kid != k2.ID {
				t.Fatalf("拒绝后保留代 k2 行为被污染: kid=%s err=%v", kid, err)
			}
			if _, _, err := r.Open("alice", c1); reasonOf(err) != ReasonPruned {
				t.Fatalf("拒绝后墓碑判定被污染: err=%v", err)
			}
			t.Logf("[load-atomic-reject/%s] 拒绝后环摘要/统计/当前指针/解封行为全部不变", name)
		})
	}

	// 所有拒绝之后再轮换，版本计数必须没有被坏快照推进
	k4, err := r.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if k4.Version != 4 {
		t.Fatalf("拒绝坏快照后版本计数被污染，期望新代版本=4，实际=%d", k4.Version)
	}
	t.Logf("[load-atomic-reject] 连续拒绝后轮换新版本号=%d，计数未回退/未跳变", k4.Version)
}

// legacySnapshotWithRevoked 构造旧版格式快照：非当前代也记为 active、无 pruned 字段，
// 吊销密钥（旧格式同样）携带 revoked_at。
func legacySnapshotWithRevoked(currentID string, nextVer int, keys ...*storedKey) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"current_id":%q,"next_version":%d,"keys":[`, currentID, nextVer)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":%q,"version":%d,"state":%q,"key":%q,"created_at":%d`,
			k.ID, k.Version, k.State, base64.StdEncoding.EncodeToString(k.Key), k.CreatedAt)
		if k.RevokedAt != 0 {
			fmt.Fprintf(&b, `,"revoked_at":%d`, k.RevokedAt)
		}
		b.WriteByte('}')
	}
	b.WriteString("]}")
	return b.String()
}

// TestLegacySnapshotWithRevokedCompat 合法旧格式快照（保留代记成 active、
// 无清理字段、吊销密钥带吊销时间）仍必须可读，并按新语义给出正确阶段。
func TestLegacySnapshotWithRevokedCompat(t *testing.T) {
	snap := legacySnapshotWithRevoked("legacy-cur", 4,
		testKey("legacy-rev", 1, StateRevoked, 4242), // 旧格式吊销代：带吊销时间
		testKey("legacy-old", 2, StateActive, 0),     // 旧格式保留代也记 active
		testKey("legacy-cur", 3, StateActive, 0),
	)
	t.Logf("[legacy-revoked] 输入旧格式快照: %s", snap)

	r := New()
	if err := r.LoadState([]byte(snap)); err != nil {
		t.Fatalf("含吊销密钥的旧版快照必须可读: %v", err)
	}
	iRev, _ := r.Info("legacy-rev")
	iOld, _ := r.Info("legacy-old")
	iCur, _ := r.Info("legacy-cur")
	t.Logf("[legacy-revoked] 加载后: legacy-rev state=%s revoked_at=%d; legacy-old state=%s; legacy-cur state=%s current=%v",
		iRev.State, iRev.RevokedAt, iOld.State, iCur.State, iCur.Current)
	if iRev.State != StateRevoked || iRev.RevokedAt != 4242 {
		t.Fatalf("旧快照吊销代应保持 revoked 且吊销时间不丢: %+v", iRev)
	}
	if iOld.State != StateRetained {
		t.Fatalf("旧快照非当前 active 代应降级为 retained，实际 %s", iOld.State)
	}
	if iCur.State != StateActive || !iCur.Current {
		t.Fatalf("旧快照当前代应为 active 当前代: %+v", iCur)
	}
	st := r.Stats()
	t.Logf("[legacy-revoked] 加载后统计: %+v", st)
	if st.Total != 3 || st.Active != 1 || st.Retained != 1 || st.Revoked != 1 || st.Pruned != 0 {
		t.Fatalf("旧快照加载后统计错误: %+v", st)
	}
	// 吊销代不可解封，当前代可新封装
	ct, err := r.Seal("alice", []byte("after-legacy"))
	if err != nil {
		t.Fatalf("旧快照加载后新封装应正常: %v", err)
	}
	if env, _ := decodeEnvelope(ct); env.Header.KeyID != "legacy-cur" {
		t.Fatalf("旧快照加载后新封装密钥错误: %s", env.Header.KeyID)
	}
	if nk, _ := r.Rotate(); nk.Version != 4 {
		t.Fatalf("旧快照加载后版本计数错误: %d", nk.Version)
	}
}

// TestCurrentExportWithRevokedRoundTrips 本轮正常导出（含 retained/revoked/current
// 三代及墓碑）在新校验下仍可整体加载，吊销时间原样恢复。
func TestCurrentExportWithRevokedRoundTrips(t *testing.T) {
	r := New()
	k1, _ := r.Rotate()
	k2, _ := r.Rotate()
	if _, err := r.Revoke(k1.ID); err != nil {
		t.Fatal(err)
	}
	k3, _ := r.Rotate()
	if _, err := r.Prune(k1.ID); err != nil {
		t.Fatal(err)
	}
	data, err := r.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[roundtrip] 当前格式导出快照: %s", data)

	r2 := New()
	if err := r2.LoadState(data); err != nil {
		t.Fatalf("本轮正常导出的快照必须可读: %v", err)
	}
	i2, _ := r2.Info(k2.ID)
	i3, _ := r2.Info(k3.ID)
	if i2.State != StateRetained || i2.RevokedAt != 0 {
		t.Fatalf("保留代阶段/吊销时间恢复错误: %+v", i2)
	}
	if i3.State != StateActive || !i3.Current {
		t.Fatalf("当前代恢复错误: %+v", i3)
	}
	if _, ok := r2.Info(k1.ID); ok {
		t.Fatal("已清理代不应出现在密钥列表")
	}
	if st := r2.Stats(); st.Pruned != 1 || st.Retained != 1 || st.Active != 1 || st.Revoked != 0 {
		t.Fatalf("当前格式快照重载后统计错误: %+v", st)
	}
	t.Logf("[roundtrip] 当前格式快照重载成功: retained=%s active/current=%s 墓碑=1", k2.ID, k3.ID)
}
