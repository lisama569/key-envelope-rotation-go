package keyring

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// 本文件覆盖快照加载的自洽性校验业务：
//  1. 版本号必须唯一且为合法正数（快照内、快照与环之间）；
//  2. 阶段与吊销时间必须一致（仅 revoked 可带且必须带有效 revoked_at）；
//  3. 矛盾快照整体拒绝后环内容完全不变；
//  4. 合法旧格式快照与本轮导出的新格式快照仍可正常加载。

// snapKeyJSON 按给定字段拼一条密钥 JSON；revokedAt<=0 表示不携带吊销时间
// （与旧格式及 omitempty 行为一致）。
func snapKeyJSON(id string, ver int, state string, revokedAt int64) string {
	key := make([]byte, keySize)
	for i := range key {
		key[i] = byte(ver + i)
	}
	s := fmt.Sprintf(`{"id":%q,"version":%d,"state":%q,"key":%q,"created_at":1000`,
		id, ver, state, base64.StdEncoding.EncodeToString(key))
	if revokedAt > 0 {
		s += fmt.Sprintf(`,"revoked_at":%d`, revokedAt)
	}
	s += "}"
	return s
}

// snapJSON 拼一份完整快照 JSON；currentID 为空表示无当前指针。
func snapJSON(currentID string, nextVer int, keyJSONs ...string) string {
	cur := "null"
	if currentID != "" {
		cur = fmt.Sprintf("%q", currentID)
	}
	return fmt.Sprintf(`{"current_id":%s,"next_version":%d,"keys":[%s]}`,
		cur, nextVer, strings.Join(keyJSONs, ","))
}

// TestLoadRejectsInvalidOrDuplicateVersions 业务：版本号唯一性与合法性校验。
// 版本号为 0/负数、快照内两把密钥共用版本号、快照版本号与环内已有版本撞号，
// 都必须在加载阶段以 malformed 明确拒绝。
func TestLoadRejectsInvalidOrDuplicateVersions(t *testing.T) {
	cases := map[string]string{
		// 两把不同代密钥被写成同一版本号：无法区分新旧
		"duplicate-version-in-snapshot": snapJSON("k-b", 3,
			snapKeyJSON("k-a", 1, "retained", 0),
			snapKeyJSON("k-b", 1, "active", 0)),
		// 版本号写成 0
		"version-zero": snapJSON("k-b", 3,
			snapKeyJSON("k-a", 0, "retained", 0),
			snapKeyJSON("k-b", 2, "active", 0)),
		// 版本号写成负数
		"version-negative": snapJSON("k-b", 3,
			snapKeyJSON("k-a", -3, "retained", 0),
			snapKeyJSON("k-b", 2, "active", 0)),
	}
	for name, snap := range cases {
		r := New()
		err := r.LoadState([]byte(snap))
		expectFail(t, "load-version/"+name, "", err, ReasonMalformed)
		if len(r.ListInfos()) != 0 {
			t.Fatalf("case=%s 拒绝后空环被污染: %d 条密钥", name, len(r.ListInfos()))
		}
		t.Logf("[load-version/%s] 非法版本号快照被整体拒绝: %v", name, err)
	}

	// 快照本身合法，但其版本号与环内既有密钥撞号（不同标识、同一版本）。
	ring := New()
	k1, err := ring.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	if k1.Version != 1 {
		t.Fatalf("首代版本号应为 1，实际 %d", k1.Version)
	}
	snap := snapJSON("k-import", 2, snapKeyJSON("k-import", 1, "active", 0))
	err = ring.LoadState([]byte(snap))
	expectFail(t, "load-version/version-conflicts-with-ring", "k-import", err, ReasonMalformed)
	if got := len(ring.ListInfos()); got != 1 {
		t.Fatalf("撞号拒绝后环被污染: %d 条密钥", got)
	}
	t.Logf("[load-version/version-conflicts-with-ring] 与环内 %s 版本撞号被拒绝: %v", k1.ID, err)
}

// TestLoadRejectsStateRevocationConflict 业务：阶段与吊销时间一致性校验。
// active/retained 携带吊销时间、revoked 缺少有效吊销时间，都属于字段冲突。
func TestLoadRejectsStateRevocationConflict(t *testing.T) {
	cases := map[string]string{
		// 保留代被带上吊销时间
		"retained-with-revoked-at": snapJSON("k-b", 3,
			snapKeyJSON("k-a", 1, "retained", 500),
			snapKeyJSON("k-b", 2, "active", 0)),
		// 当前生效代被带上吊销时间
		"current-active-with-revoked-at": snapJSON("k-a", 2,
			snapKeyJSON("k-a", 1, "active", 500)),
		// 旧格式风格的非当前 active（加载时会降级 retained）带吊销时间，仍是冲突
		"legacy-active-with-revoked-at": snapJSON("k-b", 3,
			snapKeyJSON("k-a", 1, "active", 500),
			snapKeyJSON("k-b", 2, "active", 0)),
		// 已吊销密钥缺少吊销时间（JSON 中无 revoked_at 字段）
		"revoked-missing-revoked-at": snapJSON("k-b", 3,
			snapKeyJSON("k-a", 1, "revoked", 0),
			snapKeyJSON("k-b", 2, "active", 0)),
	}
	for name, snap := range cases {
		r := New()
		err := r.LoadState([]byte(snap))
		expectFail(t, "load-revoke-conflict/"+name, "", err, ReasonMalformed)
		if len(r.ListInfos()) != 0 {
			t.Fatalf("case=%s 拒绝后空环被污染: %d 条密钥", name, len(r.ListInfos()))
		}
		t.Logf("[load-revoke-conflict/%s] 阶段与吊销时间冲突被整体拒绝: %v", name, err)
	}
}

// ringSnapshot 是环内部状态的深拷贝，用于对比拒绝加载前后的完整状态。
type ringSnapshot struct {
	current     string
	nextVersion int
	entries     map[string]KeyEntry
	pruned      map[string]int64
	stats       Stats
}

func dumpRing(r *KeyRing) ringSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	snap := ringSnapshot{
		current:     r.current,
		nextVersion: r.nextVersion,
		entries:     make(map[string]KeyEntry, len(r.entries)),
		pruned:      make(map[string]int64, len(r.pruned)),
		stats:       r.Stats(),
	}
	for id, e := range r.entries {
		snap.entries[id] = KeyEntry{
			ID:        e.ID,
			Version:   e.Version,
			State:     e.State,
			Key:       append([]byte(nil), e.Key...),
			CreatedAt: e.CreatedAt,
			RevokedAt: e.RevokedAt,
		}
	}
	for id, at := range r.pruned {
		snap.pruned[id] = at
	}
	return snap
}

// TestRejectedLoadLeavesRingUntouched 业务：拒绝必须是原子的——整份快照
// 要么整体生效、要么整体拒绝；被拒绝后环内的密钥、阶段、统计、墓碑、当前指针、
// 版本计数一个都不能变，也不能被部分合并污染出半套状态。
func TestRejectedLoadLeavesRingUntouched(t *testing.T) {
	r := New()
	// 构造覆盖三种阶段 + 墓碑的既有环：k1 吊销、k2 清理、k3 保留、k4 当前。
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("gen-1"))
	k2, _ := r.Rotate()
	k3, _ := r.Rotate()
	c3, _ := r.Seal("alice", []byte("gen-3"))
	k4, _ := r.Rotate()
	if _, err := r.Revoke(k1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Prune(k2.ID); err != nil {
		t.Fatal(err)
	}
	before := dumpRing(r)
	t.Logf("[load-atomic] 拒绝前基线: current=%s nextVersion=%d entries=%d pruned=%d stats=%+v",
		before.current, before.nextVersion, len(before.entries), len(before.pruned), before.stats)

	// 每一份坏快照都包含两把“新”密钥，若被部分合并一定会留下痕迹。
	bad := map[string]string{
		"dup-version": snapJSON("k-bad2", 9,
			snapKeyJSON("k-bad1", 5, "retained", 0),
			snapKeyJSON("k-bad2", 5, "active", 0)),
		"zero-version": snapJSON("k-bad2", 9,
			snapKeyJSON("k-bad1", 0, "retained", 0),
			snapKeyJSON("k-bad2", 6, "active", 0)),
		"retained-with-revoked-at": snapJSON("k-bad2", 9,
			snapKeyJSON("k-bad1", 5, "retained", 42),
			snapKeyJSON("k-bad2", 6, "active", 0)),
		"revoked-without-revoked-at": snapJSON("k-bad2", 9,
			snapKeyJSON("k-bad1", 5, "revoked", 0),
			snapKeyJSON("k-bad2", 6, "active", 0)),
		"duplicate-id": snapJSON("k-bad2", 9,
			snapKeyJSON("k-bad1", 5, "retained", 0),
			snapKeyJSON("k-bad1", 6, "active", 0)),
	}
	for name, snap := range bad {
		err := r.LoadState([]byte(snap))
		expectFail(t, "load-atomic/"+name, "", err, ReasonMalformed)
		after := dumpRing(r)
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("case=%s 拒绝快照后环状态发生变化:\nbefore=%+v\nafter =%+v", name, before, after)
		}
		t.Logf("[load-atomic/%s] 拒绝后环完全不变: current=%s entries=%d pruned=%d stats=%+v",
			name, after.current, len(after.entries), len(after.pruned), after.stats)
	}

	// 拒绝发生后，既有密钥的密码学行为与诊断也必须原样。
	_, _, err := r.Open("alice", c1)
	expectFail(t, "load-atomic/open-revoked-still-revoked", k1.ID, err, ReasonRevoked)
	if pt, kid, err := r.Open("alice", c3); err != nil || kid != k3.ID || string(pt) != "gen-3" {
		t.Fatalf("拒绝坏快照后 retained 代解封行为被污染: pt=%q kid=%s err=%v", pt, kid, err)
	}
	cur, ok := r.CurrentKeyID()
	if !ok || cur != k4.ID {
		t.Fatalf("拒绝坏快照后当前指针被污染: %q ok=%v", cur, ok)
	}
	if ct, err := r.Seal("alice", []byte("still-current")); err != nil {
		t.Fatalf("拒绝坏快照后当前代新封装失败: %v", err)
	} else {
		if pt, kid, err := r.Open("alice", ct); err != nil || kid != k4.ID || string(pt) != "still-current" {
			t.Fatalf("拒绝坏快照后封解封链路异常: pt=%q kid=%s err=%v", pt, kid, err)
		}
	}
	t.Logf("[load-atomic] 拒绝多份坏快照后行为不变: revoked 仍拒绝、retained/current 正常")
}

// TestLegalSnapshotsLoadWithCorrectPhases 业务：合法快照不得被误伤——
// 本轮正常导出的新格式快照（含 revoked 且带有效吊销时间、retained、墓碑）
// 加载后按新语义给出正确阶段与吊销时间。
func TestLegalSnapshotsLoadWithCorrectPhases(t *testing.T) {
	src := New()
	k1, _ := src.Rotate()
	c1, _ := src.Seal("alice", []byte("legal-gen-1"))
	k2, _ := src.Rotate()
	c2, _ := src.Seal("alice", []byte("legal-gen-2"))
	k3, _ := src.Rotate()
	if _, err := src.Revoke(k1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Prune(k2.ID); err != nil {
		t.Fatal(err)
	}
	data, err := src.ExportState()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[load-legal] 新格式导出快照: %s", string(data))

	dst := New()
	if err := dst.LoadState(data); err != nil {
		t.Fatalf("合法新格式快照必须可读: %v", err)
	}
	i1, ok := dst.Info(k1.ID)
	if !ok || i1.State != StateRevoked || i1.RevokedAt <= 0 {
		t.Fatalf("吊销代阶段/吊销时间恢复错误: %+v ok=%v", i1, ok)
	}
	i3, _ := dst.Info(k3.ID)
	if i3.State != StateActive || !i3.Current {
		t.Fatalf("当前代恢复错误: %+v", i3)
	}
	_, _, err = dst.Open("alice", c1)
	expectFail(t, "load-legal/open-revoked", k1.ID, err, ReasonRevoked)
	_, _, err = dst.Open("alice", c2)
	expectFail(t, "load-legal/open-pruned", k2.ID, err, ReasonPruned)
	if pt, kid, err := dst.Open("alice",
		mustSeal(t, dst, "alice", []byte("legal-new"))); err != nil || kid != k3.ID || string(pt) != "legal-new" {
		t.Fatalf("加载后当前代封解封错误: pt=%q kid=%s err=%v", pt, kid, err)
	}
	st := dst.Stats()
	if st.Total != 2 || st.Active != 1 || st.Retained != 0 || st.Revoked != 1 || st.Pruned != 1 {
		t.Fatalf("加载后统计错误: %+v", st)
	}
	t.Logf("[load-legal] 新格式快照加载成功: revoked(%s, revoked_at=%d)、pruned(%s)、current(%s) 阶段正确, stats=%+v",
		k1.ID, i1.RevokedAt, k2.ID, k3.ID, st)
}

func mustSeal(t *testing.T, r *KeyRing, recipient string, pt []byte) []byte {
	t.Helper()
	ct, err := r.Seal(recipient, pt)
	if err != nil {
		t.Fatalf("Seal 失败: %v", err)
	}
	return ct
}

// TestLegacySnapshotWithRevokedKeyStillLoads 业务：旧版导出格式（无 retained
// 枚举、无 pruned 字段）中，已吊销密钥携带有效吊销时间的快照仍必须可读；
// 吊销代按 revoked 恢复且保留吊销时间，其余旧代按旧格式兼容规则降级 retained。
func TestLegacySnapshotWithRevokedKeyStillLoads(t *testing.T) {
	mk := func(id string, ver int, state string, revokedAt int64) *storedKey {
		key := make([]byte, keySize)
		for i := range key {
			key[i] = byte(len(id) + ver + i)
		}
		return &storedKey{
			ID: id, Version: ver, State: state, Key: key,
			CreatedAt: 1000 + int64(ver), RevokedAt: revokedAt,
		}
	}
	keys := []*storedKey{
		mk("k-old-1", 1, "revoked", 500), // 旧格式吊销代：带有效吊销时间
		mk("k-old-2", 2, "active", 0),    // 旧格式保留代：记为 active、无吊销时间
		mk("k-old-3", 3, "active", 0),    // 当前代
	}
	var b strings.Builder
	fmt.Fprintf(&b, `{"current_id":"k-old-3","next_version":4,"keys":[`)
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":%q,"version":%d,"state":%q,"key":%q,"created_at":%d`,
			k.ID, k.Version, k.State, base64.StdEncoding.EncodeToString(k.Key), k.CreatedAt)
		if k.RevokedAt > 0 {
			fmt.Fprintf(&b, `,"revoked_at":%d`, k.RevokedAt)
		}
		b.WriteByte('}')
	}
	b.WriteString("]}")
	snap := b.String()
	t.Logf("[legacy-revoked] 输入旧格式快照: %s", snap)

	r := New()
	if err := r.LoadState([]byte(snap)); err != nil {
		t.Fatalf("含吊销代的旧格式快照必须可读: %v", err)
	}
	i1, _ := r.Info("k-old-1")
	i2, _ := r.Info("k-old-2")
	i3, _ := r.Info("k-old-3")
	t.Logf("[legacy-revoked] 加载后: k-old-1 state=%s revoked_at=%d; k-old-2 state=%s revoked_at=%d; k-old-3 state=%s current=%v",
		i1.State, i1.RevokedAt, i2.State, i2.RevokedAt, i3.State, i3.Current)
	if i1.State != StateRevoked || i1.RevokedAt != 500 {
		t.Fatalf("吊销代阶段/吊销时间恢复错误: %+v", i1)
	}
	if i2.State != StateRetained || i2.RevokedAt != 0 {
		t.Fatalf("旧格式非当前 active 应降级 retained 且无吊销时间: %+v", i2)
	}
	if i3.State != StateActive || !i3.Current {
		t.Fatalf("当前代恢复错误: %+v", i3)
	}
	if st := r.Stats(); st.Revoked != 1 || st.Retained != 1 || st.Active != 1 {
		t.Fatalf("旧格式加载后统计错误: %+v", st)
	}
}
