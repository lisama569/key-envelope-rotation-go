package keyring

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func reasonOf(err error) Reason {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

// expectFail 校验错误被正确归类，并打印输入标识与判定依据。
func expectFail(t *testing.T, op string, keyID string, err error, want Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("[%s] key=%s 期望失败原因=%s，实际成功", op, keyID, want)
	}
	got := reasonOf(err)
	t.Logf("[%s] 输入标识 key=%s -> 判定依据 reason=%q, err=%v", op, keyID, got, err)
	if got != want {
		t.Fatalf("[%s] key=%s 期望原因=%s，实际=%s (%v)", op, keyID, want, got, err)
	}
	if !errors.Is(err, &Error{Reason: want}) {
		t.Fatalf("[%s] key=%s errors.Is 原因归类失败", op, keyID)
	}
}

func TestSealOpenHappyPath(t *testing.T) {
	r := New()
	info, err := r.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("轮换生成当前密钥 key=%s version=%d", info.ID, info.Version)

	ct, err := r.Seal("alice", []byte("hello-key-ring"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := decodeEnvelope(ct)
	if err != nil {
		t.Fatal(err)
	}
	if env.Header.KeyID != info.ID || env.Header.Version != Version {
		t.Fatalf("密文头部标识错误: kid=%s want=%s, v=%d want=%d",
			env.Header.KeyID, info.ID, env.Header.Version, Version)
	}
	t.Logf("封装成功: 输入接收方=alice, 当前 key=%s, 密文携带 key=%s v=%d",
		info.ID, env.Header.KeyID, env.Header.Version)

	pt, kid, err := r.Open("alice", ct)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("解封成功: 输入接收方=alice, 密文 key=%s -> 判定使用 key=%s", env.Header.KeyID, kid)
	if string(pt) != "hello-key-ring" || kid != info.ID {
		t.Fatalf("解封结果错误: pt=%q kid=%s", pt, kid)
	}
}

func TestEmptyRingSealRejected(t *testing.T) {
	r := New()
	_, err := r.Seal("alice", []byte("x"))
	expectFail(t, "seal-empty", "", err, ReasonNoCurrentKey)
}

func TestUnknownKey(t *testing.T) {
	r := New()
	if _, err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	ct, err := r.Seal("alice", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	other := New()
	if _, err := other.Rotate(); err != nil {
		t.Fatal(err)
	}
	env, _ := decodeEnvelope(ct)
	_, _, err = other.Open("alice", ct)
	expectFail(t, "open-unknown", env.Header.KeyID, err, ReasonUnknownKey)
}

func TestRecipientMismatch(t *testing.T) {
	r := New()
	if _, err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	ct, _ := r.Seal("alice", []byte("secret"))
	env, _ := decodeEnvelope(ct)
	_, _, err := r.Open("bob", ct)
	expectFail(t, "open-recipient", env.Header.KeyID, err, ReasonRecipientMismatch)
}

func TestTamperedCiphertext(t *testing.T) {
	r := New()
	info, _ := r.Rotate()
	ct, _ := r.Seal("alice", []byte("integrity-protected"))

	// 1) 篡改密文主体最后一个字节（GCM 标签/主体区）
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 0xFF
	_, _, err := r.Open("alice", bad)
	expectFail(t, "open-tamper-body", info.ID, err, ReasonTampered)

	// 2) 篡改受 AAD 保护的头部：在头部 JSON 中插入空白，解析值不变但 AAD 字节已变
	env, _ := decodeEnvelope(ct)
	hdrJSON, _ := json.Marshal(&env.Header)
	hdrJSON = append(hdrJSON[:len(hdrJSON)-1], ' ', '}')
	tampered := append([]byte(nil), ct[:len(Magic)]...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(hdrJSON)))
	tampered = append(tampered, lenBuf[:]...)
	tampered = append(tampered, hdrJSON...)
	tampered = append(tampered, env.Nonce...)
	tampered = append(tampered, env.Cipher...)
	if _, _, err := r.Open("alice", tampered); err == nil {
		t.Fatal("篡改头部后必须被拒绝")
	} else {
		t.Logf("[open-tamper-header] key=%s -> 判定依据 reason=%q, err=%v",
			info.ID, reasonOf(err), err)
	}
}

func TestMalformed(t *testing.T) {
	r := New()
	if _, err := r.Rotate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":           nil,
		"too-short":       []byte("KE"),
		"bad-magic":       []byte("XXXX\x00\x10{}"),
		"header-overflow": append([]byte(Magic), 0xFF, 0xFF),
		"truncated-body":  nil,
	}
	ct, _ := r.Seal("alice", []byte("x"))
	env, _ := decodeEnvelope(ct)
	// 头部声称的 nonce 长度合法但主体被截断
	goodJSON, _ := json.Marshal(&env.Header)
	trunc := append([]byte(nil), ct[:len(Magic)+2]...)
	trunc = append(trunc, goodJSON...)
	trunc = append(trunc, env.Nonce[:2]...)
	cases["truncated-body"] = trunc

	for name, in := range cases {
		_, _, err := r.Open("alice", in)
		if err == nil {
			t.Fatalf("case=%s 畸形密文必须被拒绝", name)
		}
		got := reasonOf(err)
		t.Logf("[open-malformed/%s] 输入长度=%d -> 判定依据 reason=%q, err=%v", name, len(in), got, err)
		if got != ReasonMalformed && got != ReasonUnsupportedVersion {
			t.Fatalf("case=%s 期望格式类错误，实际=%s", name, got)
		}
	}
}

func TestRotationMultiGeneration(t *testing.T) {
	r := New()

	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("generation-1"))

	k2, _ := r.Rotate()
	c2, _ := r.Seal("alice", []byte("generation-2"))

	// 新密文必须使用新一代密钥
	e2, _ := decodeEnvelope(c2)
	if e2.Header.KeyID != k2.ID {
		t.Fatalf("轮换后新密文仍使用旧 key=%s，应使用 key=%s", e2.Header.KeyID, k2.ID)
	}
	t.Logf("轮换: 旧 key=%s(version=%d) 保留, 当前 key=%s(version=%d)",
		k1.ID, k1.Version, k2.ID, k2.Version)

	// 旧密钥保留期间，历史密文可继续解封
	pt, kid, err := r.Open("alice", c1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("历史密文解封: 密文携带 key=%s -> 判定使用 key=%s, 明文=%q", k1.ID, kid, pt)
	if kid != k1.ID || string(pt) != "generation-1" {
		t.Fatalf("历史密文解封错误: kid=%s pt=%q", kid, pt)
	}

	infos := r.ListInfos()
	if len(infos) != 2 || infos[0].Version != 1 || infos[1].Version != 2 {
		t.Fatalf("多代密钥并存视图错误: %+v", infos)
	}
}

func TestRevokeAndRotate(t *testing.T) {
	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("under-k1"))
	k2, _ := r.Rotate()
	c2, _ := r.Seal("alice", []byte("under-k2"))

	if _, err := r.Revoke(k1.ID); err != nil {
		t.Fatal(err)
	}
	info, ok := r.Info(k1.ID)
	if !ok || info.State != StateRevoked {
		t.Fatalf("吊销状态未生效: %+v ok=%v", info, ok)
	}
	t.Logf("吊销旧密钥 key=%s；当前密钥仍为 key=%s", k1.ID, k2.ID)

	// 吊销旧密钥不影响新封装（使用当前 k2）
	c3, err := r.Seal("alice", []byte("after-revoke"))
	if err != nil {
		t.Fatalf("吊销非当前密钥后新封装应成功: %v", err)
	}
	e3, _ := decodeEnvelope(c3)
	t.Logf("吊销后新封装: 密文携带 key=%s（期望 %s）", e3.Header.KeyID, k2.ID)
	if e3.Header.KeyID != k2.ID {
		t.Fatal("吊销后新封装误用了其他密钥")
	}

	// 既有密文: 被吊销密钥的密文确定性拒绝
	_, _, err = r.Open("alice", c1)
	expectFail(t, "open-revoked", k1.ID, err, ReasonRevoked)

	// 当前密钥的密文仍可解封
	if pt, kid, err := r.Open("alice", c2); err != nil || kid != k2.ID || string(pt) != "under-k2" {
		t.Fatalf("未吊销密钥的密文受牵连: pt=%q kid=%s err=%v", pt, kid, err)
	}
	t.Logf("未吊销 key=%s 的密文解封正常", k2.ID)

	// 吊销当前密钥后，新封装被拒绝；轮换后恢复
	if _, err := r.Revoke(k2.ID); err != nil {
		t.Fatal(err)
	}
	_, err = r.Seal("alice", []byte("x"))
	expectFail(t, "seal-after-current-revoked", k2.ID, err, ReasonNoCurrentKey)

	k3, err := r.Rotate()
	if err != nil {
		t.Fatalf("吊销后轮换必须成功: %v", err)
	}
	c4, err := r.Seal("alice", []byte("generation-3"))
	if err != nil {
		t.Fatalf("轮换后新封装必须成功: %v", err)
	}
	e4, _ := decodeEnvelope(c4)
	t.Logf("吊销后轮换: 新 key=%s(version=%d), 密文携带 key=%s", k3.ID, k3.Version, e4.Header.KeyID)
	if e4.Header.KeyID != k3.ID {
		t.Fatal("轮换恢复后密文未使用新密钥")
	}
}

func TestRevokeUnknownKey(t *testing.T) {
	r := New()
	_, err := r.Revoke("k-does-not-exist")
	expectFail(t, "revoke-unknown", "k-does-not-exist", err, ReasonUnknownKey)
}

func TestPersistenceRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ring.json")

	r := New()
	k1, _ := r.Rotate()
	c1, _ := r.Seal("alice", []byte("persist-me"))
	k2, _ := r.Rotate()
	if _, err := r.Revoke(k1.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.SaveToFile(path); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("状态文件权限错误: %v %v", fi, err)
	}

	r2, err := LoadKeyRingFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// 重载后多代密钥、吊销状态、当前密钥全部恢复
	cur, ok := r2.CurrentKeyID()
	if !ok || cur != k2.ID {
		t.Fatalf("重载后当前密钥错误: %q ok=%v", cur, ok)
	}
	if info, ok := r2.Info(k1.ID); !ok || info.State != StateRevoked {
		t.Fatalf("重载后吊销状态丢失: %+v", info)
	}
	_, _, err = r2.Open("alice", c1)
	expectFail(t, "open-after-reload-revoked", k1.ID, err, ReasonRevoked)

	c2, _ := r2.Seal("alice", []byte("after-reload"))
	pt, kid, err := r2.Open("alice", c2)
	if err != nil || kid != k2.ID || string(pt) != "after-reload" {
		t.Fatalf("重载后封解封错误: %v", err)
	}
	t.Logf("持久化重载成功: 当前 key=%s, 历史吊销 key=%s 行为确定", kid, k1.ID)
}

func TestDiagnosticsContainNoKeyMaterial(t *testing.T) {
	r := New()
	k, _ := r.Rotate()
	ct, _ := r.Seal("alice", []byte("secret-material"))
	env, _ := decodeEnvelope(ct)

	// 原始密钥材料绝不能出现在任何诊断输出中
	r.mu.RLock()
	raw := r.entries[k.ID].Key
	r.mu.RUnlock()

	dump, _ := json.Marshal(r.ListInfos())
	infoDump, _ := json.Marshal(func() KeyInfo { i, _ := r.Info(k.ID); return i }())
	for _, d := range [][]byte{dump, infoDump} {
		if bytes.Contains(bytes.ToLower(d), bytes.ToLower(raw)) {
			t.Fatal("诊断信息中出现密钥材料")
		}
		if strings.Contains(string(d), "\"key\"") {
			t.Fatalf("诊断元数据包含 key 字段: %s", d)
		}
	}
	t.Logf("诊断导出仅含元数据: %s；密文中 key=%s nonce长度=%d", dump, env.Header.KeyID, len(env.Nonce))
}

func TestConcurrentAccess(t *testing.T) {
	r := New()
	k0, _ := r.Rotate()

	const workers = 16
	const rounds = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	nonces := map[string]bool{}
	type sealed struct {
		ct  []byte
		kid string
	}
	sealedList := make([]sealed, 0, workers*rounds)
	var failMu sync.Mutex
	typedFails := 0

	// 并发轮换者
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 8; i++ {
			info, err := r.Rotate()
			if err == nil {
				t.Logf("[rotate] 新当前 key=%s version=%d", info.ID, info.Version)
			}
		}
	}()

	// 并发封装/解封者
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				pt := []byte(fmt.Sprintf("worker-%d-msg-%d", w, i))
				ct, err := r.Seal("alice", pt)
				if err != nil {
					// 轮换窗口内不存在当前密钥是唯一可接受的失败类型
					if reasonOf(err) != ReasonNoCurrentKey {
						failMu.Lock()
						t.Errorf("并发封装出现非预期错误: %v", err)
						failMu.Unlock()
					}
					failMu.Lock()
					typedFails++
					failMu.Unlock()
					continue
				}
				env, derr := decodeEnvelope(ct)
				if derr != nil {
					failMu.Lock()
					t.Errorf("并发封装密文无法解码: %v", derr)
					failMu.Unlock()
					continue
				}
				// nonce 全局不得重复
				nk := env.Header.KeyID + ":" + string(env.Nonce)
				mu.Lock()
				if nonces[nk] {
					t.Error("检测到 nonce 重复使用")
				}
				nonces[nk] = true
				sealedList = append(sealedList, sealed{ct: ct, kid: env.Header.KeyID})
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()

	if len(sealedList) == 0 {
		t.Fatal("并发场景下没有成功产生任何密文")
	}
	// 轮换停止后，所有密文必须按其携带的密钥标识正确解封
	for _, s := range sealedList {
		pt, kid, err := r.Open("alice", s.ct)
		if err != nil {
			t.Fatalf("并发期间密文解封失败 key=%s: %v", s.kid, err)
		}
		if kid != s.kid {
			t.Fatalf("跨密钥误用: 密文 key=%s 实际用 key=%s 解封", s.kid, kid)
		}
		if !strings.HasPrefix(string(pt), "worker-") {
			t.Fatalf("解封明文错误: %q", pt)
		}
	}
	t.Logf("并发结束: 成功密文=%d, 可解释拒绝(no_current_key)=%d, 唯一nonce=%d, 初始key=%s, 当前密钥代数=%d",
		len(sealedList), typedFails, len(nonces), k0.ID, len(r.ListInfos()))
}
