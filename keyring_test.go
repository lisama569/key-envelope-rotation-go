package keyenvelope

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// assertKind 校验错误类别，并打印“输入标识 + 判定依据”，满足诊断要求。
func assertKind(t *testing.T, op string, err error, want FailureKind, inputDesc string) {
	t.Helper()
	if err == nil {
		t.Fatalf("[%s] 输入=%s 期望错误类别 %s，实际成功（可能解出错误明文）", op, inputDesc, want)
	}
	got := KindOf(err)
	t.Logf("[%s] 输入=%s 判定依据=%s（want=%s, got=%s）err=%v", op, inputDesc, got, want, got, err)
	if got != want {
		t.Fatalf("[%s] 输入=%s 错误类别不符：want=%s got=%s err=%v", op, inputDesc, want, got, err)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	kr := NewKeyring("alice")
	id, err := kr.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	t.Logf("接收方=alice 当前密钥标识=%s", id)

	cases := []string{"", "hello", "中文明文", strings.Repeat("x", 4096)}
	for i, pt := range cases {
		blob, err := kr.SealBytes([]byte(pt))
		if err != nil {
			t.Fatalf("case %d seal: %v", i, err)
		}
		ev, perr := ParseEnvelope(blob)
		if perr != nil {
			t.Fatalf("case %d parse: %v", i, perr)
		}
		t.Logf("case=%d 密文携带 formatVer=%d recipient=%s keyID=%s", i, ev.FormatVersion, ev.Recipient, ev.KeyID)
		got, err := kr.OpenBytes(blob)
		if err != nil {
			t.Fatalf("case %d open: %v", i, err)
		}
		if string(got) != pt {
			t.Fatalf("case %d 明文不一致：want=%q got=%q", i, pt, got)
		}
	}
}

func TestSealWithoutActiveKey(t *testing.T) {
	kr := NewKeyring("alice")
	_, err := kr.SealBytes([]byte("x"))
	assertKind(t, "seal", err, KindNoActiveKey, "recipient=alice（空密钥环）")
}

func TestFormatErrors(t *testing.T) {
	kr := NewKeyring("alice")
	if _, err := kr.Rotate(); err != nil {
		t.Fatal(err)
	}
	good, err := kr.SealBytes([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 密文 = len(明文)+16 字节；截掉 len(明文)+1 字节后剩余密文为 15 字节，低于标签长度。
	cutBelowTag := len("payload") + 1

	cases := []struct {
		name string
		in   []byte
	}{
		{"空输入", nil},
		{"短于头部", good[:3]},
		{"魔数错误", append(append([]byte{}, good...), 0)[:0]}, // placeholder, 下方替换
		{"密文截断到标签以下", good[:len(good)-cutBelowTag]},        // 剩余密文 15 字节，结构不完整
		{"头部截断", good[:headerSize+1]},
	}
	// 构造魔数错误输入：复制 good 后翻转首个字节。
	badMagic := append([]byte{}, good...)
	badMagic[0] ^= 0xFF
	cases[2].in = badMagic

	for _, c := range cases {
		_, err := kr.OpenBytes(c.in)
		assertKind(t, "open", err, KindFormat, fmt.Sprintf("case=%s len=%d", c.name, len(c.in)))
	}

	// 不支持的格式版本（偏移 4）。
	badVer := append([]byte{}, good...)
	badVer[4] = 99
	_, err = kr.OpenBytes(badVer)
	assertKind(t, "open", err, KindFormat, "case=格式版本=99")
}

func TestTamperClassifications(t *testing.T) {
	kr := NewKeyring("alice")
	id, _ := kr.Rotate()
	good, _ := kr.SealBytes([]byte("secret"))

	// 1) 篡改密文正文（末字节）：结构完整、key 存在且未吊销 -> 认证失败 tampered。
	tampered := append([]byte{}, good...)
	tampered[len(tampered)-1] ^= 0x01
	_, err := kr.OpenBytes(tampered)
	assertKind(t, "open", err, KindTampered,
		fmt.Sprintf("case=翻转密文末字节 keyID=%s recipient=alice", id))

	// 2) 篡改 nonce（定位 nonce：在 keyID 之后）。
	ev, _ := ParseEnvelope(good)
	nonceOff := headerSize + 1 + len(ev.Recipient) + 1 + len(ev.KeyID) + 1
	tNonce := append([]byte{}, good...)
	tNonce[nonceOff] ^= 0x01
	_, err = kr.OpenBytes(tNonce)
	assertKind(t, "open", err, KindTampered,
		fmt.Sprintf("case=翻转nonce首字节 keyID=%s recipient=alice", id))

	// 3) 篡改 keyID 字节：长度不变、接收方一致，但该标识在环中不存在 -> unknown_key。
	idOff := headerSize + 1 + len(ev.Recipient) + 1 // 跳过长度字节，指向 keyID 内容首字节
	tKey := append([]byte{}, good...)
	tKey[idOff] ^= 0x01
	te, _ := ParseEnvelope(tKey)
	_, err = kr.OpenBytes(tKey)
	assertKind(t, "open", err, KindUnknownKey,
		fmt.Sprintf("case=篡改keyID字节 篡改后标识=%s", te.KeyID))

	// 4) 篡改接收方字节：解析成功但与密钥环接收方不符 -> recipient_mismatch。
	tRec := append([]byte{}, good...)
	tRec[headerSize+1] ^= 0x01 // recipient 内容首字节（'a' ^ 1 = '`'），长度不变
	tre, _ := ParseEnvelope(tRec)
	_, err = kr.OpenBytes(tRec)
	assertKind(t, "open", err, KindRecipientMismatch,
		fmt.Sprintf("case=篡改recipient字节 篡改后接收方=%s", tre.Recipient))
}

func TestUnknownKeyAndRecipientMismatch(t *testing.T) {
	alice := NewKeyring("alice")
	bob := NewKeyring("bob")
	idA, _ := alice.Rotate()
	idB, _ := bob.Rotate()

	blob, _ := alice.SealBytes([]byte("for-alice"))
	ev, _ := ParseEnvelope(blob)
	t.Logf("密文收件人=%s 密文密钥=%s | bob环 active=%s", ev.Recipient, ev.KeyID, idB)

	// bob 打开 alice 的密文：接收方先不匹配。
	_, err := bob.Open(ev)
	assertKind(t, "open", err, KindRecipientMismatch,
		fmt.Sprintf("case=跨接收方解封 密文recipient=%s 环recipient=bob", ev.Recipient))

	// 构造一封“给 alice 但携带未知密钥标识”的信封：bob 不能用，
	// 直接在 alice 环上打开一个伪造 KeyID 的结构合法信封。
	fake := &Envelope{
		FormatVersion: currentFormatVer,
		Recipient:     "alice",
		KeyID:         "key-deadbeef",
		Nonce:         make([]byte, gcmStandardNonceLen),
		Ciphertext:    make([]byte, gcmTagLen),
	}
	fb, _ := fake.MarshalBinary()
	_, err = alice.OpenBytes(fb)
	assertKind(t, "open", err, KindUnknownKey,
		"case=伪造信封 keyID=key-deadbeef recipient=alice（环中仅有 "+idA+"）")
}

func TestRetireKeepsHistory(t *testing.T) {
	kr := NewKeyring("alice")
	id1, _ := kr.Rotate()
	oldBlob, _ := kr.SealBytes([]byte("old"))

	// 轮换：id1 转 retired。
	id2, _ := kr.Rotate()
	t.Logf("轮换后 active=%s retired=%s", id2, id1)
	if _, err := kr.OpenBytes(oldBlob); err != nil {
		t.Fatalf("retired 密钥应仍可解封历史密文: %v", err)
	}
	t.Logf("判定依据：keyID=%s 状态=retired，保留期内允许 open、禁止 seal", id1)

	// 手动退役当前 active：seal 立即不可用。
	if err := kr.Retire(id2); err != nil {
		t.Fatal(err)
	}
	_, err := kr.SealBytes([]byte("new"))
	assertKind(t, "seal", err, KindNoActiveKey,
		fmt.Sprintf("case=手动退役 active=%s 后再封装", id2))

	// 两代理历史密文均可解封。
	newBlob := mustSealWithKey(t, kr, id2, "new")
	for i, b := range [][]byte{oldBlob, newBlob} {
		if _, err := kr.OpenBytes(b); err != nil {
			t.Fatalf("历史密文 %d 解封失败: %v", i, err)
		}
	}
}

// mustSealWithKey 临时恢复指定密钥为 active 来制造密文（仅测试辅助）。
func mustSealWithKey(t *testing.T, kr *Keyring, keyID, pt string) []byte {
	t.Helper()
	kr.mu.Lock()
	e := kr.keys[keyID]
	prev := kr.activeID
	e.State = StateActive
	kr.activeID = keyID
	kr.mu.Unlock()
	b, err := kr.SealBytes([]byte(pt))
	kr.mu.Lock()
	e.State = StateRetired
	kr.activeID = prev
	kr.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRevokeFlow(t *testing.T) {
	kr := NewKeyring("alice")
	id1, _ := kr.Rotate()
	c1, _ := kr.SealBytes([]byte("before-revoke"))

	// 吊销 active 密钥。
	if err := kr.Revoke(id1); err != nil {
		t.Fatal(err)
	}
	t.Logf("已吊销 keyID=%s，active 槽应清空（当前 active=%q）", id1, kr.ActiveKeyID())

	// 吊销后新封装被拒绝：此时无 active。
	_, err := kr.SealBytes([]byte("after-revoke"))
	assertKind(t, "seal", err, KindNoActiveKey,
		fmt.Sprintf("case=吊销 active=%s 后立即新封装", id1))

	// 既有密文：确定地以 key_revoked 拒绝（不是 tampered，也不返回明文）。
	_, err = kr.OpenBytes(c1)
	assertKind(t, "open", err, KindKeyRevoked,
		fmt.Sprintf("case=解封已吊销密钥的既有密文 keyID=%s", id1))

	// 吊销后轮换：新 active 与旧吊销密钥并存。
	id2, err := kr.Rotate()
	if err != nil {
		t.Fatalf("吊销后轮换失败: %v", err)
	}
	t.Logf("吊销后轮换成功 newActive=%s；旧密文 keyID=%s 仍应被拒绝", id2, id1)

	c2, err := kr.SealBytes([]byte("after-rotate"))
	if err != nil {
		t.Fatalf("新密钥封装失败: %v", err)
	}
	if pt, err := kr.OpenBytes(c2); err != nil || string(pt) != "after-rotate" {
		t.Fatalf("新密钥解封异常: %v %q", err, pt)
	}
	_, err = kr.OpenBytes(c1)
	assertKind(t, "open", err, KindKeyRevoked,
		fmt.Sprintf("case=轮换后再解封旧吊销密文 keyID=%s newActive=%s", id1, id2))

	// 重复吊销返回 invalid_state。
	err = kr.Revoke(id1)
	assertKind(t, "revoke", err, KindState, "case=重复吊销 "+id1)

	// 吊销未知标识。
	err = kr.Revoke("key-nope")
	assertKind(t, "revoke", err, KindUnknownKey, "case=吊销未知标识 key-nope")
}

func TestNonceUniqueness(t *testing.T) {
	kr := NewKeyring("alice")
	if _, err := kr.Rotate(); err != nil {
		t.Fatal(err)
	}
	const n = 3000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		ev, err := kr.Seal([]byte("same-plaintext"))
		if err != nil {
			t.Fatal(err)
		}
		h := hex.EncodeToString(ev.Nonce)
		if _, dup := seen[h]; dup {
			t.Fatalf("nonce 重复使用，i=%d nonce=%s", i, h)
		}
		seen[h] = struct{}{}
	}
	t.Logf("判定依据：%d 次封装产生 %d 个互不相同的随机 nonce", n, len(seen))
}

func TestConcurrentSealOpenRotate(t *testing.T) {
	kr := NewKeyring("alice")
	firstID, _ := kr.Rotate()

	const (
		sealers   = 8
		perSealer = 100
		openers   = 4
		rotations = 10
	)
	var (
		producerWg sync.WaitGroup // 轮换者 + 封装者
		consumerWg sync.WaitGroup // 解封者
		nonceMu    sync.Mutex
		nonces     = make(map[string]struct{})
	)
	// 密文经有缓冲 channel 从封装者流向解封者，工作量天然有界（无忙循环）。
	ch := make(chan []byte, sealers*perSealer)
	allBlobs := make([][]byte, 0, sealers*perSealer)
	var collectMu sync.Mutex

	// 轮换者：持续轮换，旧密钥转为 retired 保留。
	producerWg.Add(1)
	go func() {
		defer producerWg.Done()
		for i := 0; i < rotations; i++ {
			id, err := kr.Rotate()
			if err != nil {
				t.Errorf("rotate: %v", err)
				return
			}
			t.Logf("轮换 i=%d newActive=%s", i, id)
		}
	}()

	// 封装者：轮换不清空 active，所有 seal 都应成功。
	for w := 0; w < sealers; w++ {
		producerWg.Add(1)
		go func(w int) {
			defer producerWg.Done()
			for i := 0; i < perSealer; i++ {
				ev, err := kr.Seal([]byte(fmt.Sprintf("w%d-%d", w, i)))
				if err != nil {
					t.Errorf("seal w=%d: %v", w, err)
					return
				}
				h := hex.EncodeToString(ev.Nonce)
				nonceMu.Lock()
				if _, dup := nonces[h]; dup {
					t.Errorf("nonce 复用 w=%d i=%d nonce=%s", w, i, h)
				}
				nonces[h] = struct{}{}
				nonceMu.Unlock()

				b, err := ev.MarshalBinary()
				if err != nil {
					t.Errorf("marshal: %v", err)
					return
				}
				collectMu.Lock()
				allBlobs = append(allBlobs, b)
				collectMu.Unlock()
				ch <- b
			}
		}(w)
	}

	// 解封者：与封装、轮换并发消费；密钥至少为 retired，应全部成功。
	for o := 0; o < openers; o++ {
		consumerWg.Add(1)
		go func() {
			defer consumerWg.Done()
			for b := range ch {
				if _, err := kr.OpenBytes(b); err != nil {
					t.Errorf("并发 open: %v", err)
				}
			}
		}()
	}

	// 生产者全部结束后关闭 channel，解封者消费完残余密文后退出。
	producerWg.Wait()
	close(ch)
	consumerWg.Wait()

	// 终态校验：所有密文可解封且明文正确，跨代密钥没有误用。
	for _, b := range allBlobs {
		ev, _ := ParseEnvelope(b)
		pt, err := kr.OpenBytes(b)
		if err != nil {
			t.Fatalf("终态解封失败 keyID=%s: %v", ev.KeyID, err)
		}
		if !strings.HasPrefix(string(pt), "w") {
			t.Fatalf("明文异常 keyID=%s pt=%q", ev.KeyID, pt)
		}
	}
	t.Logf("判定依据：轮换%d次+%d×%d并发封装全部成功，nonce 去重后=%d，初代密钥=%s 已退役但历史可解封",
		rotations, sealers, perSealer, len(nonces), firstID)
	if want := rotations + 1; len(kr.Snapshot()) != want {
		t.Fatalf("多代密钥应并存为 %d 代，实际 %d 代", want, len(kr.Snapshot()))
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ring.json")

	kr := NewKeyring("alice")
	id1, _ := kr.Rotate()
	c1, _ := kr.SealBytes([]byte("persisted-1"))
	id2, _ := kr.Rotate()
	c2, _ := kr.SealBytes([]byte("persisted-2"))
	if err := kr.Save(path); err != nil {
		t.Fatal(err)
	}

	// 文件权限必须是 0600（含密钥材料）。
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("持久化文件权限=%o，期望 0600", perm)
	}
	t.Logf("持久化文件=%s 权限=0600，两代密钥=%s,%s", path, id1, id2)

	// 重新加载：旧密文（retired）与新密文（active）均可解封。
	kr2, err := LoadKeyring(path, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if kr2.ActiveKeyID() != id2 {
		t.Fatalf("active 重载错误：want=%s got=%s", id2, kr2.ActiveKeyID())
	}
	for i, c := range [][]byte{c1, c2} {
		ev, _ := ParseEnvelope(c)
		pt, err := kr2.OpenBytes(c)
		if err != nil {
			t.Fatalf("重载后密文 %d（keyID=%s）解封失败: %v", i, ev.KeyID, err)
		}
		t.Logf("重载解封 case=%d keyID=%s 明文=%q", i, ev.KeyID, pt)
	}

	// 绑定路径后 Rotate 自动落盘；再加载应看到第三代。
	id3, err := kr2.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	kr3, err := LoadKeyring(path, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if kr3.ActiveKeyID() != id3 || len(kr3.Snapshot()) != 3 {
		t.Fatalf("自动落盘后状态错误 active=%s generations=%d", kr3.ActiveKeyID(), len(kr3.Snapshot()))
	}

	// 接收方不一致必须拒绝加载。
	_, err = LoadKeyring(path, "bob")
	assertKind(t, "load", err, KindRecipientMismatch,
		"case=以 bob 身份加载 alice 的密钥环文件")

	// 文件不存在。
	_, err = LoadKeyring(filepath.Join(dir, "missing.json"), "alice")
	assertKind(t, "load", err, KindIO, "case=加载不存在的文件")
}

func TestSnapshotExcludesKeyMaterial(t *testing.T) {
	kr := NewKeyring("alice")
	id, _ := kr.Rotate()
	_, _ = kr.Rotate()
	if err := kr.Revoke(id); err != nil {
		t.Fatal(err)
	}

	infos := kr.Snapshot()
	if len(infos) != 2 {
		t.Fatalf("snapshot 代数=%d，期望 2", len(infos))
	}
	data, _ := json.MarshalIndent(infos, "", "  ")
	dump := string(data)
	t.Logf("对外诊断视图（不含密钥材料）:\n%s", dump)

	// 原始密钥材料绝不能出现在导出信息中。
	rawHex := hex.EncodeToString(kr.keys[id].Raw)
	if strings.Contains(dump, rawHex) {
		t.Fatal("Snapshot 泄露了原始密钥材料")
	}
	for _, info := range infos {
		if info.State != StateActive && info.State != StateRetired && info.State != StateRevoked {
			t.Fatalf("非法状态: %s", info.State)
		}
	}
	t.Logf("判定依据：导出仅含 id/state/时间戳；吊销密钥 %s 的 raw(%d字节) 未出现", id, len(rawHex))
}
