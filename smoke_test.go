package keyenvelope

import "testing"

func TestSmokeSealOpenRotate(t *testing.T) {
	kr := NewKeyring("alice")
	id1, err := kr.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	blob, err := kr.SealBytes([]byte("hello"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	pt, err := kr.OpenBytes(blob)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("open: %v pt=%q", err, pt)
	}
	id2, err := kr.Rotate()
	if err != nil || id1 == id2 {
		t.Fatalf("second rotate: id1=%s id2=%s err=%v", id1, id2, err)
	}
	// 旧密文仍可解封（retired 保留期）。
	pt, err = kr.OpenBytes(blob)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("open after rotate: %v pt=%q", err, pt)
	}
	// 新密文使用新密钥。
	ev, _ := ParseEnvelope(blob)
	newBlob, _ := kr.SealBytes([]byte("world"))
	evNew, _ := ParseEnvelope(newBlob)
	if evNew.KeyID != id2 || ev.KeyID != id1 {
		t.Fatalf("expected new ciphertext keyed by %s, got %s", id2, evNew.KeyID)
	}
}
