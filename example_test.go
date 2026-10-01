package keyring_test

import (
	"errors"
	"fmt"
	"log"

	keyring "github.com/lisama569/key-envelope-rotation-go"
)

func classify(err error) string {
	var e *keyring.Error
	if errors.As(err, &e) {
		return string(e.Reason)
	}
	return "ok"
}

// label 按轮换顺序把真实密钥标识映射为稳定的 k1/k2，便于示例输出。
func label(id string, order ...*keyring.KeyInfo) string {
	for i, k := range order {
		if k != nil && k.ID == id {
			return fmt.Sprintf("k%d", i+1)
		}
	}
	return "?"
}

func Example() {
	ring := keyring.New()

	// 首次轮换生成第 1 代密钥
	k1, err := ring.Rotate()
	if err != nil {
		log.Fatal(err)
	}

	// 面向接收方 alice 封装
	ct1, err := ring.Seal("alice", []byte("第一代密钥保护的秘密"))
	if err != nil {
		log.Fatal(err)
	}

	// 轮换：第 2 代成为当前密钥，第 1 代保留可解封历史密文
	k2, _ := ring.Rotate()
	ct2, _ := ring.Seal("alice", []byte("第二代密钥保护的秘密"))

	pt1, used1, err := ring.Open("alice", ct1)
	if err != nil {
		log.Fatal(err)
	}
	pt2, used2, _ := ring.Open("alice", ct2)
	fmt.Printf("ct1 用 %s 解封: %q\n", label(used1, k1, k2), pt1)
	fmt.Printf("ct2 用 %s 解封: %q\n", label(used2, k1, k2), pt2)

	// 吊销第 1 代：新封装不受影响（仍用当前 k2），其历史密文解封被确定性拒绝
	if _, err := ring.Revoke(k1.ID); err != nil {
		log.Fatal(err)
	}
	_, _, err = ring.Open("alice", ct1)
	fmt.Printf("吊销后解封 ct1 的判定: %s\n", classify(err))

	// 按代清理：当前世代受保护，旧代（含已吊销）可安全清出密钥环
	err = ring.Retire(k2.ID)
	fmt.Printf("清理当前世代 %s 的判定: %s\n", label(k2.ID, k1, k2), classify(err))
	if err := ring.Retire(k1.ID); err != nil {
		log.Fatal(err)
	}
	_, _, err = ring.Open("alice", ct1)
	fmt.Printf("清理后解封 ct1 的判定: %s\n", classify(err))

	// 诊断信息只含元数据，不含密钥材料；Stats 给出各阶段世代数
	infos := ring.ListInfos()
	fmt.Printf("密钥代数=%d, 当前=%s, 统计=%+v\n", len(infos), label(k2.ID, k1, k2), ring.Stats())

	// Output:
	// ct1 用 k1 解封: "第一代密钥保护的秘密"
	// ct2 用 k2 解封: "第二代密钥保护的秘密"
	// 吊销后解封 ct1 的判定: revoked
	// 清理当前世代 k2 的判定: current_key_protected
	// 清理后解封 ct1 的判定: key_retired
	// 密钥代数=1, 当前=k2, 统计={Total:1 Current:1 Retained:0 Revoked:0 Retired:1}
}
