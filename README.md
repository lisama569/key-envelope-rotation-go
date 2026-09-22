# key-envelope-rotation-go

本地密钥环上的**加密封装（envelope encryption）与密钥轮换**实现。
用本地多代密钥模拟完整密钥生命周期，使多代密钥并存时的加解密结论确定、可预期、可诊断。

- 每封密文面向**唯一接收方**，自带可识别的**内容版本（format version）**与**密钥标识（KeyID）**。
- 密钥缺失、标识未知、密文被篡改、格式不完整、接收方不符、密钥已吊销——全部给出**可区分的失败类别**，且任何失败路径都不返回明文。
- 轮换后旧密钥转为 `retired` 保留：新密文用当前密钥，历史密文继续可解封；`revoked` 密钥则新封装与既有密文一律拒绝。
- 全部操作并发安全（`sync.RWMutex`），nonce 每次来自 `crypto/rand` 绝不复用；密钥环可原子持久化（0600）并重新加载。
- 对外诊断视图 `Snapshot()` **不含任何密钥材料**。

## 密文格式（v1）

自描述的紧凑二进制，魔数 `KEN1`，字段按顺序紧密排列：

| 偏移 | 长度 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | magic | 固定 `KEN1` |
| 4 | 1 | format version | 内容版本，当前为 `1` |
| 5 | 1 | recipientLen | 接收方长度（≤255） |
| 6 | N | recipient | 接收方 UTF-8 文本 |
| … | 1 | keyIDLen | 密钥标识长度（≤255） |
| … | N | keyID | 生成该密文的密钥标识 |
| … | 1 | nonceLen | 固定 12 |
| … | 12 | nonce | AES-GCM 标准随机 nonce |
| … | 剩余 | ciphertext | AES-256-GCM 输出，末尾附 16 字节认证标签 |

其中 `format version | recipient | keyID` 同时作为 **GCM 的 AAD（附加认证数据）**：
即便篡改通过了结构解析，也会在解密阶段被认证标签拒绝（`tampered`），不可能解出错误明文。

> 说明：仅截断密文、但剩余密文仍 ≥16 字节时，在密码学上与“篡改”不可区分，统一归类为 `tampered`；
> 只有连 GCM 输入的最小结构都不满足（缺魔数/版本、字段截断、密文 <16 字节等）才归类为 `format`。

## 密钥生命周期

每把密钥处于且仅处于一个状态，任一时刻至多一把 `active`：

```text
                 Rotate()（旧 active 下场）
        ┌──────────────────────────────────┐
        ▼                                   │
   [active] ──Retire()──▶ [retired]        │ 新密钥
  可 Seal / Open         仅 Open 历史密文   │ 成为 active
        │                    │             │
        └──Revoke()──────────┴──▶ [revoked]
                                  Seal 与 Open 一律拒绝
```

- **active**：当前有效。新封装只使用它；也可解封。
- **retired**：轮换/手动退役后进入。不能再产生新密文，但在被显式吊销/删除前，历史密文持续可解封。
- **revoked**：疑似失陷。确定性地拒绝一切使用——既不能新封装，既有密文也不能解封（返回 `key_revoked`，而非 `tampered`，结论可解释）。
  吊销当前 active 会清空 active 槽，需重新 `Rotate()` 才能再封装。

## 失败类别（可区分）

`KindOf(err)` 返回 `FailureKind`：

| 类别 | 触发条件 |
|------|----------|
| `format` | 魔数/版本错误、字段截断、长度非法、密文短于标签、UTF-8 非法 |
| `recipient_mismatch` | 密文接收方与本地密钥环不一致；或以错误接收方加载持久化文件 |
| `unknown_key` | 密文 KeyID 在本地密钥环不存在；吊销/退役一个未知标识 |
| `key_revoked` | 用已吊销密钥新封装（active 槽空时表现为 `no_active_key`）或解封既有密文 |
| `tampered` | 结构合法但 GCM 认证失败：密文/nonce/AAD 头部被改动 |
| `no_active_key` | 密钥环为空或 active 被退役/吊销后尚未轮换 |
| `invalid_state` | 非法生命周期迁移（如重复吊销、退役非 active 密钥）、加载文件不变量被破坏 |
| `io` | 持久化读写失败、随机数源失败 |

`Open` 的判定顺序固定为：接收方 → 密钥存在性 → 吊销状态 → GCM 认证，类别互斥、可区分。

## 兼容与轮换规则

1. **向后解封**：轮换不删除旧密钥，旧密文在 `retired` 保留期内始终可解封；多代密钥并存。
2. **向前封装**：所有新密文只携带当前 `active` 的 KeyID。
3. **格式版本**：解析与封装都只接受当前版本 `1`；遇到不同魔数/版本直接 `format` 拒绝，不做猜测式解密。
4. **持久化版本独立**：磁盘 JSON 有自己的 `format_version`，加载时校验，与密文内容版本互不影响。
5. **加载校验**：重新加载会复核接收方一致、KeyID 唯一、密钥长度正确、active 不变量（为空或指向唯一 active）。
6. **吊销语义确定**：吊销后历史密文返回 `key_revoked`，不依赖标签校验时机，结论稳定。

## 持久化与诊断安全

- `Save(path)`：临时文件 + `fsync` + `rename` 原子替换，文件权限 `0600`，目录 `0700`。
- `LoadKeyring(path, recipient)`：严格校验后重建；绑定路径后 `Rotate/Revoke/Retire` 自动同步落盘。
- 磁盘文件**含密钥材料**，仅限本地私有保存；对外导出请用 `Snapshot()`，它只含 `id / state / 时间戳`。

## 快速上手

```go
kr := keyenvelope.NewKeyring("alice")
id, _ := kr.Rotate()                 // 生成第一代 active 密钥
blob, _ := kr.SealBytes([]byte("hello")) // 封装 -> 自描述二进制
pt, err := kr.OpenBytes(blob)        // 解封
if err != nil {
    switch keyenvelope.KindOf(err) { // 按可区分类别处理
    case keyenvelope.KindTampered:    /* 被篡改 */
    case keyenvelope.KindUnknownKey:  /* 密钥已不在环中 */
    case keyenvelope.KindKeyRevoked:  /* 密钥被吊销 */
    }
}
newID, _ := kr.Rotate()              // 轮换：id 转 retired，newID 为 active
_, _ = kr.OpenBytes(blob)            // 旧密文仍可解封
_ = kr.Save("/path/ring.json")       // 0600 原子持久化
kr2, _ := keyenvelope.LoadKeyring("/path/ring.json", "alice")
```

## 验证方法

```bash
go test ./... -count=1 -v     # 查看每个用例的“输入标识 + 判定依据”日志
go test ./... -race           # 并发封装/解封/轮换的竞态检测
go vet ./...
go build ./...
```

测试覆盖：

- 正常往返（空串/中文/4KB 明文）、密文携带的版本/接收方/KeyID 校验；
- 格式异常：空输入、短于头部、魔数错误、版本错误、字段/密文截断；
- 篡改：翻转密文、nonce、KeyID、recipient 字节，分别归类为 `tampered / unknown_key / recipient_mismatch`；
- 未知密钥、跨接收方解封；
- 轮换多代并存、`retired` 保留期内历史可解封、手动退役后禁止新封装；
- 吊销 active 后新封装被拒、既有密文确定返回 `key_revoked`、吊销后再轮换、重复吊销；
- 3000 次封装 nonce 全局唯一；8 封装者 × 4 解封者与 10 次轮换并发（`-race` 无告警）；
- 持久化往返、0600 权限、自动落盘、接收方不符拒绝加载、文件缺失；
- `Snapshot()` 导出不含原始密钥材料。
