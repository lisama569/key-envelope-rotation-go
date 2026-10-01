# 本地密钥环：加密封装与密钥轮换

一个零外部依赖的 Go 库，用本地内存密钥环（可持久化为 JSON 文件）模拟密钥生命周期，
提供面向接收方的 AEAD 密文封装、解封、多代密钥并存、轮换、吊销与按代清理（淘汰）。

- 算法：AES-256-GCM（`crypto/aes` + `crypto/cipher`），每次封装使用密码学随机 nonce。
- 完整性：头部作为 AEAD 的 AAD，任何对密文或头部的篡改都会导致解封失败。
- 生命周期三阶段：`current`（新封装）、`retained`（仅解历史密文）、`revoked`（拒绝一切）；
  `Retire` 可按代清理旧密钥（留墓碑，历史密文得 `key_retired`）。
- 持久化：上级目录自动创建，临时文件 + fsync + rename 崩溃安全原子替换；旧版快照兼容加载。
- 并发安全：所有读写经同一把 `sync.RWMutex` 串行化状态访问；随机数与 AEAD 运算在锁外执行。
- 诊断安全：`Info` / `ListInfos` / `Stats` 只导出元数据与计数，任何外部可见信息都不含密钥材料。

## 快速上手

```go
ring := keyring.New()
k1, _ := ring.Rotate()                    // 生成第 1 代密钥
ct, _ := ring.Seal("alice", []byte("秘密")) // 面向接收方 alice 封装
pt, kid, err := ring.Open("alice", ct)    // 解封；kid 为实际使用的密钥标识
```

## 密文格式（线格式）

```
+--------+-------------+-------------------+--------+------------------+
| "KEN1" | 头长 u16be  | Header JSON (UTF8)| nonce  | 密文(含 16B GCM 标签)|
| 4 字节 | 2 字节      | 头长 字节          | 12 字节 | 剩余全部字节         |
+--------+-------------+-------------------+--------+------------------+
```

- 魔数 `KEN1` 与格式版本：头部 JSON 内 `v=1`。魔数不符 → `unsupported_version`。
- `Header JSON` 字段：
  - `magic`：固定 `"KEN1"`
  - `v`：内容格式版本（当前 `1`）
  - `kid`：封装所用密钥标识（形如 `k-xxxxxxxxxxxxxxxx`）
  - `ns`：nonce 字节数（GCM 标准 12）
  - `rcp`：接收方标识（字符串，调用方语义自定）
- **AAD = `"KEN1" + 头长 + Header JSON` 这段前缀的原始字节**。
  GCM 同时保护主体密文与 AAD：改一个字节、插入一个空白、改 `kid`/`rcp` 都会被识别为篡改。
- 解封时按头部的 `kid` 在环中定位密钥，因此多代密钥无需协商即可自动选择正确密钥；
  不存在“用错误密钥解出错误明文”的情况——找不到密钥或校验不过都会明确报错。

## 密钥生命周期

每个密钥世代都处于三个互斥阶段之一，诊断信息（`Info`/`ListInfos`/`Stats`）直接标注阶段，
轮换后旧代与当前代不再难以区分：

| 阶段（`state`） | 含义 | 新封装 (`Seal`) | 解封 (`Open`) 其历史密文 |
|------|------|-----------------|--------------------------|
| `current` | **当前世代**：唯一用于新封装的密钥 | 是 | 是 |
| `retained` | **保留世代**：轮换后退役的旧代，只留着解历史密文 | **否** | 是 |
| `revoked` | **已吊销**：拒绝一切密钥使用 | **否，拒绝** | **否，确定性拒绝（`revoked`）** |
| 已清理（仅墓碑） | 材料已被 `Retire` 删除，环中不再有该世代 | — | **否，确定性拒绝（`key_retired`）** |
| 环中不存在（无墓碑） | 从未属于本环 | — | `unknown_key` |

阶段迁移规则：

- `Rotate()`：生成新一代（版本号单调递增）并置为 `current`；**原 `current` 自动降级为
  `retained`**，更早的世代保持 `retained`。新密文始终只使用 `current`；`retained` 世代
  仅用于解封其历史密文，从而支持平滑、长期的频繁轮换。
- `Revoke(id)`：将指定世代标记为 `revoked` 并记录吊销时间。
  - 吊销的是旧世代：`current` 不变，新封装照常；该世代的历史密文此后一律解封失败。
  - 吊销的是当前世代：环内不再有当前世代，新封装返回 `no_current_key`；
    再次 `Rotate()` 后恢复。吊销即“拒绝一切使用”，不区分新旧密文。
- 空环（从未轮换）调用 `Seal` 返回 `no_current_key`。

### 旧代清理（淘汰）

`Retire(id)` 按代清理，用来控制密钥环长期增长：

```go
if err := ring.Retire(oldKeyID); err != nil { // err 为 *keyring.Error，可按 Reason 归类
    // current_key_protected：清理目标是当前世代（请先 Rotate）
    // key_retired：该世代此前已经被清理（幂等判定）
    // unknown_key：标识从未存在
}
```

使用边界与后果：

- **必须显式指定目标世代**；`current` 世代受保护，清理它会得到 `current_key_protected`，
  绝不会把正在用于新封装的密钥抽走。需要淘汰时请先 `Rotate()`。
- 清理会**删除密钥材料**，但保留一条只含标识与时间戳的**墓碑（tombstone）**。
  因此用该世代封装过的历史密文在 `Open` 时得到稳定、可解释的 `key_retired`，
  不会被含糊报成 `malformed`/`tampered`，也绝不会误用其他世代的密钥“解出”内容。
- 已清理世代不再出现在 `Info`/`ListInfos` 中，但计入 `Stats().Retired`；
  清理前后可通过 `Stats()`（`current`/`retained`/`revoked`/`retired` 计数）看清还剩多少代。
- 已 `revoked` 的世代同样可以被清理（吊销拒绝解封、清理删除材料，二者可叠加）。
- 清理可与 `Seal`/`Open`/`Rotate`/`Revoke` 并发：所有状态访问由同一把锁串行化，
  任何时刻都不会出现状态撕裂或跨密钥误用（见并发测试）。

## 失败原因码（可区分、可归类）

错误为 `*keyring.Error`，可通过 `errors.As` 读取 `Reason`，或用 `errors.Is` 与哨兵比较：

| Reason | 触发场景 |
|--------|----------|
| `malformed` | 密文截断、长度字段越界、头部 JSON 无法解析、nonce 长度与算法不符 |
| `unsupported_version` | 魔数不符或头部版本不受支持 |
| `unknown_key` | 密文 `kid` 在环中不存在；吊销/清理不存在的标识 |
| `revoked` | 使用已吊销密钥进行新封装之外的任何密钥使用（解封历史密文等） |
| `key_retired` | 密钥世代已被 `Retire` 清理：解封其历史密文，或重复清理/吊销该世代 |
| `current_key_protected` | 尝试 `Retire` 当前正在生效的世代（受保护，拒绝清理） |
| `tampered` | AEAD 校验失败：密文主体、标签或受保护头部被篡改 |
| `no_current_key` | 空环或当前密钥已吊销时调用 `Seal` |
| `recipient_mismatch` | 解封接收方与密文头部 `rcp` 不一致（常量时间比较） |

任意失败路径都不会返回明文。

## 持久化

```go
_ = ring.SaveToFile("ring.json")                      // 0600 权限，临时文件+fsync+rename 崩溃安全原子写
restored, _ := keyring.LoadKeyRingFromFile("ring.json")
data, _ := ring.ExportState()                          // 含材料的完整快照（仅本地落盘/迁移用）
```

**写入保证（崩溃安全的原子替换）**：

1. 上级目录不存在时自动 `MkdirAll` 创建（目录权限 `0700`），多级缺失也能保存成功；
2. 先在**同目录**创建隐藏临时文件（`.keyring-*.tmp`），写入全部数据并 `f.Sync()` 落盘，
   `chmod 0600`；
3. 再用 `rename(2)` **原子替换**目标文件，随后 `fsync` 目录保证替换本身持久化
   （Windows 上目录 fsync 为空操作，rename 原子性由文件系统保证）；
4. 任意步骤失败：关闭并删除临时文件，**原有目标文件保持原样、内容不被破坏**，
   且不会残留临时文件。调用方随后仍可正常加载旧文件。

**快照格式与兼容范围**：

- 当前为 `format_version: 2`：每代密钥记录 `current`/`retained`/`revoked` 阶段；
  另含 `retired` 墓碑列表（`id` + `retired_at`，不含材料）。重载后阶段、当前指针、
  吊销结果与清理墓碑全部原样恢复：retained 仍只能解历史密文、retired 仍稳定拒绝。
- **旧快照（无 `format_version` 字段的 v1）继续可读，不会因多出阶段而被拒绝**：
  旧的 `active` 世代按快照 `current_id` 归一化——当前世代映射为 `current`，
  其余映射为 `retained`；`revoked` 语义不变。
- `format_version` 无法识别时以 `unsupported_version` 拒绝。

**一致性校验（拒绝自相矛盾的快照）**，加载在全部校验通过后才原子提交，
失败不会改动既有密钥环：

- 密钥标识/版本号为空、为零或重复；密钥材料长度不是 32；
- 状态枚举非法（v1 仅接受 `active`/`revoked`，v2 仅接受 `current`/`retained`/`revoked`）；
- 字段冲突：未吊销世代携带 `revoked_at`、`current` 状态与 `current_id` 不一致、
  `current_id` 指向吊销/已清理/不存在的世代、同一标识既是存活密钥又在墓碑中、
  墓碑标识重复、墓碑与环内已有存活条目冲突（合并加载场景）。

- 损坏快照统一以 `*keyring.Error` 返回（多为 `malformed`，当前指针问题为
  `revoked`/`key_retired`/`unknown_key`）。
- **安全提示**：快照含密钥材料，应像对待私钥一样保护文件；面向外部诊断请用
  `Info`/`ListInfos`/`Stats`（输出形如 `{"id","version","state","created_at","revoked_at"}`，
  无 `key` 字段）。

## 并发保证

- 状态（密钥表、墓碑表、当前指针、版本计数）由同一把 `sync.RWMutex` 保护，
  任何时刻不存在状态撕裂；`Seal`/`Open` 在锁内复制密钥材料后释放锁，密码学运算在锁外。
- 每次 `Seal` 独立向 `crypto/rand` 取 12 字节 nonce；测试在数千次并发封装下校验
  nonce 全局唯一，不存在随机数重用。
- 解封严格使用密文声明的 `kid` 对应的密钥材料：世代已清理则 `key_retired`，
  已吊销则 `revoked`，找不到则 `unknown_key`——不存在跨密钥误用。
- 轮换、吊销、**清理**与封解封可并发进行；并发窗口内仅可能出现可解释的确定性失败
  （空环瞬间的 `no_current_key`、竞争清理时的 `key_retired` 等）。

## 验证方法

```bash
go test -race -v ./...     # 全量单测（含竞态检测），日志打印输入标识与判定依据
go vet ./...
```

测试覆盖（含上一轮全部用例，无回归）：

- 正常封解封、空环封装、未知密钥、接收方不符、密文主体/头部篡改、各类畸形输入；
- 多代并存、阶段迁移（`current`→`retained`、`revoked`）、吊销旧/当前世代后轮换、
  吊销未知标识、诊断输出无密钥材料；
- **本轮新增**：`Stats` 阶段计数、当前世代清理受保护、清理后历史密文判定为
  `key_retired` 且不牵连其他世代、清理幂等与未知标识边界；
- 并发清理 × 并发轮换 × 12 goroutine × 150 轮封解封（竞态检测、nonce 唯一、
  终态复核跨密钥无误用）；
- 上级多级目录不存在时保存与重载（阶段/墓碑恢复）、替换失败时原文件完好、
  旧版 v1 快照兼容（`active`→`current`/`retained`）、十余种自相矛盾快照被拒绝
  且拒绝后密钥环不被污染、v2 快照往返一致。
