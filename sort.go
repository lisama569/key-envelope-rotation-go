package keyenvelope

import "sort"

// sortKeyInfos 按 ID 排序，保证 Snapshot 输出稳定可比较。
func sortKeyInfos(infos []KeyInfo) {
	sort.Slice(infos, func(i, j int) bool { return infos[i].ID < infos[j].ID })
}
