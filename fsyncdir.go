//go:build !windows

package keyring

import "os"

// fsyncDir 同步目录项，保证此前的 rename 在崩溃后仍然生效（崩溃安全原子替换）。
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
