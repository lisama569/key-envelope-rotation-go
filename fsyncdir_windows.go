//go:build windows

package keyring

// fsyncDir 在 Windows 上无法直接 fsync 目录；rename 本身由文件系统保证原子性。
func fsyncDir(dir string) error { return nil }
