//go:build !windows

package fileserver

import (
	"os"
	"syscall"
)

func private(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid() && info.Mode().Perm() == 0700
}
