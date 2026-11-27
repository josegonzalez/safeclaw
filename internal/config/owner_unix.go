//go:build unix

package config

import (
	"os"
	"syscall"
)

// ownerOf returns the uid owning a file.
func ownerOf(info os.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
