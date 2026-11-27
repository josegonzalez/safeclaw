//go:build !unix

package config

import "os"

// ownerOf is not available on this platform.
func ownerOf(os.FileInfo) (int, bool) {
	return 0, false
}
