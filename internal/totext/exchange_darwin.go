package totext

import "golang.org/x/sys/unix"

// exchange swaps the directories a and b in one step.
func exchange(a, b string) error {
	return unix.RenamexNp(a, b, unix.RENAME_SWAP)
}
