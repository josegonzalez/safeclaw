package session

import "golang.org/x/sys/unix"

// renameNoReplace renames from to to, failing if to exists.
func renameNoReplace(from, to string) error {
	return unix.RenamexNp(from, to, unix.RENAME_EXCL)
}
