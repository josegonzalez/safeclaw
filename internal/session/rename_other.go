//go:build !linux && !darwin

package session

import "errors"

// renameNoReplace is not available on this platform.
func renameNoReplace(_, _ string) error {
	return errors.ErrUnsupported
}
