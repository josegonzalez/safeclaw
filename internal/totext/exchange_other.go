//go:build !linux && !darwin

package totext

import "errors"

// exchange is not available on this platform, so replaceDir renames
// twice instead.
func exchange(_, _ string) error {
	return errors.ErrUnsupported
}
